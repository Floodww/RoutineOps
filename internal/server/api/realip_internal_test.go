package api

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
)

func req(t *testing.T, peer string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r.RemoteAddr = peer
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// Заголовок от НЕдоверенного собеседника не значит ничего. Это половина, ради которой
// не взят chi middleware.RealIP: он верит заголовку всегда, а клиент шлёт его сам —
// и per-IP лимит обходится новым значением на каждый запрос.
func TestClientIPBehindProxy_UntrustedPeerIgnored(t *testing.T) {
	r := req(t, "192.0.2.10:44444", map[string]string{
		"X-Real-IP":       "192.0.2.66",
		"True-Client-IP":  "192.0.2.67",
		"X-Forwarded-For": "192.0.2.68",
	})
	if got := clientIPBehindProxy(r, defaultTrustedProxies); got != "" {
		t.Errorf("подделанный заголовок принят от чужого адреса: %q", got)
	}
}

// True-Client-IP не читаем вообще, даже от доверенного прокси: наш nginx его не ставит,
// а chi/httprate смотрят именно на него ПЕРВЫМ — то есть клиент, отправив его сам,
// перебивал бы честный X-Real-IP.
func TestClientIPBehindProxy_TrueClientIPNeverTrusted(t *testing.T) {
	r := req(t, "172.18.0.3:5555", map[string]string{"True-Client-IP": "192.0.2.66"})
	if got := clientIPBehindProxy(r, defaultTrustedProxies); got != "" {
		t.Errorf("True-Client-IP прочитан: %q", got)
	}
}

func TestClientIPBehindProxy_RealIPFromTrustedProxy(t *testing.T) {
	r := req(t, "172.18.0.3:5555", map[string]string{"X-Real-IP": "192.0.2.10"})
	if got := clientIPBehindProxy(r, defaultTrustedProxies); got != "192.0.2.10" {
		t.Errorf("получено %q, ожидался адрес клиента 192.0.2.10", got)
	}
}

// 🔴 Главная ловушка X-Forwarded-For: список дописывается СЛЕВА, и левый элемент прислал
// клиент. Читая слева, мы приняли бы за клиента то, что он сам про себя написал.
// Идём справа и берём первый недоверенный.
func TestClientIPBehindProxy_XFFPrependAttack(t *testing.T) {
	// Клиент 192.0.2.10 прислал «X-Forwarded-For: 192.0.2.66»; прокси дописал справа
	// адрес, с которого реально пришёл запрос.
	r := req(t, "172.18.0.3:5555", map[string]string{"X-Forwarded-For": "192.0.2.66, 192.0.2.10"})
	if got := clientIPBehindProxy(r, defaultTrustedProxies); got != "192.0.2.10" {
		t.Errorf("получено %q — подделка слева принята за клиента", got)
	}
}

// Два прокси в цепочке: пропускаем свои и останавливаемся на первом чужом.
func TestClientIPBehindProxy_XFFSkipsTrustedHops(t *testing.T) {
	r := req(t, "172.18.0.3:5555", map[string]string{"X-Forwarded-For": "192.0.2.10, 172.18.0.9, 172.18.0.4"})
	if got := clientIPBehindProxy(r, defaultTrustedProxies); got != "192.0.2.10" {
		t.Errorf("получено %q, ожидался 192.0.2.10", got)
	}
}

// Вся цепочка своя — клиента в ней нет, выдумывать его нельзя.
func TestClientIPBehindProxy_XFFAllTrustedYieldsNothing(t *testing.T) {
	r := req(t, "172.18.0.3:5555", map[string]string{"X-Forwarded-For": "172.18.0.9, 172.18.0.4"})
	if got := clientIPBehindProxy(r, defaultTrustedProxies); got != "" {
		t.Errorf("получено %q при цепочке из одних доверенных", got)
	}
}

// Dual-stack-слушатель отдаёт адрес собеседника как ::ffff:172.18.0.3. Без Unmap он не
// совпал бы ни с одним v4-префиксом, и доверие к своему же прокси молча отключилось бы.
func TestClientIPBehindProxy_IPv4MappedPeerIsTrusted(t *testing.T) {
	r := req(t, "[::ffff:172.18.0.3]:5555", map[string]string{"X-Real-IP": "192.0.2.10"})
	if got := clientIPBehindProxy(r, defaultTrustedProxies); got != "192.0.2.10" {
		t.Errorf("получено %q — IPv4-mapped собеседник не опознан как доверенный", got)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	if got, err := ParseTrustedProxies(""); err != nil || len(got) != len(defaultTrustedProxies) {
		t.Errorf("пустая строка не дала дефолтный набор: %v / %v", got, err)
	}
	// Голый адрес — это /32: оператору проще написать адрес прокси, чем считать маску.
	got, err := ParseTrustedProxies("192.0.2.7, 172.18.0.0/16")
	if err != nil {
		t.Fatalf("разбор корректного списка: %v", err)
	}
	if len(got) != 2 || got[0] != netip.MustParsePrefix("192.0.2.7/32") {
		t.Errorf("разобрано %v", got)
	}
	// Опечатка — ошибка, а НЕ тихий откат на дефолт: иначе оператор остаётся с лимитом,
	// который считает настроенным.
	if _, err := ParseTrustedProxies("192.0.2.7, не-адрес"); err == nil {
		t.Error("мусор в списке принят молча")
	}
}

// 🔴 Ради чего всё: за одним прокси клиенты обязаны попадать в РАЗНЫЕ бакеты.
// Тест держит обе половины — с middleware и без него, — потому что «два запроса
// прошли» само по себе ничего не доказывает: надо видеть, что БЕЗ подмены второй
// клиент упирается в лимит, съеденный первым.
func TestRealIPFromProxy_PerIPBucketsActuallySeparate(t *testing.T) {
	newRouter := func(withRealIP bool) http.Handler {
		h := &Handler{trustedProxies: defaultTrustedProxies}
		r := chi.NewRouter()
		if withRealIP {
			r.Use(h.realIPFromProxy)
		}
		r.With(httprate.LimitByIP(1, time.Minute)).Post("/api/v1/auth/login",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		return r
	}

	// Оба запроса приходят с адреса nginx, различаются только заголовком.
	call := func(router http.Handler, clientIP string) int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req(t, "172.18.0.3:5555", map[string]string{"X-Real-IP": clientIP}))
		return w.Code
	}

	fixed := newRouter(true)
	if code := call(fixed, "192.0.2.10"); code != http.StatusOK {
		t.Fatalf("первый клиент получил %d", code)
	}
	if code := call(fixed, "192.0.2.11"); code != http.StatusOK {
		t.Errorf("второй клиент получил %d — бакет общий, лимит съеден соседом", code)
	}
	if code := call(fixed, "192.0.2.10"); code != http.StatusTooManyRequests {
		t.Errorf("повтор того же клиента получил %d, ожидался 429 — лимит не работает вовсе", code)
	}

	broken := newRouter(false)
	if code := call(broken, "192.0.2.10"); code != http.StatusOK {
		t.Fatalf("контроль: первый запрос получил %d", code)
	}
	if code := call(broken, "192.0.2.11"); code != http.StatusTooManyRequests {
		t.Errorf("контроль: без подмены второй клиент получил %d, а должен был упереться "+
			"в чужой лимит (%d). Если это не так — тест выше ничего не проверяет",
			code, http.StatusTooManyRequests)
	}
}
