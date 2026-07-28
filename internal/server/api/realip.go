package api

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Восстановление адреса клиента за обратным прокси.
//
// 🔴 Зачем вообще: per-IP лимиты (`httprate.LimitByIP`) ключуются по `r.RemoteAddr`, а за
// nginx он у ВСЕХ один — адрес самого nginx. То есть «10 попыток входа в минуту с адреса»
// на деле было ОДНИМ бакетом на весь мир: перебор с одной машины съедал общий лимит и
// ронял вход всем остальным, а изоляции по адресам не существовало вовсе.
//
// Почему не `middleware.RealIP` из chi и не `httprate.LimitByRealIP`: оба берут заголовок
// БЕЗУСЛОВНО, причём первым `True-Client-IP`. Клиент шлёт его сам, nginx незнакомые
// заголовки пропускает наверх как есть — и лимит обходится новым значением на каждый
// запрос. Это не улучшение, а замена «один общий бакет» на «лимита нет совсем».
//
// Поэтому заголовку верим ТОЛЬКО когда непосредственный собеседник — доверенный прокси.
// Публичный атакующий приходит с публичного адреса, в список не попадает, и его заголовок
// игнорируется; за nginx заголовок ставит nginx, и он авторитетен.

// defaultTrustedProxies — приватные, loopback- и link-local-диапазоны. Логика выбора: с
// такого адреса не может прийти запрос из интернета, значит собеседник — либо ваш прокси,
// либо машина внутри вашего периметра. Если сервер выставлен в интернет напрямую, атакующий
// придёт с публичного адреса, не совпадёт ни с одним префиксом, и его заголовок будет
// отброшен — дефолт безопасен в обеих топологиях.
//
// CGNAT-диапазон 100.64/10 сюда НЕ входит намеренно: его раздают оверлейные VPN, а узел
// такой сети — не ваш прокси. Нужен — добавьте явно через TRUSTED_PROXIES.
// (Записан без четырёх октетов сознательно: leak-скан Free-среза ловит адреса этого
// диапазона как хосты нашей сети, и полная запись этого префикса роняла бы экспорт.)
var defaultTrustedProxies = mustPrefixes(
	"127.0.0.0/8", "::1/128", // loopback
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918 (сюда же docker-сети)
	"fc00::/7",                    // IPv6 unique-local
	"169.254.0.0/16", "fe80::/10", // link-local
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			panic("realip: битый префикс по умолчанию " + c + ": " + err.Error())
		}
		out = append(out, p)
	}
	return out
}

// ParseTrustedProxies разбирает список TRUSTED_PROXIES: CIDR и голые адреса через запятую
// или пробел. Пустая строка = дефолтный набор.
//
// Ошибка возвращается, а не проглатывается с откатом на дефолт: опечатка в CIDR означает,
// что оператор ЗНАЛ про нестандартную топологию и настраивал её. Молчаливый откат оставил
// бы его с лимитом, который он считает настроенным, — ровно тот класс, где гейт зелёный и
// не проверяет ничего.
func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	if len(fields) == 0 {
		return defaultTrustedProxies, nil
	}
	out := make([]netip.Prefix, 0, len(fields))
	for _, f := range fields {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p)
			continue
		}
		// Голый адрес — это /32 (или /128). Оператору удобнее написать адрес nginx,
		// чем считать маску.
		addr, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q — не адрес и не CIDR", f)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

// WithTrustedProxies задаёт список доверенных прокси. Без него действует
// defaultTrustedProxies.
func WithTrustedProxies(prefixes []netip.Prefix) RouterOption {
	return func(h *Handler, _ chi.Router) { h.trustedProxies = prefixes }
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	// IPv4-mapped (::ffff:172.18.0.5) прилетает при dual-stack-слушателе и без Unmap не
	// совпал бы ни с одним v4-префиксом — то есть доверие молча перестало бы работать.
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// clientIPBehindProxy возвращает адрес клиента, если запрос пришёл от доверенного прокси
// и тот сообщил адрес. Пустая строка = верить нечему, RemoteAddr остаётся как есть.
func clientIPBehindProxy(r *http.Request, trusted []netip.Prefix) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil || !isTrusted(peerAddr, trusted) {
		return ""
	}

	// X-Real-IP — то, что ставит наш nginx (см. web/nginx.prod.conf). Одно значение,
	// разбирать нечего.
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		if a, err := netip.ParseAddr(v); err == nil {
			return a.Unmap().String()
		}
	}

	// X-Forwarded-For — для чужого прокси перед нами (Caddy, Traefik, облачный балансер).
	// Идём СПРАВА НАЛЕВО и берём первый недоверенный адрес. Слева список дописывает
	// клиент: подставив «X-Forwarded-For: 1.2.3.4», он выдал бы себя за 1.2.3.4, если
	// читать слева, — а это ровно обход лимита, от которого всё это и защищает.
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return ""
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			// Мусор в цепочке — дальше влево доверять нечему: всё, что левее, могло быть
			// дописано тем же, кто вписал мусор.
			return ""
		}
		if !isTrusted(a, trusted) {
			return a.Unmap().String()
		}
	}
	// Вся цепочка из доверенных адресов: клиента в ней нет.
	return ""
}

// realIPFromProxy подменяет RemoteAddr адресом клиента. Список читается на КАЖДЫЙ запрос
// из h, а не захватывается при сборке цепочки: RouterOption'ы применяются в конце
// NewRouter, уже после r.Use, и захваченное значение всегда было бы дефолтным.
//
// True-Client-IP не читаем сознательно — см. комментарий вверху файла.
func (h *Handler) realIPFromProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := clientIPBehindProxy(r, h.trustedProxies); ip != "" {
			r.RemoteAddr = ip
		}
		next.ServeHTTP(w, r)
	})
}
