package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Recovery-код обязан лежать в БД хешем: он эквивалентен второму фактору, и одного
// чтения таблицы (дамп, бэкап, дыра в выборке) не должно хватать для входа.
// Без хеширования первый же подтест зелёный на плейнтексте — то есть незаметен.
func TestRecoveryCodes_StoredHashed(t *testing.T) {
	plain, hashed, err := newRecoveryCodes()
	if err != nil {
		t.Fatalf("newRecoveryCodes: %v", err)
	}
	if len(plain) != recoveryCodeCount || len(hashed) != recoveryCodeCount {
		t.Fatalf("ожидалось по %d кодов, получено %d/%d", recoveryCodeCount, len(plain), len(hashed))
	}
	for i, h := range hashed {
		if !strings.HasPrefix(h, recoveryHashPrefix) {
			t.Fatalf("код %d хранится не хешем: %q", i, h)
		}
		if strings.Contains(h, plain[i]) {
			t.Fatalf("код %d виден в хранимом значении", i)
		}
	}
	// Энтропии должно хватать, чтобы перебор не имел смысла: 13 байт → 21 символ.
	if len(plain[0]) < 20 {
		t.Fatalf("код слишком короткий: %q", plain[0])
	}
	// Коды не повторяются между собой.
	seen := map[string]bool{}
	for _, c := range plain {
		if seen[c] {
			t.Fatalf("повтор кода %q", c)
		}
		seen[c] = true
	}
}

// Код одноразовый: после успешного предъявления он исчезает из списка, иначе
// «одноразовость» была бы только на словах.
func TestTakeRecoveryCode_OneShot(t *testing.T) {
	plain, hashed, _ := newRecoveryCodes()

	rest, matched := takeRecoveryCode(hashed, plain[3])
	if !matched {
		t.Fatal("верный код не принят")
	}
	if len(rest) != recoveryCodeCount-1 {
		t.Fatalf("осталось %d кодов, ожидалось %d", len(rest), recoveryCodeCount-1)
	}
	if _, again := takeRecoveryCode(rest, plain[3]); again {
		t.Fatal("использованный код принят повторно")
	}
	if _, bad := takeRecoveryCode(rest, "явно-не-код"); bad {
		t.Fatal("принят посторонний код")
	}
	// Регистр и пробелы вокруг не должны мешать человеку, переписывающему код с бумаги.
	rest2, ok := takeRecoveryCode(rest, "  "+strings.ToUpper(plain[0])+" ")
	if !ok || len(rest2) != recoveryCodeCount-2 {
		t.Fatalf("код в другом регистре не принят (ok=%v, осталось %d)", ok, len(rest2))
	}
}

// Полуаутентифицированный токен (пароль сверен, второй фактор — нет) пускается
// РОВНО в две ручки привязки. Иначе политика «тенант требует MFA» становится
// ловушкой: сервер требует привязать TOTP и сам же закрывает привязку.
//
// И наоборот: префиксное сравнение пустило бы такой токен во всё, что начинается
// на /auth/mfa, поэтому проверяем и отказы.
func TestIsMFASetupPath(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/api/v1/auth/mfa/enroll", true},
		{http.MethodPost, "/api/v1/auth/mfa/verify", true},
		{http.MethodPost, "/api/v1/auth/mfa/enroll/extra", false},
		{http.MethodPost, "/api/v1/auth/mfa", false},
		{http.MethodDelete, "/api/v1/auth/mfa", false},
		{http.MethodGet, "/api/v1/auth/mfa/enroll", false},
		{http.MethodPost, "/api/v1/devices", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		if got := isMFASetupPath(r); got != c.want {
			t.Errorf("%s %s: got %v, want %v", c.method, c.path, got, c.want)
		}
	}
}
