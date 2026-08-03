package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestMe_ReturnsCurrentUser(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/me", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /me: %d %s", w.Code, w.Body)
	}
	// map[string]any, а не map[string]string: с ADR-7 в /me появилось булево
	// is_provider_admin — надзор больше не выражается ролью.
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["role"] != "it_admin" {
		t.Errorf("role = %v, want it_admin", m["role"])
	}
	if m["email"] == "" || m["id"] == "" {
		t.Errorf("пустые поля идентичности: %+v", m)
	}
	if m["is_provider_admin"] != false {
		t.Errorf("is_provider_admin = %v, want false у обычного админа тенанта", m["is_provider_admin"])
	}
}

func TestChangePassword(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := authToken(t, rtr, db) // сидит admin_<name>@test.com / pass123 / it_admin
	email := "admin_" + t.Name() + "@test.com"
	jb := func(cur, next string) []byte {
		b, _ := json.Marshal(map[string]string{"current_password": cur, "new_password": next})
		return b
	}

	// неверный текущий пароль → 401
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/me/password", jb("wrong", "NewP@ssw0rd123"), token); w.Code != http.StatusUnauthorized {
		t.Fatalf("неверный current: ждали 401, получили %d %s", w.Code, w.Body)
	}
	// слабый новый пароль → 400
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/me/password", jb("pass123", "weak"), token); w.Code != http.StatusBadRequest {
		t.Fatalf("слабый new: ждали 400, получили %d %s", w.Code, w.Body)
	}
	// корректная смена → 200
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/me/password", jb("pass123", "NewP@ssw0rd123"), token); w.Code != http.StatusOK {
		t.Fatalf("смена: ждали 200, получили %d %s", w.Code, w.Body)
	}
	// логин новым паролем работает, старым — нет
	if w := doLogin(t, rtr, email, "NewP@ssw0rd123"); w.Code != http.StatusOK {
		t.Fatalf("логин новым паролем: %d %s", w.Code, w.Body)
	}
	if w := doLogin(t, rtr, email, "pass123"); w.Code == http.StatusOK {
		t.Fatal("логин СТАРЫМ паролем должен падать")
	}
}
