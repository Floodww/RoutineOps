package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// loginToken логинится и возвращает значение httpOnly-cookie "token".
func loginToken(t *testing.T, rtr http.Handler, email, password string) string {
	t.Helper()
	w := doLogin(t, rtr, email, password)
	if w.Code != http.StatusOK {
		t.Fatalf("login %s: got %d, want 200; body: %s", email, w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "token" {
			return c.Value
		}
	}
	t.Fatalf("no token cookie for %s", email)
	return ""
}

// assertMe бьёт GET /api/v1/me данной кукой и проверяет HTTP-код (жив ли токен).
func assertMe(t *testing.T, rtr http.Handler, token string, want int) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: token})
	w := httptest.NewRecorder()
	rtr.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("GET /me: got %d, want %d; body: %s", w.Code, want, w.Body)
	}
}

// Смена пароля инвалидирует ВСЕ ранее выпущенные токены (token-epoch,
// password_changed_at), но НЕ разлогинивает сессию, из которой пароль меняли —
// ей переминчивают свежий токен (его iat >= нового epoch).
func TestPasswordChange_InvalidatesOldTokens_KeepsCurrent(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	seedUser(t, db, "epoch@test.com", "OldPass123!", "it_admin")

	tokenA := loginToken(t, rtr, "epoch@test.com", "OldPass123!") // «другое устройство»
	tokenB := loginToken(t, rtr, "epoch@test.com", "OldPass123!") // «текущая сессия»
	assertMe(t, rtr, tokenA, http.StatusOK)
	assertMe(t, rtr, tokenB, http.StatusOK)

	// JWT iat — секундная гранулярность: гарантируем, что смена пароля попадёт в
	// ПОЗЖЕ секунду, чем iat токенов (иначе same-second токен пережил бы epoch).
	time.Sleep(1100 * time.Millisecond)

	body, _ := json.Marshal(map[string]string{"current_password": "OldPass123!", "new_password": "NewPass456!"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me/password", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "token", Value: tokenB})
	w := httptest.NewRecorder()
	rtr.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("change password: got %d, want 200; body: %s", w.Code, w.Body)
	}
	var tokenC string
	for _, c := range w.Result().Cookies() {
		if c.Name == "token" {
			tokenC = c.Value
		}
	}
	if tokenC == "" {
		t.Fatal("change password did not re-issue a token cookie")
	}

	assertMe(t, rtr, tokenA, http.StatusUnauthorized) // другая сессия убита
	assertMe(t, rtr, tokenB, http.StatusUnauthorized) // старый токен B убит
	assertMe(t, rtr, tokenC, http.StatusOK)           // текущая сессия (переминчена) жива
}

// Сброс пароля (reset-flow вызывает тот же UpdateUserPassword) тоже двигает
// token-epoch и гасит ранее выпущенные токены.
func TestResetPassword_InvalidatesOldTokens(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	seedUser(t, db, "epoch-reset@test.com", "OldPass123!", "it_admin")

	token := loginToken(t, rtr, "epoch-reset@test.com", "OldPass123!")
	assertMe(t, rtr, token, http.StatusOK)

	time.Sleep(1100 * time.Millisecond)
	// ADR-7: token-epoch двигает смена пароля ЛИЧНОСТИ — членство пароля не имеет.
	id, err := db.GetIdentityByEmail(context.Background(), "epoch-reset@test.com")
	if err != nil || id == nil {
		t.Fatalf("GetIdentityByEmail: %v", err)
	}
	newHash, _ := bcrypt.GenerateFromPassword([]byte("Reset999!"), bcrypt.DefaultCost)
	if err := db.UpdateIdentityPassword(context.Background(), id.ID, string(newHash)); err != nil {
		t.Fatalf("UpdateIdentityPassword: %v", err)
	}

	assertMe(t, rtr, token, http.StatusUnauthorized)
}
