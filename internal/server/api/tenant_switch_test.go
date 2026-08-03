package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// ADR-7 §11.4: человек состоит в тенантах A и B, к C отношения не имеет. Он входит
// одним логином, видит только свои тенанты и переключается между ними без
// перелогина; тенант C для него не существует ни в списке, ни по прямому запросу.

const (
	tenantB = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	tenantC = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
)

func mustTenant(t *testing.T, db *storage.DB, id, name string) {
	t.Helper()
	if _, err := db.Pool().Exec(context.Background(),
		`INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, id, name,
	); err != nil {
		t.Fatalf("tenant %s: %v", name, err)
	}
}

// addMembership добавляет членство существующей личности в тенант.
func addMembership(t *testing.T, db *storage.DB, email, tenantID, role string) {
	t.Helper()
	ctx := context.Background()
	identity, err := db.GetIdentityByEmail(ctx, email)
	if err != nil || identity == nil {
		t.Fatalf("GetIdentityByEmail(%s) = %v, %v", email, identity, err)
	}
	scoped, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("bind %s: %v", tenantID, err)
	}
	if _, err := db.Q(scoped).Exec(scoped, `
		INSERT INTO users (name, email, role, tenant_id, identity_id)
		VALUES ('Test User', $1, $2, $3, $4)`, email, role, tenantID, identity.ID); err != nil {
		finish(false)
		t.Fatalf("membership in %s: %v", tenantID, err)
	}
	finish(true)
}

func getMyTenants(t *testing.T, rtr http.Handler, token string) []map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/tenants", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: token})
	w := httptest.NewRecorder()
	rtr.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /auth/tenants = %d, body=%s", w.Code, w.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode tenants: %v", err)
	}
	return out
}

func postSwitch(t *testing.T, rtr http.Handler, token, tenantID string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"tenant_id": tenantID})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/tenant", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "token", Value: token})
	w := httptest.NewRecorder()
	rtr.ServeHTTP(w, r)
	return w
}

// activeTenant / otherTenant — активный и любой НЕактивный тенант по ответу API.
// Порядок членств задаётся именем тенанта, поэтому «куда попадёт вход» зависит от
// названий; тест не должен это угадывать.
func activeTenant(t *testing.T, list []map[string]any) string {
	t.Helper()
	for _, m := range list {
		if m["active"] == true {
			id, _ := m["tenant_id"].(string)
			return id
		}
	}
	t.Fatalf("в списке нет активного тенанта: %+v", list)
	return ""
}

func otherTenant(t *testing.T, list []map[string]any) (id, role string) {
	t.Helper()
	for _, m := range list {
		if m["active"] != true {
			id, _ = m["tenant_id"].(string)
			role, _ = m["role"].(string)
			return id, role
		}
	}
	t.Fatalf("в списке нет неактивного тенанта: %+v", list)
	return "", ""
}

func tokenFromCookies(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == "token" {
			return c.Value
		}
	}
	t.Fatal("в ответе нет cookie token")
	return ""
}

func TestSwitchTenant_OnlyOwnTenants(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	mustTenant(t, db, tenantB, "B-tenant")
	mustTenant(t, db, tenantC, "C-tenant")

	email := "multi_" + t.Name() + "@test.com"
	seedUser(t, db, email, "pass123", "it_admin")
	// В B тот же человек — viewer: роль принадлежит членству, а не человеку.
	addMembership(t, db, email, tenantB, "viewer")

	w := doLogin(t, rtr, email, "pass123")
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d", w.Code)
	}
	token := tokenFromCookies(t, w)

	list := getMyTenants(t, rtr, token)
	if len(list) != 2 {
		t.Fatalf("тенантов в списке = %d, want 2: %+v", len(list), list)
	}
	for _, m := range list {
		if m["tenant_id"] == tenantC {
			t.Fatal("в списке оказался тенант, в котором человек не состоит")
		}
	}

	// Переключение в другой СВОЙ тенант: роль обязана стать ролью ТОГО членства.
	targetID, targetRole := otherTenant(t, list)
	sw := postSwitch(t, rtr, token, targetID)
	if sw.Code != http.StatusOK {
		t.Fatalf("switch = %d, body=%s", sw.Code, sw.Body.String())
	}
	newToken := tokenFromCookies(t, sw)

	after := getMyTenants(t, rtr, newToken)
	if got := activeTenant(t, after); got != targetID {
		t.Fatalf("активный тенант = %q, want %q", got, targetID)
	}
	for _, m := range after {
		if m["active"] == true && m["role"] != targetRole {
			t.Fatalf("роль после переключения = %v, want %q (роль принадлежит членству)", m["role"], targetRole)
		}
	}

	// Чужой тенант — 403, сколько бы его ни просили.
	if got := postSwitch(t, rtr, newToken, tenantC); got.Code != http.StatusForbidden {
		t.Fatalf("switch to C = %d, want 403", got.Code)
	}
}

// Старый токен после переключения обязан умереть: иначе «сменил тенант» означало бы
// «получил два рабочих токена сразу».
func TestSwitchTenant_RevokesPreviousToken(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	mustTenant(t, db, tenantB, "B-tenant")

	email := "revoke_" + t.Name() + "@test.com"
	seedUser(t, db, email, "pass123", "it_admin")
	addMembership(t, db, email, tenantB, "it_admin")

	token := tokenFromCookies(t, doLogin(t, rtr, email, "pass123"))
	assertMe(t, rtr, token, http.StatusOK)

	targetID, _ := otherTenant(t, getMyTenants(t, rtr, token))
	sw := postSwitch(t, rtr, token, targetID)
	if sw.Code != http.StatusOK {
		t.Fatalf("switch = %d", sw.Code)
	}
	assertMe(t, rtr, token, http.StatusUnauthorized)
	assertMe(t, rtr, tokenFromCookies(t, sw), http.StatusOK)
}

// Надзор — признак личности: он не появляется и не исчезает от переключения тенанта
// и не выдаётся тем, у кого флага нет (ADR-7 §11.3).
func TestProviderAdmin_IsIdentityFlagNotTenantRole(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	ctx := context.Background()

	email := "prov_" + t.Name() + "@test.com"
	seedUser(t, db, email, "pass123", "it_admin")
	token := tokenFromCookies(t, doLogin(t, rtr, email, "pass123"))

	across := func(tok string) int {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/devices/across-tenants", nil)
		r.AddCookie(&http.Cookie{Name: "token", Value: tok})
		w := httptest.NewRecorder()
		rtr.ServeHTTP(w, r)
		return w.Code
	}

	if got := across(token); got != http.StatusForbidden {
		t.Fatalf("без флага across-tenants = %d, want 403", got)
	}

	identity, err := db.GetIdentityByEmail(ctx, email)
	if err != nil || identity == nil {
		t.Fatalf("identity: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`UPDATE identities SET is_provider_admin = true WHERE id = $1`, identity.ID); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	// Тот же токен: признак читается из БД на каждый запрос, а не из claims.
	if got := across(token); got != http.StatusOK {
		t.Fatalf("с флагом across-tenants = %d, want 200", got)
	}

	// Роль членства при этом осталась обычной — иерархии флаг не вводит.
	u, err := db.GetUserByEmailInTenant(ctx, tenancy.DefaultTenantID, email)
	if err != nil || u == nil {
		t.Fatalf("membership: %v", err)
	}
	if u.Role != "it_admin" {
		t.Fatalf("роль членства = %q, want it_admin", u.Role)
	}
}
