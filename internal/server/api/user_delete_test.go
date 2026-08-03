package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// userIDByEmail — id пользователя, заведённого хелперами через email.
func userIDByEmail(t *testing.T, db *storage.DB, email string) string {
	t.Helper()
	u, err := db.GetUserByEmailInTenant(context.Background(), tenancy.DefaultTenantID, email)
	if err != nil || u == nil {
		t.Fatalf("пользователь %q не найден: %v", email, err)
	}
	return u.ID
}

// Удаление отбирает доступ НАСОВСЕМ — в этом весь смысл ручки. Проверяем, что живой
// JWT уволенного перестаёт работать сразу: иначе «удалили из панели» означало бы
// «удалили из списка», а сессия жила бы до истечения токена.
func TestDeleteUser_KillsLiveSession(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	victimJWT := tokenForRole(t, rtr, db, "viewer", "victim_")
	victimEmail := "victim_" + t.Name() + "@test.com"
	victimID := userIDByEmail(t, db, victimEmail)

	// До удаления сессия рабочая.
	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices", nil, victimJWT); w.Code != http.StatusOK {
		t.Fatalf("сессия жертвы не работает ещё ДО удаления: %d", w.Code)
	}

	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/users/"+victimID, nil, admin); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}

	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices", nil, victimJWT); w.Code != http.StatusUnauthorized {
		t.Errorf("живой JWT удалённого дал %d, ожидался 401", w.Code)
	}
	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/users/"+victimID, nil, admin); w.Code != http.StatusNotFound {
		t.Errorf("повторное удаление дало %d, ожидался 404", w.Code)
	}
}

// 🔴 Сервисные токены уволенного обязаны умереть вместе с ним (api_tokens.created_by,
// ON DELETE CASCADE). Иначе удаление аккаунта — фикция: выданный им токен продолжает
// работать с его ролью, и в списке /api-tokens его больше не видно, потому что видеть
// некому.
func TestDeleteUser_RevokesTheirServiceTokens(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	// Жертва — тоже it_admin: сервисные токены выпускает только он.
	victimJWT := tokenForRole(t, rtr, db, "it_admin", "tokenowner_")
	victimID := userIDByEmail(t, db, "tokenowner_"+t.Name()+"@test.com")
	secret, _ := createToken(t, rtr, victimJWT, "bot-"+t.Name(), "it_admin", 30)

	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices", nil, "Bearer "+secret); w.Code != http.StatusOK {
		t.Fatalf("сервисный токен не работает ещё ДО удаления владельца: %d", w.Code)
	}

	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/users/"+victimID, nil, admin); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}

	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices", nil, "Bearer "+secret); w.Code != http.StatusUnauthorized {
		t.Errorf("токен уволенного дал %d, ожидался 401", w.Code)
	}
}

// Себя удалить нельзя: оператор мгновенно теряет сессию посреди работы, а снести
// коллегу может любой другой it_admin.
func TestDeleteUser_SelfRefused(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	selfID := userIDByEmail(t, db, "admin_"+t.Name()+"@test.com")

	w := authedDo(t, rtr, http.MethodDelete, "/api/v1/users/"+selfID, nil, admin)
	if w.Code != http.StatusConflict {
		t.Errorf("самоудаление дало %d, ожидался 409", w.Code)
	}
	// И аккаунт на месте — отказ не должен быть косметическим.
	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices", nil, admin); w.Code != http.StatusOK {
		t.Errorf("сессия после отказа сломалась: %d", w.Code)
	}
}

// Роль и человечность — два разных гарда, проверяем оба. Сервисный токен под
// requireHuman: распоряжаться личностями автоматизация не должна, как и выпускать их.
func TestDeleteUser_ForbiddenForViewerAndServiceToken(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	tokenForRole(t, rtr, db, "viewer", "prey_") // заводим жертву
	victimID := userIDByEmail(t, db, "prey_"+t.Name()+"@test.com")

	viewer := tokenForRole(t, rtr, db, "viewer", "looker_")
	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/users/"+victimID, nil, viewer); w.Code != http.StatusForbidden {
		t.Errorf("viewer получил %d, ожидался 403", w.Code)
	}

	secret, _ := createToken(t, rtr, admin, "bot-"+t.Name(), "it_admin", 30)
	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/users/"+victimID, nil, "Bearer "+secret); w.Code != http.StatusForbidden {
		t.Errorf("сервисный токен получил %d, ожидался 403 (requireHuman)", w.Code)
	}

	// Никто из них никого не удалил.
	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/users/"+victimID, nil, admin); w.Code != http.StatusNoContent {
		t.Errorf("после отказов жертва должна была остаться, удаление дало %d %s", w.Code, w.Body)
	}
}

// Кривой UUID из URL обязан давать 404, а не 500: id::text в запросе именно для этого.
func TestDeleteUser_UnknownIDIs404(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	for _, id := range []string{"00000000-0000-0000-0000-000000000000", "not-a-uuid"} {
		if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/users/"+id, nil, admin); w.Code != http.StatusNotFound {
			t.Errorf("id=%q дал %d, ожидался 404", id, w.Code)
		}
	}
}

// Кого удалили — обязано остаться в журнале безопасности, причём с адресом: сама строка
// в users исчезла, и по одному uuid разбирать инцидент нечем.
func TestDeleteUser_AuditKeepsEmail(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	tokenForRole(t, rtr, db, "viewer", "audited_")
	victimEmail := "audited_" + t.Name() + "@test.com"
	victimID := userIDByEmail(t, db, victimEmail)

	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/users/"+victimID, nil, admin); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/audit-log?limit=200", nil, admin)
	if w.Code != http.StatusOK {
		t.Fatalf("журнал: %d", w.Code)
	}
	var entries []struct {
		Action  string          `json:"action"`
		Details json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatalf("разбор журнала: %v", err)
	}
	for _, e := range entries {
		if e.Action == "delete_user" && strings.Contains(string(e.Details), victimEmail) {
			return
		}
	}
	t.Errorf("в журнале нет delete_user с адресом %q", victimEmail)
}
