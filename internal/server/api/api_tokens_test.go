package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// createToken выпускает сервисный токен через API и возвращает (плейнтекст, id).
func createToken(t *testing.T, rtr http.Handler, adminJWT, name, role string, days int) (string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": name, "role": role, "expires_in_days": days})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/api-tokens", body, adminJWT)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание токена: %d %s", w.Code, w.Body)
	}
	var resp struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	if !strings.HasPrefix(resp.Token, storage.APITokenPrefix) {
		t.Fatalf("плейнтекст без префикса %q: %q", storage.APITokenPrefix, resp.Token)
	}
	return resp.Token, resp.ID
}

// Основной путь: токен пускают в API, и роль он несёт СВОЮ, а не роль запроса.
func TestAPIToken_AuthenticatesWithOwnRole(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	secret, _ := createToken(t, rtr, admin, "ci", "it_admin", 0)

	// it_admin-токен пускают в мутирующую ручку (создание группы).
	body, _ := json.Marshal(map[string]string{"name": "grp-" + t.Name()})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, "Bearer "+secret)
	if w.Code != http.StatusCreated {
		t.Errorf("it_admin-токен должен пускать в мутацию, получили %d %s", w.Code, w.Body)
	}
}

// Роль токена реально ограничивает: viewer не может мутировать, хотя выпустил его админ.
// Это главный инвариант — иначе любой сервисный токен был бы админским.
func TestAPIToken_ViewerRoleIsEnforced(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	secret, _ := createToken(t, rtr, admin, "readonly", "viewer", 0)

	// Чтение — можно.
	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/device-groups", nil, "Bearer "+secret); w.Code != http.StatusOK {
		t.Errorf("viewer-токен должен читать, получили %d %s", w.Code, w.Body)
	}
	// Мутация — нельзя.
	body, _ := json.Marshal(map[string]string{"name": "grp2-" + t.Name()})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, "Bearer "+secret); w.Code != http.StatusForbidden {
		t.Errorf("viewer-токен НЕ должен мутировать, ждали 403, получили %d %s", w.Code, w.Body)
	}
}

// Отзыв = удаление строки, и он мгновенный: следующий же запрос отбивается.
func TestAPIToken_RevokedImmediatelyRejected(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	secret, id := createToken(t, rtr, admin, "temp", "it_admin", 0)
	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/device-groups", nil, "Bearer "+secret); w.Code != http.StatusOK {
		t.Fatalf("до отзыва токен обязан работать: %d", w.Code)
	}

	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/api-tokens/"+id, nil, admin); w.Code != http.StatusNoContent {
		t.Fatalf("отзыв: %d %s", w.Code, w.Body)
	}
	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/device-groups", nil, "Bearer "+secret); w.Code != http.StatusUnauthorized {
		t.Errorf("отозванный токен должен давать 401, получили %d", w.Code)
	}
}

// Срок проверяется в SQL при аутентификации. Токен с прошедшим expires_at не пускают,
// даже если он валиден во всём остальном. Создаём через storage: API отрицательный
// срок не принимает (и правильно делает).
func TestAPIToken_ExpiredRejected(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	_ = authToken(t, rtr, db) // заводит пользователя, от чьего имени выпускаем

	ctx := context.Background()
	user, err := db.GetUserByEmail(ctx, "admin_"+t.Name()+"@test.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	secret, err := storage.NewAPITokenSecret()
	if err != nil {
		t.Fatalf("NewAPITokenSecret: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	if _, err := db.CreateAPIToken(ctx, "expired", "it_admin", user.ID, secret, &past); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/device-groups", nil, "Bearer "+secret); w.Code != http.StatusUnauthorized {
		t.Errorf("истёкший токен должен давать 401, получили %d %s", w.Code, w.Body)
	}
}

// Неизвестный токен с правильным префиксом — 401, а не 500: ветка не должна
// разваливаться на мусоре, который любой может прислать.
func TestAPIToken_UnknownRejected(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	_ = authToken(t, rtr, db)

	bogus := storage.APITokenPrefix + strings.Repeat("de", 32)
	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/device-groups", nil, "Bearer "+bogus); w.Code != http.StatusUnauthorized {
		t.Errorf("неизвестный токен должен давать 401, получили %d %s", w.Code, w.Body)
	}
}

// Плейнтекст показывается РОВНО один раз. Список обязан отдавать метаданные и
// ничего, по чему токен можно было бы восстановить или подобрать.
func TestAPIToken_SecretNeverReturnedTwice(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	secret, _ := createToken(t, rtr, admin, "once", "it_admin", 30)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/api-tokens", nil, admin)
	if w.Code != http.StatusOK {
		t.Fatalf("список токенов: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Error("список вернул плейнтекст токена")
	}
	// И хеш тоже не отдаём: он не секрет в смысле подбора, но и в API ему делать нечего.
	if strings.Contains(w.Body.String(), "token_hash") {
		t.Error("список вернул token_hash")
	}
}

// Действия автоматизации в журнале аудита должны быть отличимы от действий человека,
// иначе разбор инцидента упирается в «админ сделал» без понимания, кто именно.
func TestAPIToken_ActionsAreAttributableInAudit(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	secret, _ := createToken(t, rtr, admin, "deployer", "it_admin", 0)
	body, _ := json.Marshal(map[string]string{"name": "audited-" + t.Name()})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, "Bearer "+secret); w.Code != http.StatusCreated {
		t.Fatalf("создание группы токеном: %d %s", w.Code, w.Body)
	}

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/audit-log?limit=50", nil, admin)
	if w.Code != http.StatusOK {
		t.Fatalf("журнал аудита: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "token:deployer") {
		t.Errorf("в журнале нет отметки о действии токена (ждали token:deployer), тело: %s", w.Body)
	}
}

// Невалидная роль отвергается на входе: иначе получился бы токен, не совпадающий
// ни с одной ролью — бесполезный, но выглядящий рабочим (иерархии ролей нет).
func TestAPIToken_InvalidRoleRejected(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	for _, role := range []string{"", "root", "employee"} {
		body, _ := json.Marshal(map[string]any{"name": "bad", "role": role})
		if w := authedDo(t, rtr, http.MethodPost, "/api/v1/api-tokens", body, admin); w.Code != http.StatusBadRequest {
			t.Errorf("роль %q должна отвергаться 400, получили %d %s", role, w.Code, w.Body)
		}
	}
}

// ── Регрессии из адверс-ревью 19.07. Все четыре воспроизводились на живом коде. ──

// Токен НЕ должен уметь выписывать токены. Иначе модель отзыва — фикция: утёкший
// токен выписывает теневой, тот переживает удаление исходного и в списке неотличим
// от выданного руками (created_by копируется с исходного).
func TestAPIToken_CannotMintAnotherToken(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	secret, _ := createToken(t, rtr, admin, "ci-admin", "it_admin", 0)

	body, _ := json.Marshal(map[string]any{"name": "shadow", "role": "it_admin"})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/api-tokens", body, "Bearer "+secret); w.Code != http.StatusForbidden {
		t.Errorf("токен не должен выписывать токены, ждали 403, получили %d %s", w.Code, w.Body)
	}
	// Список и отзыв — тоже человеческие действия.
	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/api-tokens", nil, "Bearer "+secret); w.Code != http.StatusForbidden {
		t.Errorf("список токенов под токеном: ждали 403, получили %d", w.Code)
	}
}

// Токен НЕ должен трогать аккаунт создавшего админа. Воспроизводилось: viewer-токен
// менял админу пароль (зная текущий) и сбрасывал все его живые сессии.
func TestAPIToken_CannotChangeCreatorPassword(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	secret, _ := createToken(t, rtr, admin, "ci", "viewer", 0)

	body, _ := json.Marshal(map[string]string{"current_password": "pass123", "new_password": "NewPass!234"})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/me/password", body, "Bearer "+secret); w.Code != http.StatusForbidden {
		t.Errorf("токен не должен менять пароль создателя, ждали 403, получили %d %s", w.Code, w.Body)
	}
}

// Токен НЕ должен читать telegram link_token создателя: скормив его боту, держатель
// read-only токена перехватывал бы админские алерты. Пароль для этого не нужен.
func TestAPIToken_CannotReadCreatorTelegramLinkToken(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	secret, _ := createToken(t, rtr, admin, "ci", "viewer", 0)

	// Админ генерирует линк-токен и «отвлекается» — он лежит непогашенным.
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/profile/telegram-link", nil, admin); w.Code != http.StatusOK {
		t.Fatalf("генерация линк-токена админом: %d %s", w.Code, w.Body)
	}
	w := authedDo(t, rtr, http.MethodGet, "/api/v1/profile/telegram", nil, "Bearer "+secret)
	if w.Code != http.StatusForbidden {
		t.Errorf("токен не должен читать telegram создателя, ждали 403, получили %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "link_token") {
		t.Errorf("в ответе утёк link_token: %s", w.Body)
	}
}

// /me обязан отдавать личность и роль ТОКЕНА. Воспроизводилось: viewer-токен получал
// role=it_admin (противоположное тому, что энфорсится) плюс email и id админа.
func TestAPIToken_MeReportsTokenIdentityNotCreator(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	secret, id := createToken(t, rtr, admin, "readonly-ci", "viewer", 0)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/me", nil, "Bearer "+secret)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /me под токеном: %d %s", w.Code, w.Body)
	}
	var me struct{ ID, Email, Name, Role string }
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil {
		t.Fatalf("разбор /me: %v", err)
	}
	if me.Role != "viewer" {
		t.Errorf("role = %q, want viewer — иначе клиент включит админские действия, которые все 403'ят", me.Role)
	}
	if me.ID != id {
		t.Errorf("id = %q, want id токена %q", me.ID, id)
	}
	if !strings.HasPrefix(me.Email, "token:") {
		t.Errorf("email = %q, ждали token:<имя> — email админа утекать не должен", me.Email)
	}
	if strings.Contains(w.Body.String(), "@test.com") {
		t.Errorf("в /me утёк email создателя: %s", w.Body)
	}
}

// Огромный срок переполнял AddDate и заворачивался в прошлое: 201 с мёртвым токеном,
// плейнтекст показан один раз и невосстановим.
func TestAPIToken_AbsurdTTLRejected(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	for _, days := range []int{maxTTLOverflowProbe, 3651} {
		body, _ := json.Marshal(map[string]any{"name": "huge", "role": "viewer", "expires_in_days": days})
		if w := authedDo(t, rtr, http.MethodPost, "/api/v1/api-tokens", body, admin); w.Code != http.StatusBadRequest {
			t.Errorf("expires_in_days=%d должен отвергаться 400, получили %d %s", days, w.Code, w.Body)
		}
	}
}

// Значение из находки ревью — оно реально переполняло time.AddDate.
const maxTTLOverflowProbe = 4611686018427387904

// Токен НЕ должен приглашать людей. Найдено вторым раундом ревью и проверено сквозной
// цепочкой: утёкший it_admin-токен звал /users/invite с role=it_admin, при выключенном
// SMTP получал сырой invite_url прямо в теле ответа, принимал приглашение
// неавторизованным accept-invite — и оставался полноправным админом ПОСЛЕ отзыва
// токена. Хуже теневого токена: строки в users нет в списке /api-tokens, поэтому при
// разборе инцидента её не находят.
//
// Проверяем не только 403, но и то, что приглашения не возникло: гард, отбивающий
// запрос уже ПОСЛЕ создания строки, выглядел бы точно так же.
func TestAPIToken_CannotInviteUsers(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	secret, _ := createToken(t, rtr, admin, "ci-admin", "it_admin", 0)

	body, _ := json.Marshal(map[string]string{"email": "attacker@evil.tld", "role": "it_admin"})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/users/invite", body, "Bearer "+secret)
	if w.Code != http.StatusForbidden {
		t.Errorf("токен не должен приглашать пользователей, ждали 403, получили %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "invite_url") || strings.Contains(w.Body.String(), "token") {
		t.Errorf("в отказе не должно быть приглашения: %s", w.Body)
	}
	// Учётной записи возникнуть не должно — иначе цепочка живёт, несмотря на 403.
	if u, err := db.GetUserByEmail(context.Background(), "attacker@evil.tld"); err == nil && u != nil {
		t.Error("приглашение всё-таки создало пользователя")
	}
}

// Одобрение admin-access выдаёт сотруднику локального админа — решение человека.
// Плюс approved_by durable-колонка: под токеном туда попал бы админ-создатель, и при
// разборе инцидента одобрившим числился бы человек, который ничего не одобрял.
func TestAPIToken_CannotApproveAdminAccess(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)
	secret, _ := createToken(t, rtr, admin, "ci-admin", "it_admin", 0)

	body, _ := json.Marshal(map[string]string{"decision": "approve"})
	path := "/api/v1/admin-access-requests/00000000-0000-0000-0000-000000000000/respond"
	if w := authedDo(t, rtr, http.MethodPost, path, body, "Bearer "+secret); w.Code != http.StatusForbidden {
		t.Errorf("токен не должен одобрять admin-access, ждали 403, получили %d %s", w.Code, w.Body)
	}
}

// JWT-путь не сломан: обычная сессия продолжает работать рядом с токенами.
func TestAPIToken_JWTPathStillWorks(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	admin := authToken(t, rtr, db)

	if w := authedDo(t, rtr, http.MethodGet, "/api/v1/api-tokens", nil, admin); w.Code != http.StatusOK {
		t.Errorf("JWT должен продолжать работать, получили %d %s", w.Code, w.Body)
	}
}
