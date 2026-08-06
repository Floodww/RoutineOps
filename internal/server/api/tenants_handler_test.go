package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Реестр тенантов — контур надзора над инсталляцией (контракт §4/§11.3). Здесь
// проверяется не «работает ли CRUD», а три вещи, которые ломаются молча:
// кто вправе это делать, куда девается содержимое удалённого тенанта и остаётся ли
// след в журнале после того, как тенант из выборок исчез.

// providerAdminToken — токен надзорного. Флаг живёт на ЛИЧНОСТИ, а не на членстве
// (ADR-7 §11.3), поэтому роль членства здесь ни при чём и ставится обычной.
func providerAdminToken(t *testing.T, rtr http.Handler, db *storage.DB, prefix string) string {
	t.Helper()
	ctx := context.Background()
	email := prefix + t.Name() + "@test.com"
	seedUser(t, db, email, "pass123", "it_admin")

	identity, err := db.GetIdentityByEmail(ctx, email)
	if err != nil || identity == nil {
		t.Fatalf("GetIdentityByEmail(%s) = %v, %v", email, identity, err)
	}
	if _, err := db.Pool().Exec(ctx,
		`UPDATE identities SET is_provider_admin = true WHERE id = $1`, identity.ID); err != nil {
		t.Fatalf("выдача флага надзора: %v", err)
	}
	return "Bearer " + tokenFromCookies(t, doLogin(t, rtr, email, "pass123"))
}

func createTenantVia(t *testing.T, rtr http.Handler, token, name string) storage.Tenant {
	t.Helper()
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/tenants", []byte(`{"name":"`+name+`"}`), token)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /tenants = %d, body=%s", w.Code, w.Body)
	}
	var got storage.Tenant
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode tenant: %v", err)
	}
	if got.ID == "" {
		t.Fatalf("создан тенант без id: %s", w.Body)
	}
	return got
}

func listTenantsVia(t *testing.T, rtr http.Handler, token string) (showTenant bool, tenants []storage.Tenant) {
	t.Helper()
	w := authedDo(t, rtr, http.MethodGet, "/api/v1/tenants", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /tenants = %d, body=%s", w.Code, w.Body)
	}
	var out struct {
		ShowTenant bool             `json:"show_tenant"`
		Tenants    []storage.Tenant `json:"tenants"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode tenants: %v", err)
	}
	return out.ShowTenant, out.Tenants
}

// §10.2: сущность «тенант» показывается в интерфейсе только при N>1, и решает это
// сервер. Признак обязан считаться от фактического содержимого выборки — иначе
// односегментная инсталляция получает лишний уровень абстракции в UI, а
// многотенантная его теряет.
func TestListTenants_ShowTenantFollowsCount(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := providerAdminToken(t, rtr, db, "prov_")

	show, tenants := listTenantsVia(t, rtr, token)
	if show != (len(tenants) > 1) {
		t.Fatalf("show_tenant = %v при %d тенантах", show, len(tenants))
	}

	created := createTenantVia(t, rtr, token, "Реестр-"+t.Name())

	show, after := listTenantsVia(t, rtr, token)
	if !show {
		t.Fatalf("show_tenant = false при %d тенантах", len(after))
	}
	var found bool
	for _, tn := range after {
		if tn.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("созданный тенант %s не появился в реестре", created.ID)
	}
}

// Контур надзора закрыт для всех, у кого нет флага личности, и для автоматики.
//
// Проверяется тремя видами предъявителя сразу: обычный it_admin (роль высокая, флага
// нет), viewer и сервисный токен с ролью it_admin. Ручка, забывшая гард, ответит чем
// угодно кроме 403 — и тест это поймает. Без такого теста администратор одного
// подразделения смог бы переложить чужую машину к себе или завести тенант.
func TestTenantSupervisionRoutes_RejectNonSupervisor(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	ctx := context.Background()

	someTenant := tenancy.DefaultTenantID
	someDevice := "00000000-0000-4000-8000-0000000000ff"

	routes := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/v1/tenants", `{"name":"чужой"}`},
		{http.MethodPatch, "/api/v1/tenants/" + someTenant, `{"name":"переименован"}`},
		{http.MethodDelete, "/api/v1/tenants/" + someTenant, ``},
		{http.MethodPost, "/api/v1/tenants/" + someTenant + "/invites", `{"email":"x@test.com"}`},
		{http.MethodPost, "/api/v1/devices/" + someDevice + "/tenant", `{"tenant_id":"` + someTenant + `"}`},
	}

	// Сервисный токен создаётся с ролью it_admin: роль его пустила бы, надзорный
	// контур — нет. Ровно та автоматика, которой нельзя двигать тенанты.
	svcUser, err := db.CreateUser(ctx, tenancy.DefaultTenantID,
		"Tenant Svc", "tenant-svc-"+t.Name()+"@test.local", "x", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	svcSecret := serviceTokenSecret(t)
	if _, err := db.CreateAPIToken(ctx, tenancy.DefaultTenantID,
		"tenants", "it_admin", "", svcUser.ID, svcSecret, nil); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	predjaviteli := map[string]string{
		"it_admin без флага надзора": tokenForRole(t, rtr, db, "it_admin", "plain_admin_"),
		"viewer":                   tokenForRole(t, rtr, db, "viewer", "viewer_"),
		"сервисный токен it_admin": "Bearer " + svcSecret,
	}

	for who, token := range predjaviteli {
		for _, rt := range routes {
			t.Run(who+" "+rt.method+" "+rt.path, func(t *testing.T) {
				w := authedDo(t, rtr, rt.method, rt.path, []byte(rt.body), token)
				if w.Code != http.StatusForbidden {
					t.Fatalf("%s получил %d %s — на ручке нет гарда надзора", who, w.Code, w.Body)
				}
			})
		}
	}
}

// Удаление тенанта не должно уносить с собой ни устройства, ни журнал.
//
// Содержимое переезжает в Default (решение флуда 30.07: иначе удаление тенанта =
// потеря парка), а запись о самом удалении делается ДО пометки и в журнал удаляемого
// тенанта — цепочка хешей пер-тенантная, и строка-тумбстоун держит её именно ради
// этого события. Проверяется в СКОУПЕ, а не через пул: под RLS «видно» и «не видно»
// зависит от привязки, и запрос мимо скоупа доказывал бы не то.
func TestDeleteTenant_ReparentsContentAndKeepsAuditTrail(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	ctx := context.Background()
	token := providerAdminToken(t, rtr, db, "del_")

	victim := createTenantVia(t, rtr, token, "Удаляемый-"+t.Name())
	dev, err := db.CreatePendingDevice(ctx, victim.ID, "host-reparent-"+t.Name(), "linux")
	if err != nil {
		t.Fatalf("CreatePendingDevice: %v", err)
	}

	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/tenants/"+victim.ID, nil, token); w.Code != http.StatusNoContent {
		t.Fatalf("DELETE /tenants/%s = %d, body=%s", victim.ID, w.Code, w.Body)
	}

	// Устройство обязано быть видно в Default — оно там теперь живёт.
	if got := deviceTenant(t, db, tenancy.DefaultTenantID, dev.ID); got != tenancy.DefaultTenantID {
		t.Fatalf("устройство после удаления тенанта в %q, want Default", got)
	}

	// Журнал удалённого тенанта: событие лежит в его цепочке, тумбстоун её держит.
	if n := auditCount(t, db, victim.ID, "tenant.delete"); n == 0 {
		t.Fatal("в журнале удалённого тенанта нет записи tenant.delete — событие потерялось")
	}

	// Из реестра тенант исчез.
	_, tenants := listTenantsVia(t, rtr, token)
	for _, tn := range tenants {
		if tn.ID == victim.ID {
			t.Fatalf("удалённый тенант %s остался в реестре", victim.ID)
		}
	}
}

// deviceTenant читает tenant_id устройства в скоупе tenantID. Пусто = в этом скоупе
// устройства не видно.
func deviceTenant(t *testing.T, db *storage.DB, tenantID, deviceID string) string {
	t.Helper()
	ctx := context.Background()
	scoped, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("bind %s: %v", tenantID, err)
	}
	defer finish(true)

	var got string
	err = db.Scoped(scoped).QueryRow(scoped,
		`SELECT tenant_id::text FROM devices WHERE id = $1`, deviceID).Scan(&got)
	if err != nil {
		return ""
	}
	return got
}

func auditCount(t *testing.T, db *storage.DB, tenantID, action string) int {
	t.Helper()
	ctx := context.Background()
	scoped, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("bind %s: %v", tenantID, err)
	}
	defer finish(true)

	var n int
	if err := db.Scoped(scoped).QueryRow(scoped,
		`SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatalf("чтение журнала тенанта %s: %v", tenantID, err)
	}
	return n
}

// Тенант по умолчанию неудаляем: в нём сидит бутстрап-личность, без него в систему
// некому войти. Переименовать его при этом можно — это разные права.
func TestDeleteTenant_DefaultIsUndeletableButRenamable(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := providerAdminToken(t, rtr, db, "defprot_")

	w := authedDo(t, rtr, http.MethodDelete, "/api/v1/tenants/"+tenancy.DefaultTenantID, nil, token)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("удаление тенанта по умолчанию = %d, want 400 (body=%s)", w.Code, w.Body)
	}

	renamed := "Головной-" + t.Name()
	w = authedDo(t, rtr, http.MethodPatch, "/api/v1/tenants/"+tenancy.DefaultTenantID,
		[]byte(`{"name":"`+renamed+`"}`), token)
	if w.Code != http.StatusOK {
		t.Fatalf("переименование тенанта по умолчанию = %d, want 200 (body=%s)", w.Code, w.Body)
	}
}

func TestTenantWrites_RejectBadInput(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := providerAdminToken(t, rtr, db, "badinput_")
	unknown := "11111111-1111-4111-8111-111111111111"

	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"создание: не JSON", http.MethodPost, "/api/v1/tenants", `{`, http.StatusBadRequest},
		{"создание: пустое имя", http.MethodPost, "/api/v1/tenants", `{"name":""}`, http.StatusBadRequest},
		{"создание: имя из пробелов", http.MethodPost, "/api/v1/tenants", `{"name":"   "}`, http.StatusBadRequest},
		{"переименование: не JSON", http.MethodPatch, "/api/v1/tenants/" + unknown, `{`, http.StatusBadRequest},
		{"переименование: пустое имя", http.MethodPatch, "/api/v1/tenants/" + unknown, `{"name":" "}`, http.StatusBadRequest},
		{"переименование: нет такого тенанта", http.MethodPatch, "/api/v1/tenants/" + unknown, `{"name":"X"}`, http.StatusNotFound},
		{"удаление: нет такого тенанта", http.MethodDelete, "/api/v1/tenants/" + unknown, ``, http.StatusNotFound},
		{"приглашение: пустой e-mail", http.MethodPost, "/api/v1/tenants/" + tenancy.DefaultTenantID + "/invites", `{"email":""}`, http.StatusBadRequest},
		{"приглашение: неизвестная роль", http.MethodPost, "/api/v1/tenants/" + tenancy.DefaultTenantID + "/invites", `{"email":"x@test.com","role":"root"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := authedDo(t, rtr, c.method, c.path, []byte(c.body), token)
			if w.Code != c.want {
				t.Fatalf("%s %s = %d, want %d (body=%s)", c.method, c.path, w.Code, c.want, w.Body)
			}
		})
	}
}

// Приглашение В КОНКРЕТНЫЙ тенант — закрытие дыры полевого e2e 30.07: надзорный мог
// создать тенант, но не мог никого в него добавить, и свежий тенант оставался
// недостижим вообще ни для кого. Значит проверять надо не код ответа, а то, что
// приглашение легло в ЦЕЛЕВОЙ тенант.
func TestInviteToTenant_LandsInTargetTenantWithLeastPrivilege(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := providerAdminToken(t, rtr, db, "inv_")

	target := createTenantVia(t, rtr, token, "Приглашение-"+t.Name())
	email := fmt.Sprintf("invitee_%s@test.com", t.Name())

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/tenants/"+target.ID+"/invites",
		[]byte(`{"email":"`+email+`"}`), token)
	if w.Code != http.StatusOK {
		t.Fatalf("приглашение = %d, want 200 (body=%s)", w.Code, w.Body)
	}
	// SMTP в тестах выключен, поэтому ссылку обязаны отдать оператору: иначе
	// пригласить кого-либо было бы нечем.
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode invite: %v", err)
	}
	if out["invite_url"] == "" {
		t.Fatalf("в ответе нет invite_url: %s", w.Body)
	}

	role := invitationRole(t, db, target.ID, email)
	if role != "viewer" {
		t.Fatalf("роль приглашения = %q, want viewer (least-privilege по умолчанию)", role)
	}
}

func invitationRole(t *testing.T, db *storage.DB, tenantID, email string) string {
	t.Helper()
	ctx := context.Background()
	scoped, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("bind %s: %v", tenantID, err)
	}
	defer finish(true)

	var role string
	if err := db.Scoped(scoped).QueryRow(scoped,
		`SELECT role FROM invitation_tokens WHERE email = $1`, email).Scan(&role); err != nil {
		t.Fatalf("приглашение не найдено в скоупе целевого тенанта %s: %v", tenantID, err)
	}
	return role
}

// Перенос устройства между тенантами: машина обязана оказаться в целевом тенанте и
// пропасть из исходного. Односторонняя проверка («появилось в целевом») пропустила
// бы дубль, а он под FORCE RLS выглядел бы как две разные машины.
func TestMoveDeviceToTenant_MovesAndValidates(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	ctx := context.Background()
	token := providerAdminToken(t, rtr, db, "move_")

	dst := createTenantVia(t, rtr, token, "Приёмник-"+t.Name())
	dev, err := db.CreatePendingDevice(ctx, tenancy.DefaultTenantID, "host-move-"+t.Name(), "windows")
	if err != nil {
		t.Fatalf("CreatePendingDevice: %v", err)
	}

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+dev.ID+"/tenant",
		[]byte(`{"tenant_id":"`+dst.ID+`"}`), token)
	if w.Code != http.StatusNoContent {
		t.Fatalf("перенос устройства = %d, want 204 (body=%s)", w.Code, w.Body)
	}

	if got := deviceTenant(t, db, dst.ID, dev.ID); got != dst.ID {
		t.Fatalf("в скоупе целевого тенанта устройство = %q, want %q", got, dst.ID)
	}
	if got := deviceTenant(t, db, tenancy.DefaultTenantID, dev.ID); got != "" {
		t.Fatalf("устройство осталось видно в исходном тенанте (tenant_id=%q)", got)
	}

	bad := []struct {
		name, path, body string
		want             int
	}{
		{"нет tenant_id", "/api/v1/devices/" + dev.ID + "/tenant", `{}`, http.StatusBadRequest},
		{"tenant_id из пробелов", "/api/v1/devices/" + dev.ID + "/tenant", `{"tenant_id":"  "}`, http.StatusBadRequest},
		{"не JSON", "/api/v1/devices/" + dev.ID + "/tenant", `{`, http.StatusBadRequest},
		{"нет такого устройства", "/api/v1/devices/00000000-0000-4000-8000-0000000000ee/tenant",
			`{"tenant_id":"` + dst.ID + `"}`, http.StatusNotFound},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			w := authedDo(t, rtr, http.MethodPost, c.path, []byte(c.body), token)
			if w.Code != c.want {
				t.Fatalf("%s = %d, want %d (body=%s)", c.name, w.Code, c.want, w.Body)
			}
		})
	}
}
