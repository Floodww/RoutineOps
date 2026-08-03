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
	"github.com/google/uuid"
)

// Приглашение обязано заводить человека в СВОЙ тенант, а не в дефолтный.
//
// Полевой баг, найденный при наливке демо-данных на прод 03.08.2026: acceptInvite звал
// CreateUser с жёстко зашитым tenancy.DefaultTenantID и выбрасывал tenant_id, который
// приглашение честно несло. Последствие на живом проде: приглашённый администратор
// заказчика получил свою роль в тенанте Default, где лежат данные ДРУГОЙ организации, а
// целевой тенант остался без единого пользователя — то есть недостижимым.
//
// Сторону выписки приглашения закрывали отдельно (Q-31), сторона приёма не закрывалась
// никогда. Поэтому проверка «пользователь создался» здесь бесполезна — она зелёная и на
// сломанном коде; проверять надо ИМЕННО тенант членства.
func TestAcceptInvite_CreatesUserInInvitedTenant(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	ctx := context.Background()

	target, err := db.CreateTenant(ctx, "tenant_"+uuid.New().String())
	if err != nil {
		t.Fatalf("создание целевого тенанта: %v", err)
	}
	if target.ID == tenancy.DefaultTenantID {
		t.Fatalf("целевой тенант совпал с дефолтным — тест ничего не проверяет")
	}

	// Приглашение выписываем прямо в storage: ручка /tenants/{id}/invites требует
	// provider_admin, а предмет теста — сторона ПРИЁМА, и городить вокруг неё вход
	// надзорного администратора значило бы проверять заодно и его.
	// Приглашающий — админ целевого тенанта: invited_by ссылается на реального
	// пользователя, как и в бою.
	inviter, err := db.CreateUser(ctx, target.ID, "Inviter", "inviter-"+uuid.New().String()[:8]+"@example.com",
		"$2a$10$abcdefghijklmnopqrstuv", "it_admin")
	if err != nil {
		t.Fatalf("создание приглашающего админа: %v", err)
	}

	email := "invited-" + uuid.New().String()[:8] + "@example.com"
	token := uuid.New().String() + uuid.New().String()
	if _, err := db.CreateInvitation(ctx, target.ID, email, "it_admin", token, inviter.ID); err != nil {
		t.Fatalf("создание приглашения: %v", err)
	}
	// Сверяем сторону ВЫПИСКИ по тому же пути, каким её читает acceptInvite: CreateInvitation
	// возвращает структуру без tenant_id (в БД он есть, в RETURNING его нет), и проверка по
	// её полю ничего бы не значила.
	stored, err := db.GetInvitationByToken(ctx, token)
	if err != nil || stored == nil {
		t.Fatalf("чтение приглашения по токену: %v (nil=%v)", err, stored == nil)
	}
	if stored.TenantID != target.ID {
		t.Fatalf("приглашение выписано в тенант %s, а не в %s — сломана сторона выписки", stored.TenantID, target.ID)
	}

	body, _ := json.Marshal(map[string]string{
		"token": token, "name": "Invited Admin", "password": "Passw0rd1!",
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/accept-invite", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rtr.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("accept-invite вернул %d, want 200; тело: %s", w.Code, w.Body)
	}

	// Членство обязано быть в целевом тенанте — и не должно появиться в дефолтном.
	if got := userTenants(t, db, email); len(got) != 1 || got[0] != target.ID {
		t.Errorf("членства пользователя %s: %v; ожидалось ровно одно в тенанте %s", email, got, target.ID)
		for _, g := range got {
			if g == tenancy.DefaultTenantID {
				t.Errorf("человек заведён в тенант Default — он видит данные чужой организации, "+
					"а тенант %s остался без пользователей и недостижим", target.ID)
			}
		}
	}
}

// userTenants возвращает тенанты всех членств человека с этим e-mail.
//
// Читаем через личности (ADR-7), а не через список пользователей в API: любой такой список
// сам скоуплен тенантом вызывающего, то есть на сломанном коде показал бы ровно то, что мы
// проверяем, и тест был бы бесполезен.
func userTenants(t *testing.T, db *storage.DB, email string) []string {
	t.Helper()
	ident, err := db.GetIdentityByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("поиск личности %s: %v", email, err)
	}
	if ident == nil {
		t.Fatalf("личность %s не создана — accept-invite не завёл пользователя вовсе", email)
	}
	ms, err := db.ListMemberships(context.Background(), ident.ID)
	if err != nil {
		t.Fatalf("членства личности %s: %v", email, err)
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.TenantID)
	}
	return out
}
