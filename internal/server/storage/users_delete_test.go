package storage_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/jackc/pgx/v5"
)

func seedAdmin(t *testing.T, db *storage.DB, prefix string) string {
	t.Helper()
	u, err := db.CreateUser(context.Background(), tenancy.DefaultTenantID, "Test", fmt.Sprintf("%s-%s@example.com", prefix, uniq(t)), "hash", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u.ID
}

func adminIDs(t *testing.T, db *storage.DB) []string {
	t.Helper()
	users, err := db.ListUsers(context.Background(), tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	var ids []string
	for _, u := range users {
		if u.Role == "it_admin" {
			ids = append(ids, u.ID)
		}
	}
	return ids
}

// Обе половины защиты «последнего администратора» в одном тесте, потому что вторая
// достижима ТОЛЬКО из состояния «ровно двое», и разводить их по тестам значило бы
// зависеть от порядка выполнения на общей базе.
//
// Почему защита вообще нужна в БД, а не в ручке: ручка запрещает удалять себя, поэтому
// одиночный администратор снести себя и так не может. Реальный путь к нулю — гонка:
// два администратора удаляют ДРУГ ДРУГА одновременно. Каждая транзакция видит по два
// (чужая ещё не закоммичена), обе проходят, и панель остаётся без единого аккаунта,
// способного что-либо изменить. Чинится только доступом к БД.
func TestDeleteUser_LastAdminGuard(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	// Приводим базу к одному администратору: тест обязан быть независимым от того,
	// что оставили соседи по пакету.
	for ids := adminIDs(t, db); len(ids) > 1; ids = adminIDs(t, db) {
		if _, err := db.DeleteUser(ctx, tenancy.DefaultTenantID, ids[0]); err != nil {
			t.Fatalf("подготовка: %v", err)
		}
	}
	if len(adminIDs(t, db)) == 0 {
		seedAdmin(t, db, "solo")
	}

	// 1. Единственного администратора удалить нельзя.
	last := adminIDs(t, db)[0]
	if _, err := db.DeleteUser(ctx, tenancy.DefaultTenantID, last); !errors.Is(err, storage.ErrLastAdmin) {
		t.Fatalf("удаление последнего дало %v, ожидалась ErrLastAdmin", err)
	}
	if got := adminIDs(t, db); len(got) != 1 {
		t.Fatalf("после отказа администраторов %d", len(got))
	}

	// 2. Проверка «не остаться без администраторов» обязана быть под локой, иначе она
	// же и не работает. Берём ТУ ЖЕ локу своим соединением и смотрим, что DeleteUser
	// её ждёт: пока держим — не проходит, отпустили — проходит.
	//
	// 🔴 Почему не «две горутины удаляют друг друга»: такой тест ПРОХОДИТ и со снятой
	// локой — окно гонки узкое, и две горутины в него просто не попадают. Он выглядит
	// как проверка сериализации, ничего не проверяя. Отвергнут после того, как я снял
	// локу и увидел зелёный прогон.
	second := seedAdmin(t, db, "duel")

	holder, err := pgx.Connect(ctx, sharedDSN)
	if err != nil {
		t.Fatalf("отдельное соединение: %v", err)
	}
	defer holder.Close(ctx)
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_lock($1)`, int64(storage.AdminGuardLockKey)); err != nil {
		t.Fatalf("взять локу: %v", err)
	}

	done := make(chan error, 1)
	go func() { _, e := db.DeleteUser(ctx, tenancy.DefaultTenantID, second); done <- e }()

	select {
	case e := <-done:
		t.Fatalf("DeleteUser прошёл, не дожидаясь локи (%v) — проверка «последнего администратора» не сериализована", e)
	case <-time.After(400 * time.Millisecond):
		// Ожидаемо блокируется.
	}

	if _, err := holder.Exec(ctx, `SELECT pg_advisory_unlock($1)`, int64(storage.AdminGuardLockKey)); err != nil {
		t.Fatalf("отпустить локу: %v", err)
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatalf("после снятия локи удаление не прошло: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DeleteUser не разблокировался после снятия локи")
	}

	if got := adminIDs(t, db); len(got) != 1 {
		t.Errorf("администраторов осталось %d, ожидался 1", len(got))
	}
}

// 🔴 Ради этого и миграция 040. Заявка на локальные права держала строку пользователя
// внешним ключом без ON DELETE: удалить того, кто хоть раз её оформлял, было НЕЛЬЗЯ —
// то есть уволенного администратора приходилось оставлять в системе.
//
// Проверяем обе половины: пользователь удаляется И заявка остаётся, потеряв ссылку.
// CASCADE вместо SET NULL прошёл бы первую половину и провалил вторую — а это значило
// бы, что удаление аккаунта чистит журнал запросов на повышение прав.
func TestDeleteUser_AdminAccessRequestSurvivesAsNull(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	seedAdmin(t, db, "keeper") // чтобы удаляемый не оказался последним
	victim := seedAdmin(t, db, "leaving")

	dev := mustCreateDevice(t, db, "host-"+uniq(t), "macos")
	req, err := db.CreateAdminAccessRequest(ctx, dev.ID, victim, "нужны права", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}
	if req.RequestedBy != victim {
		t.Fatalf("заявка не привязалась к пользователю: %q", req.RequestedBy)
	}

	deleted, err := db.DeleteUser(ctx, tenancy.DefaultTenantID, victim)
	if err != nil || !deleted {
		t.Fatalf("удаление пользователя с заявкой: deleted=%v err=%v", deleted, err)
	}

	after, err := db.FetchActiveAdminRequest(ctx, dev.ID)
	if err != nil {
		t.Fatalf("FetchActiveAdminRequest: %v", err)
	}
	if after == nil {
		t.Fatal("заявка исчезла вместе с пользователем — это CASCADE, а не SET NULL: журнал повышения прав обязан пережить увольнение")
	}
	if after.RequestedBy != "" {
		t.Errorf("requested_by = %q, ожидалось пусто", after.RequestedBy)
	}
}

func TestDeleteUser_UnknownIDIsNotAnError(t *testing.T) {
	db := newDB(t)
	// Несуществующий и заведомо кривой UUID: оба обязаны дать «не найдено», а не 500.
	// id::text в запросе именно для второго случая — голое сравнение с uuid даёт 22P02.
	for _, id := range []string{"00000000-0000-0000-0000-000000000000", "не-uuid"} {
		deleted, err := db.DeleteUser(context.Background(), tenancy.DefaultTenantID, id)
		if err != nil || deleted {
			t.Errorf("id=%q: deleted=%v err=%v, ожидалось (false, nil)", id, deleted, err)
		}
	}
}
