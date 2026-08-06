package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Отчёт агента «локальный админ выдан / отозван» обязан ложиться в строку ЧУЖОГО (не
// дефолтного) тенанта — то есть ходить тем скоупом, который открыл вызывающий, а не
// соседним соединением из пула.
//
// 🔴 Почему тест устроен именно так. admin_access_requests под FORCE RLS, а
// testutil ставит роли `ALTER ROLE mdm_app SET routineops.tenant_id = <default>` —
// поэтому запрос через пул в тестах «попадает» в дефолтный тенант и выглядит рабочим.
// Проверка «отчёт по устройству из дефолтного тенанта проходит» была бы ЗЕЛЁНОЙ и на
// сломанном коде. Единственное, что различает пул и Q(ctx), — чужой тенант: там у пула
// GUC остаётся дефолтным, строка под предикат не подходит, UPDATE трогает 0 строк, и
// функция отдаёт ErrAdminRequestNotFound. Вызывающий по этой ошибке делает
// accept-and-drop, то есть отчёт теряется ТИХО.
func TestUpdateAdminAccessReport_UsesCallerScopeNotPool(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	const tenantB = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'B-admin-report') ON CONFLICT DO NOTHING`, tenantB); err != nil {
		t.Fatalf("создание тенанта B: %v", err)
	}

	scoped, finish, err := db.BindTenant(ctx, tenantB)
	if err != nil {
		t.Fatalf("BindTenant(B): %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			finish(false)
		}
	}()

	var deviceID, userID string
	if err := db.Scoped(scoped).QueryRow(scoped, `
		INSERT INTO devices (tenant_id, hostname, os, status)
		VALUES ($1, $2, 'macos', 'active') RETURNING id::text`,
		tenantB, "aar-scope-"+uniq(t)).Scan(&deviceID); err != nil {
		t.Fatalf("устройство в тенанте B: %v", err)
	}
	// CreateUser переиспользует уже открытый скоуп (BindTenant при живой транзакции —
	// no-op) и сам заводит личность: пароль с миграции ADR-7 живёт не в users.
	u, err := db.CreateUser(scoped, tenantB, "B admin", "aar-scope-"+uniq(t)+"@test.local", "x", "it_admin")
	if err != nil {
		t.Fatalf("пользователь в тенанте B: %v", err)
	}
	userID = u.ID

	var requestID string
	if err := db.Scoped(scoped).QueryRow(scoped, `
		INSERT INTO admin_access_requests
		    (tenant_id, device_id, requested_by, status, reason, pending_expires_at)
		VALUES ($1, $2, $3, 'approved', 'нужен админ', now() + interval '1 hour')
		RETURNING id::text`, tenantB, deviceID, userID).Scan(&requestID); err != nil {
		t.Fatalf("заявка в тенанте B: %v", err)
	}

	at := time.Now().UTC().Truncate(time.Second)
	if err := db.UpdateAdminAccessReport(scoped, requestID, deviceID, "approved", at); err != nil {
		if errors.Is(err, storage.ErrAdminRequestNotFound) {
			t.Fatal("отчёт по устройству ЧУЖОГО тенанта не нашёл заявку: запрос ушёл мимо " +
				"скоупа вызывающего (соседнее соединение с дефолтным GUC). На проде это тихая " +
				"потеря отчёта — вызывающий по этой ошибке делает accept-and-drop")
		}
		t.Fatalf("UpdateAdminAccessReport: %v", err)
	}

	var grantedAt *time.Time
	if err := db.Scoped(scoped).QueryRow(scoped,
		`SELECT granted_at FROM admin_access_requests WHERE id = $1`, requestID).Scan(&grantedAt); err != nil {
		t.Fatalf("чтение granted_at: %v", err)
	}
	if grantedAt == nil {
		t.Fatal("granted_at не проставлен — отчёт о выдаче прав не сохранился")
	}

	// Отзыв тем же скоупом: терминальная половина того же потока.
	if err := db.UpdateAdminAccessReport(scoped, requestID, deviceID, "revoked", at.Add(time.Minute)); err != nil {
		t.Fatalf("отчёт об отзыве: %v", err)
	}
	var status string
	var revokedAt *time.Time
	if err := db.Scoped(scoped).QueryRow(scoped,
		`SELECT status, revoked_at FROM admin_access_requests WHERE id = $1`, requestID).Scan(&status, &revokedAt); err != nil {
		t.Fatalf("чтение статуса: %v", err)
	}
	if status != "revoked" || revokedAt == nil {
		t.Fatalf("после отчёта об отзыве status=%q revoked_at=%v — отзыв не записан", status, revokedAt)
	}

	finish(false) // тестовые строки не оставляем
	committed = true
}
