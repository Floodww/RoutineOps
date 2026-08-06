package storage_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Заявка на временные админ-права из трея обязана доезжать до базы.
//
// 🔴 Полевой отказ 04.08: сотрудник жмёт кнопку в трее, трей пишет файл-заявку и
// показывает «Запрос отправлен ✓», служба шлёт RequestAdminAccess — и заявка не
// появляется в панели НИКОГДА. Причина в этой функции: INSERT не проставлял tenant_id,
// а таблица под FORCE RLS с `WITH CHECK (tenant_id = current_setting(...)::uuid)`.
// NULL под предикат не подходит ни при каком значении GUC, поэтому вставка отбивалась
// «new row violates row-level security policy» на КАЖДОЙ заявке. Шлюз отдавал agent'у
// Internal, агент считает Internal транзиентом — и долбил сервер каждые 5 секунд, а
// сотрудник видел галочку.
//
// Соседняя FetchActiveAdminRequest в том же файле всегда биндила тенанта сама — то
// есть расхождение было остатком, а не решением.
func TestCreateAdminAccessRequest_LandsInTenant(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	// 🔴 Устройство НЕ в дефолтном тенанте — иначе тест зелёный на сломанном коде.
	// Два обмана складываются ровно на дефолтном тенанте: миграция 045 навесила
	// `tenant_id DEFAULT <дефолтный>`, а testutil ставит роли
	// `ALTER ROLE mdm_app SET routineops.tenant_id = <дефолтный>`. Поэтому INSERT
	// мимо скоупа кладёт строку «куда надо» и предикат совпадает — при том что на
	// проде GUC у свежего соединения пуст, и та же вставка отбивается RLS.
	const tenantB = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'B-admin-req') ON CONFLICT DO NOTHING`, tenantB); err != nil {
		t.Fatalf("тенант B: %v", err)
	}
	scoped, finish, err := db.BindTenant(ctx, tenantB)
	if err != nil {
		t.Fatalf("BindTenant(B): %v", err)
	}
	var deviceID string
	if err := db.Scoped(scoped).QueryRow(scoped, `
		INSERT INTO devices (tenant_id, hostname, os, status)
		VALUES ($1, $2, 'windows', 'active') RETURNING id::text`,
		tenantB, fmt.Sprintf("host-aar-tenant-%s", uniq(t))).Scan(&deviceID); err != nil {
		finish(false)
		t.Fatalf("устройство в тенанте B: %v", err)
	}
	finish(true) // коммитим: заявка заводится отдельным вызовом, как в шлюзе

	now := time.Now()
	req, err := db.CreateAdminAccessRequest(ctx, deviceID, "", "запрос с устройства (трей)",
		now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("заявка не создана — в панели её не будет, а агент будет ретраить вечно: %v", err)
	}
	if req.ID == "" || req.Status != "pending" {
		t.Fatalf("заявка разъехалась: %+v", req)
	}

	// Строка обязана лежать В ТЕНАНТЕ УСТРОЙСТВА. Проверяем с обеих сторон: в своём
	// тенанте видна, в дефолтном — нет. Одной половины мало: «видна в B» прошло бы и
	// при tenant_id = NULL, если бы предикат вдруг ослабили, а «не видна в дефолтном» —
	// и просто при отсутствии строки.
	bctx, bfin, err := db.BindTenant(ctx, tenantB)
	if err != nil {
		t.Fatalf("BindTenant(B) для чтения: %v", err)
	}
	var tenantID string
	err = db.Scoped(bctx).QueryRow(bctx,
		`SELECT COALESCE(tenant_id::text, '') FROM admin_access_requests WHERE id = $1`, req.ID).Scan(&tenantID)
	bfin(true)
	if err != nil {
		t.Fatalf("заявка не видна в тенанте устройства — её не покажет ни одна ручка панели: %v", err)
	}
	if tenantID != tenantB {
		t.Fatalf("tenant_id заявки = %q, ожидался тенант устройства %q", tenantID, tenantB)
	}

	dctx, dfin, err := db.BindTenant(ctx, tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant(default): %v", err)
	}
	var n int
	err = db.Scoped(dctx).QueryRow(dctx,
		`SELECT count(*) FROM admin_access_requests WHERE id = $1`, req.ID).Scan(&n)
	dfin(true)
	if err != nil {
		t.Fatalf("чтение из дефолтного тенанта: %v", err)
	}
	if n != 0 {
		t.Fatal("заявка устройства из тенанта B видна администратору дефолтного тенанта")
	}

	// И через штатное чтение: именно им пользуется и панель, и реконсиляция агента.
	active, err := db.FetchActiveAdminRequest(ctx, deviceID)
	if err != nil {
		t.Fatalf("FetchActiveAdminRequest: %v", err)
	}
	if active == nil || active.ID != req.ID {
		t.Fatalf("свежая заявка не находится штатным чтением: %+v", active)
	}
}
