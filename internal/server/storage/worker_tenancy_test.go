package storage_test

import (
	"context"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Фоновые воркеры кросс-тенантные: тенанта в их контексте нет. До перевода прода на
// роль mdm_app (049) они ходили в БД напрямую и это работало только потому, что у
// прежней роли стоял rolbypassrls — предикат RLS не вычислялся вовсе. Под app-ролью
// тот же запрос падает 22P02: предикат из 046 кастует пустой GUC в uuid (намеренно
// fail-closed). Полевой e2e 30.07 поймал это на живом проде: expire admin requests,
// take alert escalations, sweep evidence gaps и reconcile stale acked tasks сыпались
// каждую минуту, то есть JIT-права не истекали, а алерты не эскалировались.
//
// Тест фиксирует контракт ForEachTenant: обход даёт каждому вызову привязанный
// скоуп, и воркерные методы под ним не падают.

const workerOtherTenant = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

func TestForEachTenant_BindsScopeForWorkers(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'Worker Other') ON CONFLICT DO NOTHING`, workerOtherTenant,
	); err != nil {
		t.Fatalf("other tenant: %v", err)
	}

	seen := map[string]bool{}
	if err := db.ForEachTenant(ctx, func(tctx context.Context) error {
		id, ok := storage.TenantIDFrom(tctx)
		if !ok || id == "" {
			t.Fatalf("ForEachTenant: пустой тенант в скоупе (ok=%v)", ok)
		}
		seen[id] = true

		// Ровно те вызовы, что падали на проде. Результат не важен — важно, что
		// запрос доходит до БД и не отбивается предикатом RLS.
		if _, err := db.ExpireStaleAdminRequests(tctx); err != nil {
			return err
		}
		if _, err := db.FailStaleAckedTasks(tctx, storage.StaleAckedTimeoutMinutes); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("ForEachTenant: %v", err)
	}

	if !seen[tenancy.DefaultTenantID] || !seen[workerOtherTenant] {
		t.Fatalf("обойдены не все тенанты: %v", seen)
	}
}

// Якорь цепочки аудита тенантский: до 30.07 он был захардкожен на дефолтный тенант,
// то есть у всех остальных tamper-evidence молча отсутствовала при живом
// /audit-log/verify. Без привязанного скоупа вызов обязан отказать, а не тихо
// записать якорь не тому тенанту.
func TestWriteAuditAnchor_RequiresBoundTenant(t *testing.T) {
	db := newDB(t)

	if _, _, err := db.WriteAuditAnchor(context.Background()); err == nil {
		t.Fatal("WriteAuditAnchor без скоупа обязан вернуть ошибку, вернул nil")
	}

	ctx, finish, err := db.BindTenant(context.Background(), workerOtherTenant)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	defer finish(false)

	if _, _, err := db.WriteAuditAnchor(ctx); err != nil {
		t.Fatalf("WriteAuditAnchor под скоупом: %v", err)
	}
}
