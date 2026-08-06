package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Очередь одобрения и «недоэнролленные» — РАЗНЫЕ состояния, и путать их дорого.
//
// Повод: при наливке демо-данных на прод (03.08.2026) устройства были заведены со
// статусом 'pending', не нашлись в панели, и это прочиталось как «очередь энроллмента не
// работает никогда». Проверка на живой БД показывает другое:
//
//	pending_approval — энроллмент ЗАВЕРШЁН (CSR подписан), ждём решения админа. Это и есть
//	                   очередь: она видна в списке и её берут Approve/RejectPendingDevices.
//	pending          — энроллмент НЕ завершён (серта нет) либо устройство сброшено на
//	                   переэнролл. Показывать такую строку в парке нечего, и одобрять тоже
//	                   нечего: одобрение перевело бы в active машину без сертификата.
//
// Предикат `status != 'pending'` в ListEnrolledDevices (postgres.go) исключает ТОЛЬКО
// литеральный 'pending' — ровно как и написано в комментарии web/src/pages/
// EnrollmentQueue.tsx. Тест держит это поведение с обеих сторон, чтобы следующий, кто
// увидит пустую очередь, сразу знал, где смотреть: в статусе своих данных, а не в SQL.
func TestEnrollmentQueueVisibility(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	// pending_approval — как его ставит боевой путь FinalizeBulkEnroll(requireApproval=true).
	tok := bulkToken(t, db, "", nil, true, time.Hour)
	waiting, requireApproval, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "queue-host", "windows")
	if err != nil {
		t.Fatalf("BeginBulkEnroll: %v", err)
	}
	if !requireApproval {
		t.Fatalf("токен выписан с require_approval, а BeginBulkEnroll вернул false")
	}
	if err := db.FinalizeBulkEnroll(ctx, tenancy.DefaultTenantID, waiting, "serial-queue", "fp-queue", true); err != nil {
		t.Fatalf("FinalizeBulkEnroll: %v", err)
	}

	// pending — устройство, которое энроллмент не довело до конца (серта нет).
	halfway, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "halfway-host", "windows")
	if err != nil {
		t.Fatalf("BeginBulkEnroll (halfway): %v", err)
	}

	devices, _, err := db.ListEnrolledDevices(ctx, tenancy.DefaultTenantID, "", "", 100, 0)
	if err != nil {
		t.Fatalf("ListEnrolledDevices: %v", err)
	}
	seen := map[string]string{}
	for _, d := range devices {
		seen[d.ID] = d.Status
	}

	// Главное утверждение: ожидающее одобрения устройство ВИДНО. Если оно пропадёт из
	// списка, очередь в панели опустеет, а кнопка «одобрить всех» останется — и админ
	// будет одобрять то, чего не видит.
	if st, ok := seen[waiting]; !ok {
		t.Errorf("устройство в статусе pending_approval НЕ попало в список — очередь одобрения будет пуста в панели")
	} else if st != "pending_approval" {
		t.Errorf("статус ожидающего устройства = %q, want pending_approval", st)
	}

	// Обратная сторона: недоэнролленное устройство в парке показывать нечего.
	if st, ok := seen[halfway]; ok {
		t.Errorf("устройство без завершённого энроллмента попало в список парка со статусом %q", st)
	}
}

// Batch-одобрение работает ровно по pending_approval — и не трогает недоэнролленные.
//
// Это вторая половина того же недоразумения: одобрить 'pending' невозможно не потому, что
// «кнопка сломана», а потому что переводить в active машину без сертификата нельзя.
func TestApprovePendingTouchesOnlyPendingApproval(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	// Скоуп по группе обязателен: БД в пакете общая (helpers_test.go, sharedDSN), и
	// batch-одобрение без группы забрало бы устройства соседних тестов — счётчик показал бы
	// что угодно. Поймано первым же прогоном.
	group, err := db.CreateDeviceGroup(ctx, tenancy.DefaultTenantID, "queue-grp-"+uniq(t), "", "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}

	tok := bulkToken(t, db, group.ID, nil, true, time.Hour)
	waiting, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "approve-host", "windows")
	if err != nil {
		t.Fatalf("BeginBulkEnroll: %v", err)
	}
	if err := db.FinalizeBulkEnroll(ctx, tenancy.DefaultTenantID, waiting, "serial-approve", "fp-approve", true); err != nil {
		t.Fatalf("FinalizeBulkEnroll: %v", err)
	}
	halfway, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "approve-halfway", "windows")
	if err != nil {
		t.Fatalf("BeginBulkEnroll (halfway): %v", err)
	}

	n, err := db.ApprovePendingDevices(ctx, tenancy.DefaultTenantID, group.ID)
	if err != nil {
		t.Fatalf("ApprovePendingDevices: %v", err)
	}
	if n != 1 {
		t.Errorf("одобрено %d устройств группы, want 1 (только pending_approval)", n)
	}

	assertStatus(t, db, waiting, "active")
	assertStatus(t, db, halfway, "pending")
}

func assertStatus(t *testing.T, db *storage.DB, deviceID, want string) {
	t.Helper()
	ctx, finish, err := db.BindTenant(context.Background(), tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	defer finish(true)

	var got string
	if err := db.Scoped(ctx).QueryRow(ctx, `SELECT status FROM devices WHERE id = $1`, deviceID).Scan(&got); err != nil {
		t.Fatalf("чтение статуса %s: %v", deviceID, err)
	}
	if got != want {
		t.Errorf("статус устройства %s = %q, want %q", deviceID, got, want)
	}
}
