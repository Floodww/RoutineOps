package storage_test

import (
	"context"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCleanupOldData_DeletesOldRecords(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	// создать device
	_ = db.UpsertDeviceHeartbeat(ctx, storage.HeartbeatData{
		CertFingerprint: "fp-cleanup", DeviceID: "dev-cleanup",
		CertCN: "dev-cleanup", IPAddress: "127.0.0.1",
	})
	devID, _ := db.GetDeviceIDByFingerprint(ctx, "fp-cleanup")

	// создать алерт и ПРИНЯТЬ его: retention удаляет только принятые старые алерты
	// (непринятые сохраняются — см. CleanupOldData и TestCleanupOldData_PreservesUnacknowledged).
	_, _ = db.CreateAlert(ctx, devID, "FORBIDDEN_SOFTWARE", "test", "")
	alerts, _ := db.ListAlerts(ctx, tenancy.DefaultTenantID, devID, 10)
	if len(alerts) == 0 {
		t.Fatal("алерт не создан")
	}
	_ = db.AcknowledgeAlert(ctx, tenancy.DefaultTenantID, alerts[0].ID)

	// backdating через прямой SQL (трюк: pool недоступен снаружи, используй sharedDSN)
	pool, _ := pgxpool.New(ctx, sharedDSN)
	defer pool.Close()
	pool.Exec(ctx,
		`UPDATE alerts SET created_at = NOW() - INTERVAL '10 days'
         WHERE device_id = $1`, devID)

	n, err := db.CleanupOldData(ctx, 7, 7, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("ожидали удаление хотя бы 1 записи")
	}
}

// TestCleanupOldData_PreservesUnacknowledged: старый НЕпринятый алерт retention НЕ трогает —
// он служит якорем дедупа agent_unreachable и сигналом, который оператор ещё не видел.
func TestCleanupOldData_PreservesUnacknowledged(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	_ = db.UpsertDeviceHeartbeat(ctx, storage.HeartbeatData{
		CertFingerprint: "fp-cleanup-unack", DeviceID: "dev-cleanup-unack",
		CertCN: "dev-cleanup-unack", IPAddress: "127.0.0.1",
	})
	devID, _ := db.GetDeviceIDByFingerprint(ctx, "fp-cleanup-unack")
	_, _ = db.CreateAlert(ctx, devID, "AGENT_UNREACHABLE", "test", "")

	pool, _ := pgxpool.New(ctx, sharedDSN)
	defer pool.Close()
	pool.Exec(ctx,
		`UPDATE alerts SET created_at = NOW() - INTERVAL '10 days' WHERE device_id = $1`, devID)

	if _, err := db.CleanupOldData(ctx, 7, 7, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	alerts, _ := db.ListAlerts(ctx, tenancy.DefaultTenantID, devID, 10)
	if len(alerts) != 1 {
		t.Errorf("непринятый алерт удалён retention'ом: осталось %d, ждали 1", len(alerts))
	}
}

func TestCleanupOldData_PreservesRecentRecords(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	_ = db.UpsertDeviceHeartbeat(ctx, storage.HeartbeatData{
		CertFingerprint: "fp-cleanup-recent", DeviceID: "dev-cleanup-recent",
		CertCN: "dev-cleanup-recent", IPAddress: "127.0.0.1",
	})
	devID, _ := db.GetDeviceIDByFingerprint(ctx, "fp-cleanup-recent")
	_, _ = db.CreateAlert(ctx, devID, "FORBIDDEN_SOFTWARE", "test", "")

	n, err := db.CleanupOldData(ctx, 7, 7, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("ожидали 0, получили %d", n)
	}
}

func TestCleanupOldData_Disabled(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	n, err := db.CleanupOldData(ctx, 0, 0, t.TempDir())
	if err != nil || n != 0 {
		t.Error("ожидали 0, nil")
	}
}

// audit_log хранится по ОТДЕЛЬНОМУ (длинному) сроку: короткий data-retention для
// alerts/results не должен стирать журнал безопасности.
func TestCleanupOldData_AuditSeparateRetention(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	marker := "audit-ret-" + uniq(t)
	// userID пустой (→NULL, как login_failed); уникальный маркер — в user_email.
	if err := db.WriteAuditLog(ctx, "", marker, "test_action", "user", "", nil); err != nil {
		t.Fatal(err)
	}

	pool, _ := pgxpool.New(ctx, sharedDSN)
	defer pool.Close()
	if _, err := pool.Exec(ctx,
		`UPDATE audit_log SET created_at = NOW() - INTERVAL '30 days' WHERE user_email = $1`, marker); err != nil {
		t.Fatal(err)
	}

	count := func() int {
		var c int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE user_email = $1`, marker).Scan(&c)
		return c
	}

	// data=7, audit=365 → 30-дневная запись аудита ПЕРЕЖИВАЕТ
	if _, err := db.CleanupOldData(ctx, 7, 365, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if c := count(); c != 1 {
		t.Fatalf("audit_log должен пережить при audit-retention 365, got %d", c)
	}

	// audit=7 → та же запись стирается
	if _, err := db.CleanupOldData(ctx, 7, 7, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if c := count(); c != 0 {
		t.Fatalf("audit_log должен стереться при audit-retention 7, got %d", c)
	}
}
