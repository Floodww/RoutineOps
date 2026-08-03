package storage_test

import (
	"context"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDetectUnreachableDevices(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	fp := "fp-unreach-" + uniq(t)
	_ = db.UpsertDeviceHeartbeat(ctx, storage.HeartbeatData{
		CertFingerprint: fp, DeviceID: "dev-unreach-" + uniq(t),
		CertCN: "unreach", IPAddress: "127.0.0.1",
	})
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fp)

	pool, _ := pgxpool.New(ctx, sharedDSN)
	defer pool.Close()
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET status='active', last_seen_at = now() - interval '30 minutes' WHERE id = $1`, devID); err != nil {
		t.Fatal(err)
	}

	// Считаем alert'ы ИМЕННО этого устройства (shared-DB: глобальный count ненадёжен).
	countMine := func() int {
		var c int
		_ = pool.QueryRow(ctx,
			`SELECT count(*) FROM alerts WHERE device_id=$1 AND alert_type='agent_unreachable'`, devID).Scan(&c)
		return c
	}

	if _, err := db.DetectUnreachableDevices(ctx, 15, 0); err != nil {
		t.Fatal(err)
	}
	if c := countMine(); c != 1 {
		t.Fatalf("ожидали 1 alert agent_unreachable, got %d", c)
	}
	// повтор → всё ещё 1 (анти-дубль: alert новее last_seen)
	if _, err := db.DetectUnreachableDevices(ctx, 15, 0); err != nil {
		t.Fatal(err)
	}
	if c := countMine(); c != 1 {
		t.Fatalf("дубль: ожидали 1 alert, got %d", c)
	}
}

// TestDetectUnreachableDevices_CooldownSuppressesFlapping воспроизводит дребезг
// modern-standby: устройство коротко проснулось (last_seen сдвинулся вперёд, но всё
// ещё за порогом) при уже существующем alert'е недалеко в прошлом. Эпизодный клоз
// пропускает (alert старее last_seen), а cooldown должен подавить повторный alert.
func TestDetectUnreachableDevices_CooldownSuppressesFlapping(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	fp := "fp-flap-" + uniq(t)
	_ = db.UpsertDeviceHeartbeat(ctx, storage.HeartbeatData{
		CertFingerprint: fp, DeviceID: "dev-flap-" + uniq(t),
		CertCN: "flap", IPAddress: "127.0.0.1",
	})
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fp)

	pool, _ := pgxpool.New(ctx, sharedDSN)
	defer pool.Close()
	countMine := func() int {
		var c int
		_ = pool.QueryRow(ctx,
			`SELECT count(*) FROM alerts WHERE device_id=$1 AND alert_type='agent_unreachable'`, devID).Scan(&c)
		return c
	}

	// Первый эпизод: устройство пропало 30 мин назад → 1 alert.
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET status='active', last_seen_at = now() - interval '30 minutes' WHERE id=$1`, devID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DetectUnreachableDevices(ctx, 15, 360); err != nil {
		t.Fatal(err)
	}
	if c := countMine(); c != 1 {
		t.Fatalf("ожидали 1 alert после первого эпизода, got %d", c)
	}

	// Симулируем дребезг: alert отодвигаем в прошлое (200 мин назад), а last_seen —
	// НОВЕЕ этого alert'а (100 мин назад), но всё ещё за порогом. Эпизодный клоз теперь
	// пропустит; блокировать должен только cooldown.
	if _, err := pool.Exec(ctx,
		`UPDATE alerts SET created_at = now() - interval '200 minutes'
		 WHERE device_id=$1 AND alert_type='agent_unreachable'`, devID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET last_seen_at = now() - interval '100 minutes' WHERE id=$1`, devID); err != nil {
		t.Fatal(err)
	}

	// cooldown=360: alert 200 мин назад ещё в окне → подавляем, count остаётся 1.
	if _, err := db.DetectUnreachableDevices(ctx, 15, 360); err != nil {
		t.Fatal(err)
	}
	if c := countMine(); c != 1 {
		t.Fatalf("cooldown должен был подавить дребезг, ожидали 1, got %d", c)
	}

	// cooldown=0 (выключен): тот же state → эпизодный клоз пропускает → новый alert.
	if _, err := db.DetectUnreachableDevices(ctx, 15, 0); err != nil {
		t.Fatal(err)
	}
	if c := countMine(); c != 2 {
		t.Fatalf("без cooldown ожидали новый alert (2), got %d", c)
	}
}

func TestFetchPolicyRules_PlatformFilter(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	fp := "fp-plat-" + uniq(t)
	_ = db.UpsertDeviceHeartbeat(ctx, storage.HeartbeatData{
		CertFingerprint: fp, DeviceID: "dev-plat-" + uniq(t),
		CertCN: "plat", IPAddress: "127.0.0.1",
	})
	pool, _ := pgxpool.New(ctx, sharedDSN)
	defer pool.Close()
	if _, err := pool.Exec(ctx, `UPDATE devices SET os='Windows 11' WHERE certificate_fingerprint=$1`, fp); err != nil {
		t.Fatal(err)
	}

	winName := "WinApp-" + uniq(t)
	macName := "MacApp-" + uniq(t)
	allName := "AllApp-" + uniq(t)
	if _, err := db.CreatePolicyRule(ctx, tenancy.DefaultTenantID, winName, "forbidden", nil, []string{"Windows"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreatePolicyRule(ctx, tenancy.DefaultTenantID, macName, "forbidden", nil, []string{"macOS"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreatePolicyRule(ctx, tenancy.DefaultTenantID, allName, "forbidden", nil, nil); err != nil {
		t.Fatal(err)
	}

	res, err := db.FetchPolicyRules(ctx, fp)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range res.Rules {
		got[r.SoftwareName] = true
	}
	if !got[winName] {
		t.Error("Windows-правило должно применяться к Windows-устройству")
	}
	if !got[allName] {
		t.Error("правило без платформ должно применяться ко всем")
	}
	if got[macName] {
		t.Error("macOS-правило НЕ должно применяться к Windows-устройству")
	}
}
