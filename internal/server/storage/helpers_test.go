package storage_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"github.com/Floodww/RoutineOps/internal/server/testutil"
)

var sharedDSN string

func TestMain(m *testing.M) {
	dsn, cleanup := testutil.NewDSNWithCleanup()
	sharedDSN = dsn
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Connect(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("storage.Connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func uniq(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// tenantCtx — контекст «как в бою»: тенант в нём уже лежит. На панельных путях его
// кладёт jwtMiddleware (из перечитанного из БД членства), на агентских — gateway после
// резолва по отпечатку серта. Голый context.Background() в тесте storage проверял бы
// путь, которого в проде нет, и до перехода на TenantScope именно так и получалось:
// запрос уходил в пул, RLS не совпадал ни с одной строкой, а тест был зелёным, потому
// что testutil ставит роли дефолтный routineops.tenant_id.
func tenantCtx() context.Context {
	return storage.WithTenantID(context.Background(), tenancy.DefaultTenantID)
}

// withCommittedTenant выполняет fn в tenant-tx и коммитит до возврата (видно другим вызовам storage).
func withCommittedTenant(t *testing.T, db *storage.DB, fn func(ctx context.Context)) {
	t.Helper()
	ctx, finish, err := db.BindTenant(context.Background(), tenancy.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	fn(ctx)
	finish(true)
}

func mustCreateUser(t *testing.T, db *storage.DB, email string) *storage.User {
	t.Helper()
	var u *storage.User
	withCommittedTenant(t, db, func(ctx context.Context) {
		var err error
		u, err = db.CreateUser(ctx, tenancy.DefaultTenantID, "Test User", email, "hash", "user")
		if err != nil {
			t.Fatalf("mustCreateUser %q: %v", email, err)
		}
	})
	return u
}

func mustCreateDevice(t *testing.T, db *storage.DB, hostname, osName string) *storage.Device {
	t.Helper()
	var d *storage.Device
	withCommittedTenant(t, db, func(ctx context.Context) {
		var err error
		d, err = db.CreatePendingDevice(ctx, tenancy.DefaultTenantID, hostname, osName)
		if err != nil {
			t.Fatalf("mustCreateDevice %q: %v", hostname, err)
		}
	})
	return d
}

func mustCreateActiveDevice(t *testing.T, db *storage.DB, hostname, osName string) *storage.Device {
	t.Helper()
	var d *storage.Device
	withCommittedTenant(t, db, func(ctx context.Context) {
		var err error
		d, err = db.CreatePendingDevice(ctx, tenancy.DefaultTenantID, hostname, osName)
		if err != nil {
			t.Fatalf("mustCreateDevice %q: %v", hostname, err)
		}
		if err := db.UpdateDeviceStatus(ctx, tenancy.DefaultTenantID, d.ID, "active"); err != nil {
			t.Fatalf("activate %q: %v", hostname, err)
		}
		d.Status = "active"
	})
	return d
}

func storageHeartbeatData(fingerprint, deviceID, certCN, ip string) storage.HeartbeatData {
	return storage.HeartbeatData{
		CertFingerprint: fingerprint,
		DeviceID:        deviceID,
		CertCN:          certCN,
		IPAddress:       ip,
	}
}

func storageInventoryData(fingerprint, hostname, os, osVersion string, software []string) storage.InventoryData {
	return storageInventoryDataV(fingerprint, hostname, os, osVersion, "", software)
}

func storageInventoryDataV(fingerprint, hostname, os, osVersion, agentVersion string, software []string) storage.InventoryData {
	items := make([]storage.SoftwareItem, len(software))
	for i, s := range software {
		items[i] = storage.SoftwareItem{Name: s, Version: "1.0"}
	}
	return storage.InventoryData{
		CertFingerprint: fingerprint,
		Hostname:        hostname,
		OS:              os,
		OSVersion:       osVersion,
		AgentVersion:    agentVersion,
		Software:        items,
	}
}
