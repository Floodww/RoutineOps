package storage_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
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

// uniq returns a unique suffix for the test — avoids unique-constraint collisions
// across tests that share one DB.
func uniq(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// mustCreateUser inserts a user and returns it.
func mustCreateUser(t *testing.T, db *storage.DB, email string) *storage.User {
	t.Helper()
	u, err := db.CreateUser(context.Background(), "Test User", email, "hash", "user")
	if err != nil {
		t.Fatalf("mustCreateUser %q: %v", email, err)
	}
	return u
}

// mustCreateDevice inserts a pending device and returns it.
func mustCreateDevice(t *testing.T, db *storage.DB, hostname, os string) *storage.Device {
	t.Helper()
	d, err := db.CreatePendingDevice(context.Background(), hostname, os)
	if err != nil {
		t.Fatalf("mustCreateDevice %q: %v", hostname, err)
	}
	return d
}

// mustCreateActiveDevice — устройство сразу в 'active'. Нужно тестам задач/фан-аута:
// скрипт-задачи создаются ТОЛЬКО для active-устройств (CreateTask/FanOutScriptToGroup
// гейтят по статусу — скрипт-канал не должен уезжать на pending/pending_approval).
func mustCreateActiveDevice(t *testing.T, db *storage.DB, hostname, os string) *storage.Device {
	t.Helper()
	d := mustCreateDevice(t, db, hostname, os)
	if err := db.UpdateDeviceStatus(context.Background(), d.ID, "active"); err != nil {
		t.Fatalf("activate %q: %v", hostname, err)
	}
	d.Status = "active"
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

// storageInventoryDataV — вариант с явной версией агента (для проверки персистентности
// agent_version и COALESCE-поведения при пустом значении от старого агента).
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
