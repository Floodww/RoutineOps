package storage_test

import (
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"
)

// CreateDecommissionTask ставит задачу с task_type='decommission'; lock_*-поля берут
// DEFAULT (миграция 013 — NOT NULL DEFAULT), поэтому и INSERT-RETURNING, и последующий
// GetTack-scan не падают на NULL.
func TestCreateDecommissionTask_TypeAndDefaults(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-decomm-%s", uniq(t)), "windows")

	task, err := db.CreateDecommissionTask(tenantCtx(), d.ID)
	if err != nil {
		t.Fatalf("CreateDecommissionTask: %v", err)
	}
	if task.TaskType != "decommission" {
		t.Errorf("task_type = %q, want decommission", task.TaskType)
	}
	if task.Status != "pending" {
		t.Errorf("status = %q, want pending", task.Status)
	}

	got, err := db.GetTask(tenantCtx(), task.ID)
	if err != nil || got == nil {
		t.Fatalf("GetTask: %v", err)
	}
	if got.TaskType != "decommission" {
		t.Errorf("GetTask task_type = %q, want decommission", got.TaskType)
	}

	// CompleteTask возвращает task_type — по нему gateway решает флип устройства.
	prev, tt, err := db.CompleteTask(tenantCtx(), task.ID, d.ID, "completed", "", "")
	if err != nil {
		t.Fatalf("CompleteTask: %v", err)
	}
	if tt != "decommission" {
		t.Errorf("CompleteTask taskType = %q, want decommission", tt)
	}
	if prev != "pending" {
		t.Errorf("prevStatus = %q, want pending", prev)
	}
}

// MarkDeviceDecommissioned флипает статус, а прощальный heartbeat недоснесённого агента
// НЕ воскрешает списанную машину (UpsertDeviceHeartbeat CASE поднимает только
// enrolled/pending) — ровно тот вектор «оживает своим же heartbeat'ом», что закрываем.
func TestMarkDeviceDecommissioned_ResurrectionGuard(t *testing.T) {
	db := newDB(t)
	fp := fmt.Sprintf("fp-decomm-%s", uniq(t))
	if err := db.UpsertDeviceHeartbeat(tenantCtx(), storageHeartbeatData(fp, "decomm-host", "decomm-host", "192.0.2.5")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}
	devID, _ := db.GetDeviceIDByFingerprint(tenantCtx(), fp)

	if err := db.MarkDeviceDecommissioned(tenantCtx(), devID); err != nil {
		t.Fatalf("MarkDeviceDecommissioned: %v", err)
	}
	if st, _ := db.GetDeviceStatusByID(tenantCtx(), tenancy.DefaultTenantID, devID); st != "decommissioned" {
		t.Fatalf("status = %q, want decommissioned", st)
	}

	// Посмертный heartbeat — не должен вернуть в 'active'.
	if err := db.UpsertDeviceHeartbeat(tenantCtx(), storageHeartbeatData(fp, "decomm-host", "decomm-host", "192.0.2.5")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat (посмертный): %v", err)
	}
	if st, _ := db.GetDeviceStatusByID(tenantCtx(), tenancy.DefaultTenantID, devID); st != "decommissioned" {
		t.Errorf("списанное устройство воскрешено heartbeat'ом: status = %q, want decommissioned", st)
	}
}

func TestGetDeviceStatusByID_NotFoundEmpty(t *testing.T) {
	db := newDB(t)
	st, err := db.GetDeviceStatusByID(tenantCtx(), tenancy.DefaultTenantID, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GetDeviceStatusByID: %v", err)
	}
	if st != "" {
		t.Errorf("status = %q, want \"\" для несуществующего устройства", st)
	}
}
