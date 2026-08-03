package storage_test

import (
	"context"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

func TestListScriptResultsByPolicy(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	scr, err := db.CreateScript(ctx, tenancy.DefaultTenantID, "res-script-"+uniq(t), "linux", "echo hi")
	if err != nil {
		t.Fatalf("CreateScript: %v", err)
	}
	pol, err := db.CreateScriptPolicy(ctx, tenancy.DefaultTenantID, "res-pol-"+uniq(t), scr.ID, "schedule", nil, nil)
	if err != nil {
		t.Fatalf("CreateScriptPolicy: %v", err)
	}
	dev := mustCreateDevice(t, db, "res-host-"+uniq(t), "linux")

	// без результатов → пусто (не nil-паника)
	got, err := db.ListScriptResultsByPolicy(ctx, tenancy.DefaultTenantID, pol.ID, 100)
	if err != nil {
		t.Fatalf("ListScriptResultsByPolicy (empty): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ожидали 0 результатов, получили %d", len(got))
	}

	if err := db.SaveScriptResult(ctx, storage.ScriptResultInput{
		PolicyID:   pol.ID,
		DeviceID:   dev.ID,
		RunID:      "run-" + uniq(t),
		ExitCode:   0,
		Stdout:     "hello",
		Stderr:     "",
		Trigger:    "schedule",
		StartedAt:  time.Now().Add(-time.Minute),
		FinishedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SaveScriptResult: %v", err)
	}

	got, err = db.ListScriptResultsByPolicy(ctx, tenancy.DefaultTenantID, pol.ID, 100)
	if err != nil {
		t.Fatalf("ListScriptResultsByPolicy: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ожидали 1 результат, получили %d", len(got))
	}
	r := got[0]
	if r.PolicyID != pol.ID || r.DeviceID != dev.ID {
		t.Errorf("id не совпали: policy=%s device=%s", r.PolicyID, r.DeviceID)
	}
	if r.DeviceHostname == "" {
		t.Errorf("join не подтянул hostname устройства")
	}
	if r.Stdout != "hello" || r.ExitCode != 0 {
		t.Errorf("данные результата не совпали: %+v", r)
	}
}
