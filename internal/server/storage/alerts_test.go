package storage_test

import (
	"context"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"
)

func TestCreateAlert_NoError(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-alert-%s", uniq(t)), "macos")

	_, err := db.CreateAlert(context.Background(), d.ID, "FORBIDDEN_SOFTWARE", `{"process":"bad.exe"}`, "")
	if err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}
}

// TestCreateAlert_DedupsUnacknowledged: серверный дедуп подавляет повтор того же
// (device, type, details), пока висит непринятый алерт; после ack повтор снова создаётся.
func TestCreateAlert_DedupsUnacknowledged(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-alertdedup-%s", uniq(t)), "macos")
	ctx := context.Background()

	created, err := db.CreateAlert(ctx, d.ID, "FORBIDDEN_SOFTWARE", `{"process":"bad.exe"}`, "")
	if err != nil || !created {
		t.Fatalf("первый алерт: created=%v err=%v", created, err)
	}
	created, err = db.CreateAlert(ctx, d.ID, "FORBIDDEN_SOFTWARE", `{"process":"bad.exe"}`, "")
	if err != nil {
		t.Fatalf("второй алерт: %v", err)
	}
	if created {
		t.Error("дубль непринятого алерта создан — дедуп не сработал")
	}
	// другие details — самостоятельное событие, не дубль
	created, err = db.CreateAlert(ctx, d.ID, "FORBIDDEN_SOFTWARE", `{"process":"other.exe"}`, "")
	if err != nil || !created {
		t.Fatalf("другой details должен создать алерт: created=%v err=%v", created, err)
	}
	// после принятия всех — повтор снова создаётся («проблема вернулась после разбора»)
	alerts, _ := db.ListAlerts(ctx, tenancy.DefaultTenantID, d.ID, 10)
	for _, a := range alerts {
		_ = db.AcknowledgeAlert(ctx, tenancy.DefaultTenantID, a.ID)
	}
	created, err = db.CreateAlert(ctx, d.ID, "FORBIDDEN_SOFTWARE", `{"process":"bad.exe"}`, "")
	if err != nil || !created {
		t.Fatalf("после ack повтор должен создаться: created=%v err=%v", created, err)
	}
	if alerts, _ := db.ListAlerts(ctx, tenancy.DefaultTenantID, d.ID, 10); len(alerts) != 3 {
		t.Errorf("ждали 3 строки (bad×2 + other×1), получили %d", len(alerts))
	}
}

func TestListAlerts_ContainsCreated(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-alertlist-%s", uniq(t)), "windows")
	_, _ = db.CreateAlert(context.Background(), d.ID, "UNAUTHORIZED_INSTALL", `{}`, "")

	alerts, err := db.ListAlerts(context.Background(), tenancy.DefaultTenantID, d.ID, 50)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(alerts) == 0 {
		t.Error("expected at least one alert")
	}
	if alerts[0].DeviceID != d.ID {
		t.Errorf("device_id = %q, want %q", alerts[0].DeviceID, d.ID)
	}
}

func TestListAlerts_FilterByDevice_Isolates(t *testing.T) {
	db := newDB(t)
	d1 := mustCreateDevice(t, db, fmt.Sprintf("host-af1-%s", uniq(t)), "macos")
	d2 := mustCreateDevice(t, db, fmt.Sprintf("host-af2-%s", uniq(t)), "windows")

	_, _ = db.CreateAlert(context.Background(), d1.ID, "TYPE_A", `{}`, "")
	_, _ = db.CreateAlert(context.Background(), d2.ID, "TYPE_B", `{}`, "")

	alerts, err := db.ListAlerts(context.Background(), tenancy.DefaultTenantID, d1.ID, 50)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	for _, a := range alerts {
		if a.DeviceID != d1.ID {
			t.Errorf("got alert for device %q, want only %q", a.DeviceID, d1.ID)
		}
	}
}

func TestAcknowledgeAlert_SetsTimestamp(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-ack-alert-%s", uniq(t)), "macos")
	_, _ = db.CreateAlert(context.Background(), d.ID, "FORBIDDEN_SOFTWARE", `{}`, "")

	alerts, _ := db.ListAlerts(context.Background(), tenancy.DefaultTenantID, d.ID, 1)
	if len(alerts) == 0 {
		t.Fatal("no alert to acknowledge")
	}
	alertID := alerts[0].ID

	if err := db.AcknowledgeAlert(context.Background(), tenancy.DefaultTenantID, alertID); err != nil {
		t.Fatalf("AcknowledgeAlert: %v", err)
	}

	// re-fetch and verify acknowledged_at is set
	refreshed, _ := db.ListAlerts(context.Background(), tenancy.DefaultTenantID, d.ID, 1)
	if refreshed[0].AcknowledgedAt == nil {
		t.Error("acknowledged_at should be set after acknowledge")
	}
}

func TestAcknowledgeAlert_AlreadyAcknowledged_ReturnsError(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-doubleack-%s", uniq(t)), "windows")
	_, _ = db.CreateAlert(context.Background(), d.ID, "TYPE_X", `{}`, "")

	alerts, _ := db.ListAlerts(context.Background(), tenancy.DefaultTenantID, d.ID, 1)
	alertID := alerts[0].ID

	_ = db.AcknowledgeAlert(context.Background(), tenancy.DefaultTenantID, alertID)
	err := db.AcknowledgeAlert(context.Background(), tenancy.DefaultTenantID, alertID)
	if err == nil {
		t.Error("expected error on double-acknowledge, got nil")
	}
}
