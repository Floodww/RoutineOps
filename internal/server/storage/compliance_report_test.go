package storage_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Отчёт соответствия (Q-62, вторая половина).
//
// 🔴 До этой правки дашборд печатал «Compliant» на каждом активном устройстве без
// единой проверки. Тесты ниже проверяют, что соответствие теперь СЧИТАЕТСЯ: у
// свежего устройства причин нет, у замолчавшего — есть, и обе половины различимы.

func complianceDevice(t *testing.T, db *storage.DB, suffix string) string {
	t.Helper()
	ctx := tenantCtx()
	fp := "fp-compl-" + suffix
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, "cn-compl-"+suffix, "cn-compl-"+suffix, "192.0.2.5")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}
	id, err := db.GetDeviceIDByFingerprint(ctx, fp)
	if err != nil || id == "" {
		t.Fatalf("GetDeviceIDByFingerprint: id=%q err=%v", id, err)
	}
	return id
}

func findDeviceCompliance(t *testing.T, report *storage.ComplianceReport, deviceID string) storage.DeviceCompliance {
	t.Helper()
	for _, d := range report.Devices {
		if d.DeviceID == deviceID {
			return d
		}
	}
	t.Fatalf("устройство %s не найдено в отчёте", deviceID)
	return storage.DeviceCompliance{}
}

// Свежее устройство без замечаний — соответствует, и причин у него ноль.
func TestComplianceReport_FreshDeviceIsCompliant(t *testing.T) {
	db := newDB(t)
	id := complianceDevice(t, db, uniq(t))

	report, err := db.BuildComplianceReport(tenantCtx(), tenancy.DefaultTenantID, nil)
	if err != nil {
		t.Fatalf("BuildComplianceReport: %v", err)
	}
	got := findDeviceCompliance(t, report, id)
	if !got.Compliant {
		t.Fatalf("свежее устройство не соответствует, причины: %v", got.Reasons)
	}
	if report.Summary.Devices == 0 {
		t.Error("сводка пустая при непустом списке устройств")
	}
}

// 🔴 Замолчавшее устройство НЕ соответствует. Именно эту строку прежний дашборд
// помечал «Compliant»: всё, что мы о ней знаем, устарело неделю назад.
func TestComplianceReport_StaleDeviceIsFlagged(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	id := complianceDevice(t, db, uniq(t))

	if _, err := db.Pool().Exec(ctx,
		`UPDATE devices SET last_seen_at = now() - interval '30 days' WHERE id = $1`, id); err != nil {
		t.Fatalf("состарить устройство: %v", err)
	}

	report, err := db.BuildComplianceReport(ctx, tenancy.DefaultTenantID, nil)
	if err != nil {
		t.Fatalf("BuildComplianceReport: %v", err)
	}
	got := findDeviceCompliance(t, report, id)
	if got.Compliant {
		t.Fatal("устройство, молчащее 30 дней, отмечено как соответствующее")
	}
	if !hasReason(got.Reasons, storage.ComplianceStale) {
		t.Fatalf("причины = %v, ожидали stale", got.Reasons)
	}
	if report.Summary.ByReason[storage.ComplianceStale] == 0 {
		t.Error("причина не попала в сводку")
	}
}

// Версия агента, которой канал не предлагает, — замечание. Пустая карта целевых
// версий эту причину НЕ выставляет: сравнивать не с чем, и обвинять парк не в чем.
func TestComplianceReport_OutdatedAgent(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	id := complianceDevice(t, db, uniq(t))
	if _, err := db.Pool().Exec(ctx,
		`UPDATE devices SET agent_version = '2.0.0' WHERE id = $1`, id); err != nil {
		t.Fatalf("проставить версию: %v", err)
	}

	without, err := db.BuildComplianceReport(ctx, tenancy.DefaultTenantID, nil)
	if err != nil {
		t.Fatalf("BuildComplianceReport: %v", err)
	}
	if hasReason(findDeviceCompliance(t, without, id).Reasons, storage.ComplianceOutdatedAgent) {
		t.Fatal("без целевых версий выставлена причина outdated_agent — сравнивать было не с чем")
	}

	with, err := db.BuildComplianceReport(ctx, tenancy.DefaultTenantID,
		map[string]string{storage.ChannelStable: "2.9.0"})
	if err != nil {
		t.Fatalf("BuildComplianceReport: %v", err)
	}
	got := findDeviceCompliance(t, with, id)
	if !hasReason(got.Reasons, storage.ComplianceOutdatedAgent) {
		t.Fatalf("причины = %v, ожидали outdated_agent (2.0.0 против целевой 2.9.0)", got.Reasons)
	}

	// Совпала с целевой — замечания нет.
	ok, err := db.BuildComplianceReport(ctx, tenancy.DefaultTenantID,
		map[string]string{storage.ChannelStable: "2.0.0"})
	if err != nil {
		t.Fatalf("BuildComplianceReport: %v", err)
	}
	if hasReason(findDeviceCompliance(t, ok, id).Reasons, storage.ComplianceOutdatedAgent) {
		t.Fatal("устройство на целевой версии отмечено отставшим")
	}
}

// Отчёт тенантный: чужие устройства в него не попадают.
func TestComplianceReport_DoesNotCrossTenants(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	id := complianceDevice(t, db, uniq(t))

	other := fmt.Sprintf("dddddddd-0000-4000-8000-%012d", time.Now().UnixNano()%1_000_000_000_000)
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`, other, "чужой-"+uniq(t)); err != nil {
		t.Fatalf("создать тенант: %v", err)
	}

	report, err := db.BuildComplianceReport(ctx, other, nil)
	if err != nil {
		t.Fatalf("BuildComplianceReport: %v", err)
	}
	for _, d := range report.Devices {
		if d.DeviceID == id {
			t.Fatal("устройство другого тенанта попало в отчёт")
		}
	}
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
