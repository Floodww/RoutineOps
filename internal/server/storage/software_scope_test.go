package storage_test

import (
	"context"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Расширенный инвентарь ПО (миграция 036, proto SoftwareItem 3–8).
//
// Главное здесь — не round-trip колонок, а регресс безопасности: до 2.6.0 агент
// вообще не присылал установки в профиль пользователя, поэтому правило запрещённого
// ПО на них не срабатывало и установка «на себя» была рабочим обходом запрета.
// Теперь такая запись обязана считаться нарушением — при том что снять её нечем.
func TestInventorySoftware_ScopeAndFields(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	inv := storage.InventoryData{
		CertFingerprint: "fp-soft-scope",
		Hostname:        "soft-scope",
		OS:              "Windows",
		OSVersion:       "11",
		Software: []storage.SoftwareItem{
			{
				Name: "7-Zip", Version: "23.01", Vendor: "Igor Pavlov",
				InstallLocation: `C:\Program Files\7-Zip`, Arch: "x64",
				UninstallID:     "{23170F69-40C1-2702-2301-000001000000}",
				UninstallMethod: "msi", Scope: "machine",
			},
			// Одно и то же имя в двух scope: машинная установка и установка в профиль.
			// Обе строки обязаны доехать — по имени они неразличимы.
			{Name: "Telegram Desktop", Version: "5.0", Scope: "machine", UninstallMethod: "windows_quiet", UninstallID: "TelegramDesktop"},
			{Name: "Telegram Desktop", Version: "4.9", Scope: "user", UninstallID: "TelegramDesktop-user"},
		},
	}
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData("fp-soft-scope", "soft-scope", "soft-scope", "192.0.2.36")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}
	if err := db.UpsertInventory(ctx, inv); err != nil {
		t.Fatalf("UpsertInventory: %v", err)
	}
	deviceID, err := db.GetDeviceIDByFingerprint(ctx, "fp-soft-scope")
	if err != nil || deviceID == "" {
		t.Fatalf("GetDeviceIDByFingerprint: id=%q err=%v", deviceID, err)
	}

	_, software, err := db.GetDevice(ctx, tenancy.DefaultTenantID, deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if len(software) != 3 {
		t.Fatalf("ожидали 3 записи ПО (обе установки Telegram различимы по scope), получили %d: %+v", len(software), software)
	}
	var zip storage.SoftwareItem
	var userScoped int
	for _, s := range software {
		if s.Name == "7-Zip" {
			zip = s
		}
		if s.Scope == "user" {
			userScoped++
		}
	}
	if zip.Vendor != "Igor Pavlov" || zip.Arch != "x64" || zip.UninstallMethod != "msi" ||
		zip.UninstallID == "" || zip.InstallLocation == "" || zip.Scope != "machine" {
		t.Errorf("поля 7-Zip не доехали до чтения: %+v", zip)
	}
	if userScoped != 1 {
		t.Errorf("ожидали ровно одну per-user запись, получили %d", userScoped)
	}

	// Правило запрещённого ПО видит нарушение, и в примере — machine-установка:
	// из двух совпадений оператору полезнее то, которое можно снять.
	rule, err := db.CreatePolicyRule(ctx, tenancy.DefaultTenantID, "telegram", "forbidden", nil, nil)
	if err != nil {
		t.Fatalf("CreatePolicyRule: %v", err)
	}
	rows, err := db.ListSoftwarePolicyDeviceCompliance(ctx, tenancy.DefaultTenantID, rule.ID)
	if err != nil {
		t.Fatalf("ListSoftwarePolicyDeviceCompliance: %v", err)
	}
	got := findCompliance(t, rows, deviceID)
	if !got.Installed {
		t.Fatalf("machine-установка Telegram не засчитана нарушением: %+v", got)
	}
	if got.MatchedScope != "machine" {
		t.Errorf("ожидали в примере снимаемую machine-установку, получили scope=%q", got.MatchedScope)
	}

	// А теперь машина, где Telegram стоит ТОЛЬКО в профиле пользователя. Это и есть
	// бывший обход запрета: нарушение обязано считаться, а scope — сказать оператору,
	// что удалить нечем.
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData("fp-soft-user", "soft-user", "soft-user", "192.0.2.37")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat user: %v", err)
	}
	if err := db.UpsertInventory(ctx, storage.InventoryData{
		CertFingerprint: "fp-soft-user", Hostname: "soft-user", OS: "Windows", OSVersion: "11",
		Software: []storage.SoftwareItem{{Name: "Telegram Desktop", Version: "4.9", Scope: "user"}},
	}); err != nil {
		t.Fatalf("UpsertInventory user: %v", err)
	}
	userDeviceID, err := db.GetDeviceIDByFingerprint(ctx, "fp-soft-user")
	if err != nil || userDeviceID == "" {
		t.Fatalf("GetDeviceIDByFingerprint user: id=%q err=%v", userDeviceID, err)
	}
	rows, err = db.ListSoftwarePolicyDeviceCompliance(ctx, tenancy.DefaultTenantID, rule.ID)
	if err != nil {
		t.Fatalf("ListSoftwarePolicyDeviceCompliance (2): %v", err)
	}
	got = findCompliance(t, rows, userDeviceID)
	if !got.Installed {
		t.Fatalf("установка в профиль пользователя НЕ засчитана нарушением — запрет снова обходится установкой «на себя»: %+v", got)
	}
	if got.MatchedScope != "user" {
		t.Errorf("ожидали scope=user в примере (снять нечем), получили %q", got.MatchedScope)
	}
}

func findCompliance(t *testing.T, rows []storage.SoftwarePolicyDeviceCompliance, deviceID string) storage.SoftwarePolicyDeviceCompliance {
	t.Helper()
	for _, r := range rows {
		if r.DeviceID == deviceID {
			return r
		}
	}
	t.Fatalf("устройство %s не попало в разрез правила (ожидали глобальную область действия)", deviceID)
	return storage.SoftwarePolicyDeviceCompliance{}
}
