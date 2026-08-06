package storage_test

import (
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Способности агента (devices.capabilities) обязаны доезжать из инвентаря в карточку
// устройства.
//
// Дефект, ради которого этот тест написан, был тихим и полным: колонка заводилась
// миграцией 067, агент честно присылал список в DeviceInfo.capabilities, сервер читал
// колонку гейтом `capabilities @> ARRAY['screen_session']` — и НЕ ЗАПИСЫВАЛ её нигде.
// Колонка оставалась NULL у всего парка, гейт всегда давал false, и удалённый рабочий
// стол не мог стартовать НИ НА ОДНОМ устройстве. Ошибка при этом выглядела как «агент не
// поддерживает удалённый стол», то есть указывала на агента.
func TestInventoryPersistsCapabilities(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	fp := "fp-caps-" + uniq(t)

	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, "caps-host", "caps-host", "192.0.2.31")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}

	inv := storageInventoryDataV(fp, "caps-host", "windows", "11", "2.6.0", nil)
	inv.Capabilities = []string{"screen_session"}
	if err := db.UpsertInventory(ctx, inv); err != nil {
		t.Fatalf("UpsertInventory: %v", err)
	}

	if got := readCapabilities(t, db, fp); !hasCap(got, "screen_session") {
		t.Fatalf("способности в карточке %v — сервер не сохранил то, что прислал агент", got)
	}

	// И обратное направление: список обязан СЖИМАТЬСЯ. Агента можно понизить с
	// enterprise-сборки на free той же версии, и удалённого стола в нём тогда нет
	// физически. Sticky-запись (как у остальных полей инвентаря) оставила бы
	// screen_session навсегда, и сервер продолжил бы ставить сеансы агенту, который их
	// не умеет.
	inv.Capabilities = nil
	if err := db.UpsertInventory(ctx, inv); err != nil {
		t.Fatalf("повторный UpsertInventory: %v", err)
	}
	if got := readCapabilities(t, db, fp); hasCap(got, "screen_session") {
		t.Fatalf("способность осталась после понижения агента: %v", got)
	}
}

func readCapabilities(t *testing.T, db *storage.DB, fingerprint string) []string {
	t.Helper()
	ctx, finish, err := db.BindTenant(tenantCtx(), tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	defer finish(true)

	var caps []string
	if err := db.Scoped(ctx).QueryRow(ctx,
		`SELECT COALESCE(capabilities, '{}') FROM devices WHERE certificate_fingerprint = $1`,
		fingerprint).Scan(&caps); err != nil {
		t.Fatalf("чтение способностей: %v", err)
	}
	return caps
}

func hasCap(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
