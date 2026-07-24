package storage_test

import (
	"context"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Матч консольного юзера с каталогом: SID точный (rename-proof), логин — fallback,
// disabled не матчится; перематч задним числом через ListDevicesForDirectoryMatch.
func TestDirectory_MatchUpsertOwner(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	u := uniq(t)
	guid := "guid-" + u
	sid := "S-1-5-21-" + u
	oldSam := "ivanov" + u
	newSam := "ipetrov" + u

	p := storage.DirectoryPerson{ObjectGUID: guid, ObjectSID: sid, SAMAccount: oldSam, DisplayName: "Иван Иванов", Email: "i@corp"}
	if err := db.UpsertDirectoryPerson(ctx, p); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Идемпотентность + переименование: тот же object_guid, новый логин — не дубль, не падение.
	p.SAMAccount = newSam
	if err := db.UpsertDirectoryPerson(ctx, p); err != nil {
		t.Fatalf("upsert (rename): %v", err)
	}

	pid, err := db.FindDirectoryPersonForMatch(ctx, sid, "")
	if err != nil || pid == "" {
		t.Fatalf("match by SID: id=%q err=%v", pid, err)
	}
	// SID пуст → fallback по НОВОМУ логину.
	if id, _ := db.FindDirectoryPersonForMatch(ctx, "", newSam); id != pid {
		t.Errorf("match by renamed login: got %q want %q", id, pid)
	}
	// Старый логин уже не матчится (upsert по guid перезаписал sam) — это и есть rename-proof.
	if id, _ := db.FindDirectoryPersonForMatch(ctx, "", oldSam); id != "" {
		t.Errorf("stale login matched: %q", id)
	}
	// Нет совпадений.
	if id, _ := db.FindDirectoryPersonForMatch(ctx, "S-1-none-"+u, "nobody"+u); id != "" {
		t.Errorf("no match should be empty: %q", id)
	}

	// Disabled-персона не матчится ни по SID, ни по логину.
	p.Disabled = true
	if err := db.UpsertDirectoryPerson(ctx, p); err != nil {
		t.Fatalf("upsert disabled: %v", err)
	}
	if id, _ := db.FindDirectoryPersonForMatch(ctx, sid, newSam); id != "" {
		t.Errorf("disabled person matched: %q", id)
	}
	p.Disabled = false
	if err := db.UpsertDirectoryPerson(ctx, p); err != nil {
		t.Fatalf("re-enable: %v", err)
	}

	// Устройство с доложенным юзером, но без авто-владельца → в списке на перематч.
	fp := "fp-" + u
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, "dev-"+u, "dev-"+u, "192.0.2.50")); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fp)
	inv := storageInventoryData(fp, "host-"+u, "windows", "11", nil)
	inv.ConsoleUser = "CORP\\" + newSam
	inv.ConsoleUserSid = sid
	if err := db.UpsertInventory(ctx, inv); err != nil {
		t.Fatalf("inventory: %v", err)
	}

	inList := func() bool {
		list, err := db.ListDevicesForDirectoryMatch(ctx)
		if err != nil {
			t.Fatalf("list for match: %v", err)
		}
		for _, d := range list {
			if d.DeviceID == devID {
				if d.ConsoleUserSid != sid {
					t.Errorf("console_user_sid не доехал: %q", d.ConsoleUserSid)
				}
				return true
			}
		}
		return false
	}
	if !inList() {
		t.Fatal("устройство с console_user без владельца не попало в список на матч")
	}

	// Проставили авто-владельца → устройство ушло из списка на перематч.
	if err := db.SetDeviceOwnerDirectory(ctx, devID, pid); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	if inList() {
		t.Error("устройство всё ещё в списке после проставления владельца")
	}
}
