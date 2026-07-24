package storage_test

import (
	"context"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Владелец в карточке: ручной (owner_id→users, e-mail) и авто из каталога
// (owner_directory_id→directory_persons, имя) едут в GetDevice; SetDeviceOwner ставит/
// снимает ТОЛЬКО ручного, не трогая авто. Проверяет корреляционные подзапросы GetDevice
// и что привязка к несуществующему юзеру падает (FK), а не тихо «успевает».
func TestDevice_OwnerDisplay(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	u := uniq(t)

	fp := "own-fp-" + u
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, "own-"+u, "own-"+u, "192.0.2.51")); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fp)
	owner := mustCreateUser(t, db, "owner-"+u+"@test.com")

	// Ручная привязка → карточка кажет e-mail владельца.
	found, err := db.SetDeviceOwner(ctx, devID, owner.ID)
	if err != nil || !found {
		t.Fatalf("set owner: found=%v err=%v", found, err)
	}
	d, _, err := db.GetDevice(ctx, devID)
	if err != nil || d == nil {
		t.Fatalf("get device: %v", err)
	}
	if d.OwnerUserID != owner.ID || d.OwnerUserEmail != owner.Email {
		t.Errorf("ручной владелец: id=%q email=%q; want %q %q", d.OwnerUserID, d.OwnerUserEmail, owner.ID, owner.Email)
	}

	// Снятие → пусто.
	if _, err := db.SetDeviceOwner(ctx, devID, ""); err != nil {
		t.Fatalf("clear owner: %v", err)
	}
	d, _, _ = db.GetDevice(ctx, devID)
	if d.OwnerUserID != "" || d.OwnerUserEmail != "" {
		t.Errorf("после снятия владелец не пуст: id=%q email=%q", d.OwnerUserID, d.OwnerUserEmail)
	}

	// Авто-владелец из каталога → карточка кажет display_name (ручной остаётся пуст).
	guid := "own-guid-" + u
	if err := db.UpsertDirectoryPerson(ctx, storage.DirectoryPerson{ObjectGUID: guid, SAMAccount: "sam" + u, DisplayName: "Пётр Петров"}); err != nil {
		t.Fatalf("upsert person: %v", err)
	}
	pid, err := db.FindDirectoryPersonForMatch(ctx, "", "sam"+u)
	if err != nil || pid == "" {
		t.Fatalf("find person: id=%q err=%v", pid, err)
	}
	if err := db.SetDeviceOwnerDirectory(ctx, devID, pid); err != nil {
		t.Fatalf("set dir owner: %v", err)
	}
	d, _, _ = db.GetDevice(ctx, devID)
	if d.OwnerDirectoryName != "Пётр Петров" {
		t.Errorf("авто-владелец: %q; want %q", d.OwnerDirectoryName, "Пётр Петров")
	}

	// Несуществующий пользователь → ошибка (FK), не тихий успех.
	if _, err := db.SetDeviceOwner(ctx, devID, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Error("привязка к несуществующему юзеру должна падать (FK)")
	}
}
