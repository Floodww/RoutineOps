package storage_test

import (
	"errors"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Владелец устройства — карточка человека (миграция 038), а не аккаунт панели. Карточка
// может быть заведена руками (Free) или принесена синком каталога (Enterprise) — для
// устройства это один и тот же владелец, и ставится он одной ручкой.
func TestDevice_OwnerIsPerson(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	u := uniq(t)

	fp := "own-fp-" + u
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, "own-"+u, "own-"+u, "192.0.2.51")); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fp)

	// Ручная карточка: ФИО + почта, никакого аккаунта и приглашения.
	p, err := db.CreateManualPerson(ctx, tenancy.DefaultTenantID, "Иван Иванов", "ivanov-"+u+"@test.com")
	if err != nil {
		t.Fatalf("create person: %v", err)
	}
	if p.Source != storage.PersonSourceManual {
		t.Fatalf("source = %q, want manual", p.Source)
	}

	found, err := db.SetDeviceOwnerPerson(ctx, tenancy.DefaultTenantID, devID, p.ID)
	if err != nil || !found {
		t.Fatalf("set owner: found=%v err=%v", found, err)
	}
	d, _, err := db.GetDevice(ctx, tenancy.DefaultTenantID, devID)
	if err != nil || d == nil {
		t.Fatalf("get device: %v", err)
	}
	if d.OwnerPersonID != p.ID || d.OwnerPersonName != "Иван Иванов" || d.OwnerPersonEmail != p.Email {
		t.Errorf("владелец: id=%q name=%q email=%q; want %q %q %q",
			d.OwnerPersonID, d.OwnerPersonName, d.OwnerPersonEmail, p.ID, "Иван Иванов", p.Email)
	}

	// Снятие → пусто.
	if _, err := db.SetDeviceOwnerPerson(ctx, tenancy.DefaultTenantID, devID, ""); err != nil {
		t.Fatalf("clear owner: %v", err)
	}
	d, _, _ = db.GetDevice(ctx, tenancy.DefaultTenantID, devID)
	if d.OwnerPersonID != "" || d.OwnerPersonName != "" {
		t.Errorf("после снятия владелец не пуст: id=%q name=%q", d.OwnerPersonID, d.OwnerPersonName)
	}

	// Карточка из каталога — тот же слот владельца, разница только в source.
	guid := "own-guid-" + u
	if err := db.UpsertDirectoryPerson(ctx, tenancy.DefaultTenantID, storage.DirectoryPerson{
		ObjectGUID: guid, SAMAccount: "sam" + u, DisplayName: "Пётр Петров",
	}); err != nil {
		t.Fatalf("upsert person: %v", err)
	}
	pid, err := db.FindDirectoryPersonForMatch(ctx, tenancy.DefaultTenantID, "", "sam"+u)
	if err != nil || pid == "" {
		t.Fatalf("find person: id=%q err=%v", pid, err)
	}
	if err := db.SetDeviceOwnerDirectory(ctx, tenancy.DefaultTenantID, devID, pid); err != nil {
		t.Fatalf("set dir owner: %v", err)
	}
	d, _, _ = db.GetDevice(ctx, tenancy.DefaultTenantID, devID)
	if d.OwnerPersonName != "Пётр Петров" {
		t.Errorf("владелец из каталога: %q; want %q", d.OwnerPersonName, "Пётр Петров")
	}

	// Несуществующая карточка → ошибка (FK), не тихий успех.
	if _, err := db.SetDeviceOwnerPerson(ctx, tenancy.DefaultTenantID, devID, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Error("привязка к несуществующей карточке должна падать (FK)")
	}
}

// Правка и удаление — только для ручных карточек: у каталожных источник истины AD, и
// правка здесь пережила бы ровно до следующего синка.
func TestManualPerson_EditDeleteGuards(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	u := uniq(t)

	p, err := db.CreateManualPerson(ctx, tenancy.DefaultTenantID, "Ручной Человек", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.Email != "" {
		t.Errorf("пустая почта должна остаться пустой, got %q", p.Email)
	}

	ok, err := db.UpdateManualPerson(ctx, tenancy.DefaultTenantID, p.ID, "Ручной Человек 2", "manual-"+u+"@test.com")
	if err != nil || !ok {
		t.Fatalf("update: ok=%v err=%v", ok, err)
	}

	// Каталожную не трогаем.
	if err := db.UpsertDirectoryPerson(ctx, tenancy.DefaultTenantID, storage.DirectoryPerson{
		ObjectGUID: "ldap-guid-" + u, DisplayName: "Из Каталога",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var ldapID string
	persons, err := db.ListDirectoryPersons(ctx, tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, x := range persons {
		if x.ObjectGUID == "ldap-guid-"+u {
			ldapID = x.ID
		}
	}
	if ldapID == "" {
		t.Fatal("каталожная карточка не найдена")
	}
	if _, err := db.UpdateManualPerson(ctx, tenancy.DefaultTenantID, ldapID, "Подмена", ""); !errors.Is(err, storage.ErrPersonNotManual) {
		t.Errorf("правка каталожной: err=%v, want ErrPersonNotManual", err)
	}
	if _, err := db.DeleteManualPerson(ctx, tenancy.DefaultTenantID, ldapID); !errors.Is(err, storage.ErrPersonNotManual) {
		t.Errorf("удаление каталожной: err=%v, want ErrPersonNotManual", err)
	}

	// Ручную удаляем; несуществующая — не ошибка, а false.
	if ok, err := db.DeleteManualPerson(ctx, tenancy.DefaultTenantID, p.ID); err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	if ok, err := db.DeleteManualPerson(ctx, tenancy.DefaultTenantID, "00000000-0000-0000-0000-000000000000"); err != nil || ok {
		t.Errorf("удаление несуществующей: ok=%v err=%v; want false,nil", ok, err)
	}
}

// 🔴 Синк каталога гасит флагом disabled всё, чего не увидел в последней выдаче. Ручные
// карточки каталог не отдаёт НИКОГДА, поэтому без явного исключения первый же синк в
// Enterprise погасил бы всех владельцев, заведённых во Free.
func TestManualPerson_SurvivesDirectorySync(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	u := uniq(t)

	manual, err := db.CreateManualPerson(ctx, tenancy.DefaultTenantID, "Пережил Синк", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.UpsertDirectoryPerson(ctx, tenancy.DefaultTenantID, storage.DirectoryPerson{
		ObjectGUID: "stale-guid-" + u, DisplayName: "Исчезнет Из AD",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Синк «в будущем»: всё, что не тронуто им, считается устаревшим.
	if _, err := db.MarkDirectoryPersonsStale(ctx, tenancy.DefaultTenantID, 1<<40); err != nil {
		t.Fatalf("mark stale: %v", err)
	}

	persons, err := db.ListDirectoryPersons(ctx, tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, p := range persons {
		if p.ID == manual.ID && p.Disabled {
			t.Error("🔴 синк каталога погасил РУЧНУЮ карточку — владельцы Free исчезли бы")
		}
		if p.ObjectGUID == "stale-guid-"+u && !p.Disabled {
			t.Error("каталожная карточка, пропавшая из выдачи, должна гаситься")
		}
	}
}
