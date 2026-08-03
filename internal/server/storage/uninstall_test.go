package storage_test

import (
	"context"
	"errors"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// seedSoftware кладёт устройству снимок инвентаря с одной записью ПО.
func seedSoftware(t *testing.T, db *storage.DB, fp string, item storage.SoftwareItem) {
	t.Helper()
	err := db.UpsertInventory(context.Background(), storage.InventoryData{
		CertFingerprint: fp,
		Hostname:        "host-" + uniq(t),
		OS:              "windows",
		Software:        []storage.SoftwareItem{item},
	})
	if err != nil {
		t.Fatalf("UpsertInventory: %v", err)
	}
}

func activeDeviceWithSoftware(t *testing.T, db *storage.DB, item storage.SoftwareItem) (deviceID string) {
	t.Helper()
	fp := "fp-uninst-" + uniq(t)
	id := enrollDevice(t, db, "host-uninst-"+uniq(t), fp)
	if err := db.UpdateDeviceStatus(context.Background(), tenancy.DefaultTenantID, id, "active"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	seedSoftware(t, db, fp, item)
	return id
}

// 🔴 Селектор собирает СЕРВЕР из своего инвентаря, а не клиент из тела запроса. Иначе
// оператор (или сервисный токен) прислал бы произвольный метод, и сверка метода на
// агенте — та, ради которой она заведена, — проверяла бы присланное против присланного.
func TestCreateUninstallTask_SelectorComesFromInventory(t *testing.T) {
	db := newDB(t)
	item := storage.SoftwareItem{
		Name: "Некий Продукт", Version: "3.1.4", Vendor: "ООО Вендор",
		InstallLocation: `C:\Program Files\Некий`, Arch: "amd64",
		UninstallID: "{GUID-1}", UninstallMethod: "msi", Scope: "machine",
	}
	deviceID := activeDeviceWithSoftware(t, db, item)

	// Вызывающий передаёт ТОЛЬКО имя и машинный ключ.
	task, err := db.CreateUninstallTask(context.Background(), deviceID, item.Name, item.UninstallID, "нарушает политику")
	if err != nil {
		t.Fatalf("CreateUninstallTask: %v", err)
	}
	if task.TaskType != "uninstall" || task.Status != "pending" {
		t.Errorf("тип/статус задачи: %q/%q", task.TaskType, task.Status)
	}
	// Всё остальное обязано приехать из снимка.
	if task.Uninstall.Version != item.Version {
		t.Errorf("version = %q, ожидалась из инвентаря %q", task.Uninstall.Version, item.Version)
	}
	if task.Uninstall.Method != item.UninstallMethod {
		t.Errorf("метод = %q, ожидался из инвентаря %q", task.Uninstall.Method, item.UninstallMethod)
	}
	if task.Uninstall.InstallLocation != item.InstallLocation {
		t.Errorf("install_location = %q", task.Uninstall.InstallLocation)
	}
	if task.Uninstall.Scope != item.Scope {
		t.Errorf("scope = %q", task.Uninstall.Scope)
	}
	if task.Uninstall.Reason != "нарушает политику" {
		t.Errorf("причина не сохранилась: %q", task.Uninstall.Reason)
	}

	// Повтор при живой недоставленной заявке обязан вернуть ТУ ЖЕ задачу: новый task_id
	// для того же намерения агент считает новой командой.
	again, err := db.CreateUninstallTask(context.Background(), deviceID, item.Name, item.UninstallID, "повтор")
	if err != nil {
		t.Fatalf("повторный вызов: %v", err)
	}
	if again.ID != task.ID {
		t.Errorf("повтор создал вторую задачу: %s ≠ %s", again.ID, task.ID)
	}
}

// Цели нет в снимке — отказ, а не «поставим задачу, агент разберётся»: селектор
// собирается ИЗ снимка, и без него уехала бы команда с пустыми полями, под которую на
// машине подойдёт что угодно с похожим именем.
func TestCreateUninstallTask_NotInInventory(t *testing.T) {
	db := newDB(t)
	deviceID := activeDeviceWithSoftware(t, db, storage.SoftwareItem{
		Name: "Другое", UninstallID: "{GUID-X}", UninstallMethod: "msi", Scope: "machine",
	})
	_, err := db.CreateUninstallTask(context.Background(), deviceID, "Такого Нет", "{GUID-НЕТ}", "")
	if !errors.Is(err, storage.ErrSoftwareNotInInventory) {
		t.Errorf("получено %v, ожидалась ErrSoftwareNotInInventory", err)
	}
}

// 🔴 Метод определяет коллектор агента, и пустой он там, где снять нечем в принципе:
// per-user установки под Windows (служба работает от LocalSystem и в чужой профиль не
// ходит). Отбиваем на сервере, а не ждём NOT_REMOVABLE с устройства — оператору незачем
// ждать отчёта ради известного заранее «нет».
func TestCreateUninstallTask_NoMethodRefused(t *testing.T) {
	db := newDB(t)
	deviceID := activeDeviceWithSoftware(t, db, storage.SoftwareItem{
		Name: "Пользовательский Мессенджер", UninstallID: "user-app",
		UninstallMethod: "", Scope: "user",
	})
	_, err := db.CreateUninstallTask(context.Background(), deviceID, "Пользовательский Мессенджер", "user-app", "")
	if !errors.Is(err, storage.ErrSoftwareNotRemovable) {
		t.Errorf("получено %v, ожидалась ErrSoftwareNotRemovable", err)
	}
}

// Инвентарь заблокированной машины никуда не делся — без гейта по статусу деструктив
// уехал бы на устройство, которое мы намеренно отрезали. Тот же гейт, что у скриптов.
func TestCreateUninstallTask_BlockedDeviceRefused(t *testing.T) {
	db := newDB(t)
	item := storage.SoftwareItem{Name: "Продукт", UninstallID: "{G}", UninstallMethod: "msi", Scope: "machine"}
	deviceID := activeDeviceWithSoftware(t, db, item)
	if err := db.UpdateDeviceStatus(context.Background(), tenancy.DefaultTenantID, deviceID, "blocked"); err != nil {
		t.Fatalf("blocked: %v", err)
	}
	_, err := db.CreateUninstallTask(context.Background(), deviceID, item.Name, item.UninstallID, "")
	if !errors.Is(err, storage.ErrDeviceNotActive) {
		t.Errorf("получено %v, ожидалась ErrDeviceNotActive", err)
	}
}

// Исход скоупится по устройству: иначе устройство A по чужому task_id проставило бы
// исход задаче устройства B.
func TestSetTaskUninstallOutcome_ScopedToDevice(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	item := storage.SoftwareItem{Name: "Продукт", UninstallID: "{G2}", UninstallMethod: "msi", Scope: "machine"}
	deviceID := activeDeviceWithSoftware(t, db, item)
	task, err := db.CreateUninstallTask(ctx, deviceID, item.Name, item.UninstallID, "")
	if err != nil {
		t.Fatalf("CreateUninstallTask: %v", err)
	}

	other := activeDeviceWithSoftware(t, db, storage.SoftwareItem{
		Name: "Чужой", UninstallID: "{G3}", UninstallMethod: "msi", Scope: "machine"})
	if err := db.SetTaskUninstallOutcome(ctx, task.ID, other, "removed"); err != nil {
		t.Fatalf("SetTaskUninstallOutcome (чужое устройство): %v", err)
	}
	got, err := db.GetTask(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if got.UninstallOutcome != "" {
		t.Errorf("чужое устройство проставило исход %q", got.UninstallOutcome)
	}

	if err := db.SetTaskUninstallOutcome(ctx, task.ID, deviceID, "still_present"); err != nil {
		t.Fatalf("SetTaskUninstallOutcome: %v", err)
	}
	got, err = db.GetTask(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	// still_present, а не failed: деинсталлятор сказал «ок», а ПО осталось в повторном
	// снимке. Различие безопасности, а не формулировки, — потому и отдельным полем.
	if got.UninstallOutcome != "still_present" {
		t.Errorf("исход = %q, ожидался still_present", got.UninstallOutcome)
	}
}
