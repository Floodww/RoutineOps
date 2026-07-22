package storage_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

func TestCreateTask_ReturnsTask(t *testing.T) {
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, fmt.Sprintf("host-task-%s", uniq(t)), "macos")

	task, err := db.CreateTask(context.Background(), d.ID, "echo hello", "macos", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if task.ID == "" {
		t.Error("expected task ID")
	}
	if task.Status != "pending" {
		t.Errorf("status = %q, want pending", task.Status)
	}
	if task.DeviceID != d.ID {
		t.Errorf("device_id = %q, want %q", task.DeviceID, d.ID)
	}
}

func TestGetTask_Found(t *testing.T) {
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, fmt.Sprintf("host-gettask-%s", uniq(t)), "windows")
	created, _ := db.CreateTask(context.Background(), d.ID, "ipconfig", "windows", "normal")

	got, err := db.GetTask(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if got == nil {
		t.Fatal("got nil task")
	}
	if got.ID != created.ID {
		t.Errorf("id = %q, want %q", got.ID, created.ID)
	}
}

func TestGetTask_NotFound_ReturnsNil(t *testing.T) {
	db := newDB(t)
	got, err := db.GetTask(context.Background(), "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestGetPendingTasks_ReturnsPendingOnly(t *testing.T) {
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, fmt.Sprintf("host-pending-%s", uniq(t)), "macos")

	t1, _ := db.CreateTask(context.Background(), d.ID, "task1", "macos", "normal")
	t2, _ := db.CreateTask(context.Background(), d.ID, "task2", "macos", "normal")

	// ack t1 so it's no longer pending
	_ = db.AckTask(context.Background(), t1.ID, d.ID)

	tasks, err := db.GetPendingTasks(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("GetPendingTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("got %d pending tasks, want 1", len(tasks))
	}
	if tasks[0].ID != t2.ID {
		t.Errorf("pending task id = %q, want %q", tasks[0].ID, t2.ID)
	}
}

func TestAckTask_ChangesStatusToAcked(t *testing.T) {
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, fmt.Sprintf("host-ack-%s", uniq(t)), "macos")
	task, _ := db.CreateTask(context.Background(), d.ID, "ls", "macos", "normal")

	if err := db.AckTask(context.Background(), task.ID, d.ID); err != nil {
		t.Fatalf("AckTask: %v", err)
	}
	got, _ := db.GetTask(context.Background(), task.ID)
	if got.Status != "acked" {
		t.Errorf("status = %q, want acked", got.Status)
	}
}

func TestCompleteTask_Success(t *testing.T) {
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, fmt.Sprintf("host-complete-%s", uniq(t)), "windows")
	task, _ := db.CreateTask(context.Background(), d.ID, "dir", "windows", "normal")

	prev, tt, err := db.CompleteTask(context.Background(), task.ID, d.ID, "completed", "output text", "")
	if err != nil {
		t.Fatalf("CompleteTask: %v", err)
	}
	if prev != "pending" {
		t.Errorf("prevStatus = %q, want pending (задача не была ackнута)", prev)
	}
	if tt != "script" {
		t.Errorf("taskType = %q, want script (дефолт task_type)", tt)
	}
	got, _ := db.GetTask(context.Background(), task.ID)
	if got.Status != "completed" {
		t.Errorf("status = %q, want completed", got.Status)
	}
	if got.Output == nil || *got.Output != "output text" {
		t.Errorf("output = %v, want 'output text'", got.Output)
	}
}

// Гонка свипа и поздней доставки: задачу закрыл FailStaleAckedTasks по таймауту, а
// результат от живого агента приехал после. Результат ДОЛЖЕН быть принят (задача
// реально отработала, отвергнуть — значит навсегда оставить ложный 'failed'), но
// CompleteTask обязан сообщить, что перезаписывает именно свипнутый 'failed' —
// иначе исправление задним числом остаётся невидимым. По этому prevStatus
// gateway пишет аудит late_task_result.
func TestCompleteTask_LateResultAfterSweepReportsPrevStatus(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	d := mustCreateActiveDevice(t, db, fmt.Sprintf("host-late-%s", uniq(t)), "windows")
	task, _ := db.CreateTask(ctx, d.ID, "dir", "windows", "normal")

	if err := db.AckTask(ctx, task.ID, d.ID); err != nil {
		t.Fatalf("AckTask: %v", err)
	}
	// Отматываем acked_at за порог, чтобы свип его забрал (тест не ждёт 15 минут).
	if _, err := db.Pool().Exec(ctx,
		`UPDATE tasks SET acked_at = now() - interval '1 hour' WHERE id = $1`, task.ID); err != nil {
		t.Fatalf("сдвиг acked_at: %v", err)
	}
	if _, err := db.FailStaleAckedTasks(ctx, storage.StaleAckedTimeoutMinutes); err != nil {
		t.Fatalf("FailStaleAckedTasks: %v", err)
	}
	if got, _ := db.GetTask(ctx, task.ID); got.Status != "failed" {
		t.Fatalf("после свипа status = %q, want failed", got.Status)
	}

	prev, _, err := db.CompleteTask(ctx, task.ID, d.ID, "completed", "поздний вывод", "")
	if err != nil {
		t.Fatalf("поздний CompleteTask не должен отвергаться: %v", err)
	}
	if prev != "failed" {
		t.Errorf("prevStatus = %q, want failed — иначе gateway не узнает, что исправляет свипнутую задачу", prev)
	}
	got, _ := db.GetTask(ctx, task.ID)
	if got.Status != "completed" {
		t.Errorf("status = %q, want completed — поздний результат обязан быть принят", got.Status)
	}
	if got.Output == nil || *got.Output != "поздний вывод" {
		t.Errorf("output = %v, want 'поздний вывод'", got.Output)
	}
}

func TestListDeviceTasks_ReturnsMostRecent(t *testing.T) {
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, fmt.Sprintf("host-listtasks-%s", uniq(t)), "macos")
	db.CreateTask(context.Background(), d.ID, "cmd1", "macos", "normal")
	db.CreateTask(context.Background(), d.ID, "cmd2", "macos", "normal")

	tasks, err := db.ListDeviceTasks(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("ListDeviceTasks: %v", err)
	}
	if len(tasks) < 2 {
		t.Errorf("got %d tasks, want >=2", len(tasks))
	}
}

func TestCreateLockTask_ReturnsLockTask(t *testing.T) {
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, "host-lock-"+uniq(t), "windows")
	task, err := db.CreateLockTask(context.Background(), d.ID, "$2a$10$hash", "нарушение ИБ", false, "overlay")
	if err != nil {
		t.Fatalf("CreateLockTask: %v", err)
	}
	if task.ID == "" {
		t.Error("expected task ID")
	}
	if task.TaskType != "lock" {
		t.Errorf("TaskType = %q, want lock", task.TaskType)
	}
	if task.LockHash != "$2a$10$hash" {
		t.Errorf("LockHash = %q, want $2a$10$hash", task.LockHash)
	}
	if task.LockReason != "нарушение ИБ" {
		t.Errorf("LockReason = %q, want нарушение ИБ", task.LockReason)
	}
	if task.LockUnlock != false {
		t.Errorf("LockUnlock = %v, want false", task.LockUnlock)
	}
	if task.Status != "pending" {
		t.Errorf("Status = %q, want pending", task.Status)
	}
}

func TestCreateLockTask_Unlock(t *testing.T) {
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, "host-unlock-"+uniq(t), "windows")
	task, err := db.CreateLockTask(context.Background(), d.ID, "", "", true, "overlay")
	if err != nil {
		t.Fatalf("CreateLockTask: %v", err)
	}
	if task.LockUnlock != true {
		t.Errorf("LockUnlock = %v, want true", task.LockUnlock)
	}
}

// Регресс: platform lock-задачи должен браться из os устройства, а не быть
// захардкожен "windows" — иначе задачи на блок мака помечались как windows.
func TestCreateLockTask_PlatformFromDeviceOS(t *testing.T) {
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, "host-lock-mac-"+uniq(t), "darwin")
	task, err := db.CreateLockTask(context.Background(), d.ID, "$2a$10$hash", "тест", false, "overlay")
	if err != nil {
		t.Fatalf("CreateLockTask: %v", err)
	}
	if task.Platform != "darwin" {
		t.Errorf("Platform = %q, want darwin (os устройства)", task.Platform)
	}
}

// bcrypt-хеш для тестов desired-лока. Хранилище его не валидирует (это делает агент),
// важна только непустота — по ней UpdateDeviceLockStatus отличает живой desired-лок.
const testLockHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

func TestUpdateDeviceLockStatus_LockedThenUnlocked(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	d := mustCreateActiveDevice(t, db, "host-updatelock-"+uniq(t), "windows")

	// Подтверждение статуса приходит ПОСЛЕ того, как lock-эндпоинт выставил desired
	// вместе с хешем — воспроизводим боевой порядок. Без него UpdateDeviceLockStatus
	// справедливо откажет (ErrNoDesiredLock), см. тест ниже.
	if err := db.SetDeviceLockState(ctx, d.ID, "locked", testLockHash, "test", storage.LockModeOverlay, "lock-task-1"); err != nil {
		t.Fatalf("SetDeviceLockState(locked): %v", err)
	}
	if err := db.UpdateDeviceLockStatus(ctx, d.ID, "locked"); err != nil {
		t.Fatalf("UpdateDeviceLockStatus(locked): %v", err)
	}
	d1, _, err := db.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d1.LockStatus != "locked" {
		t.Errorf("LockStatus = %q, want locked", d1.LockStatus)
	}

	if err := db.UpdateDeviceLockStatus(ctx, d.ID, "unlocked"); err != nil {
		t.Fatalf("UpdateDeviceLockStatus(unlocked): %v", err)
	}
	d2, _, err := db.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d2.LockStatus != "unlocked" {
		t.Errorf("LockStatus = %q, want unlocked", d2.LockStatus)
	}
}

// Устаревший LOCKED из durable-outbox агента, доехавший ПОСЛЕ снятия, не должен
// воскрешать desired: unlock уже вычистил lock_hash, и 'locked' без хеша — команда,
// которую агент выполнить не может (fail-safe против офлайн-неснимаемого лока).
// Устройство тогда навсегда числилось бы заблокированным в панели, оставаясь рабочим,
// и обнаружить это можно было бы только в журнале службы на конкретной машине.
func TestUpdateDeviceLockStatus_StaleLockedAfterUnlock_Refused(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	d := mustCreateActiveDevice(t, db, "host-stalelock-"+uniq(t), "windows")

	// Полный боевой цикл: заперли (hash есть) → сняли (hash вычищен).
	if err := db.SetDeviceLockState(ctx, d.ID, "locked", testLockHash, "test", storage.LockModeOverlay, "lock-task-1"); err != nil {
		t.Fatalf("SetDeviceLockState(locked): %v", err)
	}
	if err := db.SetDeviceLockState(ctx, d.ID, "unlocked", "", "", storage.LockModeOverlay, ""); err != nil {
		t.Fatalf("SetDeviceLockState(unlocked): %v", err)
	}

	if err := db.UpdateDeviceLockStatus(ctx, d.ID, "locked"); !errors.Is(err, storage.ErrNoDesiredLock) {
		t.Fatalf("UpdateDeviceLockStatus(locked) без lock_hash = %v, want ErrNoDesiredLock", err)
	}
	got, _, err := db.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if got.LockStatus != "unlocked" {
		t.Errorf("LockStatus = %q, want unlocked — устаревший LOCKED воскресил desired", got.LockStatus)
	}

	// Гард односторонний: 'unlocked' проходит всегда, иначе агент не смог бы
	// отчитаться о локальном снятии.
	if err := db.UpdateDeviceLockStatus(ctx, d.ID, "unlocked"); err != nil {
		t.Fatalf("UpdateDeviceLockStatus(unlocked): %v", err)
	}
}

// Sweep застрявших в 'acked' задач. Порог проверяется самим параметром, без правки
// acked_at в обход API: 15 мин — свежая задача НЕ трогается, 0 — трогается.
// Главное здесь — лок-задача не должна попадать под sweep НИКОГДА: она штатно висит
// в 'acked' (агент отчитывается через ReportLockStatus), и без исключения по task_type
// каждый лок получал бы ложный failed.
func TestFailStaleAckedTasks(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	d := mustCreateActiveDevice(t, db, fmt.Sprintf("host-stale-%s", uniq(t)), "windows")

	script, err := db.CreateTask(ctx, d.ID, "whoami", "windows", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	lock, err := db.CreateLockTask(ctx, d.ID, "hash", "по требованию ИБ", false, storage.LockModeOverlay)
	if err != nil {
		t.Fatalf("CreateLockTask: %v", err)
	}
	pending, err := db.CreateTask(ctx, d.ID, "ipconfig", "windows", "normal")
	if err != nil {
		t.Fatalf("CreateTask(pending): %v", err)
	}
	for _, id := range []string{script.ID, lock.ID} {
		if err := db.AckTask(ctx, id, d.ID); err != nil {
			t.Fatalf("AckTask(%s): %v", id, err)
		}
	}

	statusOf := func(id string) string {
		t.Helper()
		got, err := db.GetTask(ctx, id)
		if err != nil {
			t.Fatalf("GetTask: %v", err)
		}
		return got.Status
	}

	// Порог не истёк — не трогаем ничего.
	if _, err := db.FailStaleAckedTasks(ctx, storage.StaleAckedTimeoutMinutes); err != nil {
		t.Fatalf("FailStaleAckedTasks(15m): %v", err)
	}
	if s := statusOf(script.ID); s != "acked" {
		t.Errorf("свежая задача в пределах порога = %q, want acked", s)
	}

	// Порог истёк.
	// Счётчик проверяем на «хотя бы одну», а не на точное число: БД в пакете общая,
	// и соседние тесты оставляют в 'acked' свои задачи. Точность даёт проверка
	// статусов по конкретным id ниже.
	n, err := db.FailStaleAckedTasks(ctx, 0)
	if err != nil {
		t.Fatalf("FailStaleAckedTasks(0): %v", err)
	}
	if n < 1 {
		t.Errorf("закрыто задач = %d, want >= 1", n)
	}
	if s := statusOf(script.ID); s != "failed" {
		t.Errorf("просвистевшая script-задача = %q, want failed", s)
	}
	if s := statusOf(lock.ID); s != "acked" {
		t.Errorf("лок-задача = %q, want acked — она НЕ должна попадать под sweep", s)
	}
	if s := statusOf(pending.ID); s != "pending" {
		t.Errorf("pending-задача = %q, want pending", s)
	}
}
