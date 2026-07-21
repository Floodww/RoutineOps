package worker_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/registry"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/testutil"
	"github.com/Floodww/RoutineOps/internal/server/worker"
	pb "github.com/Floodww/RoutineOps/proto"
	"github.com/alicebob/miniredis/v2"
	"github.com/hibiken/asynq"
)

var sharedDSN string

func TestMain(m *testing.M) {
	dsn, cleanup := testutil.NewDSNWithCleanup()
	sharedDSN = dsn
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Connect(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("storage.Connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func deliverTask(taskID string) *asynq.Task {
	payload, _ := json.Marshal(worker.DeliverTaskPayload{TaskID: taskID})
	return asynq.NewTask(worker.TypeDeliverTask, payload)
}

// setupDeviceWithCN создаёт активное устройство с заданным cert_cn и возвращает
// (deviceID, cn). cert_cn проставляется через heartbeat-upsert.
func setupDeviceWithCN(t *testing.T, db *storage.DB) (deviceID, cn string) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	fingerprint := "fp-" + suffix
	cn = "cn-" + suffix
	if err := db.UpsertDeviceHeartbeat(ctx, storage.HeartbeatData{
		CertFingerprint: fingerprint,
		DeviceID:        cn,
		CertCN:          cn,
		IPAddress:       "192.0.2.1",
	}); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}
	id, err := db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil || id == "" {
		t.Fatalf("GetDeviceIDByFingerprint: id=%q err=%v", id, err)
	}
	return id, cn
}

// Enqueue ставит задачу доставки в очередь Redis с корректным типом и payload.
func TestEnqueue_AddsTaskToQueue(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	client := worker.NewClient(mr.Addr())
	defer client.Close()

	if err := worker.Enqueue(client, "task-xyz"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	insp := asynq.NewInspector(asynq.RedisClientOpt{Addr: mr.Addr()})
	defer insp.Close()
	tasks, err := insp.ListPendingTasks("default")
	if err != nil {
		t.Fatalf("ListPendingTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("ожидалась 1 задача в очереди, получено %d", len(tasks))
	}
	if tasks[0].Type != worker.TypeDeliverTask {
		t.Errorf("type = %q, ожидался %q", tasks[0].Type, worker.TypeDeliverTask)
	}
	// Retry-политика: фиксируем, чтобы регрессия не превратила временный сбой
	// доставки в потерю задачи (без ретраев).
	if tasks[0].Queue != "default" {
		t.Errorf("queue = %q, ожидался default", tasks[0].Queue)
	}
	if tasks[0].MaxRetry != 10 {
		t.Errorf("MaxRetry = %d, ожидалось 10", tasks[0].MaxRetry)
	}
	var p worker.DeliverTaskPayload
	if err := json.Unmarshal(tasks[0].Payload, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.TaskID != "task-xyz" {
		t.Errorf("task_id = %q, ожидался task-xyz", p.TaskID)
	}
}

// NewServer конструирует asynq-сервер без подключения (dial — при Run).
func TestNewServer_Constructs(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	if srv := worker.NewServer(mr.Addr()); srv == nil {
		t.Fatal("NewServer вернул nil")
	}
}

// Happy-path: pending-задача для подключённого устройства доставляется в канал registry.
func TestProcessTask_DeliversToConnectedDevice(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	deviceID, cn := setupDeviceWithCN(t, db)

	task, err := db.CreateTask(ctx, deviceID, "echo hello", "macos", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	reg := registry.New()
	ch, cancel := reg.Register(cn)
	defer cancel()

	h := worker.NewHandler(db, reg, discardLogger())
	if err := h.ProcessTask(ctx, deliverTask(task.ID)); err != nil {
		t.Fatalf("ProcessTask вернул ошибку: %v", err)
	}

	select {
	case got := <-ch:
		if got.TaskId != task.ID {
			t.Errorf("доставлен TaskId %q, ожидался %q", got.TaskId, task.ID)
		}
		if got.ScriptContent != "echo hello" {
			t.Errorf("ScriptContent = %q", got.ScriptContent)
		}
	default:
		t.Fatal("задача не попала в канал устройства")
	}
}

// Битый JSON в payload → ошибка unmarshal.
func TestProcessTask_BadPayload_ReturnsError(t *testing.T) {
	db := newDB(t)
	h := worker.NewHandler(db, registry.New(), discardLogger())
	bad := asynq.NewTask(worker.TypeDeliverTask, []byte("{not json"))
	if err := h.ProcessTask(context.Background(), bad); err == nil {
		t.Error("ожидалась ошибка на битом payload, получили nil")
	}
}

// Несуществующая задача → ошибка "not found".
func TestProcessTask_TaskNotFound_ReturnsError(t *testing.T) {
	db := newDB(t)
	h := worker.NewHandler(db, registry.New(), discardLogger())
	// Валидный UUID, которого нет в БД.
	err := h.ProcessTask(context.Background(), deliverTask("00000000-0000-0000-0000-000000000000"))
	if err == nil {
		t.Error("ожидалась ошибка для несуществующей задачи, получили nil")
	}
}

// Задача не в статусе pending (уже acked) → no-op, без ошибки и без доставки.
func TestProcessTask_NonPending_IsNoOp(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	deviceID, cn := setupDeviceWithCN(t, db)

	task, err := db.CreateTask(ctx, deviceID, "echo hi", "macos", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := db.AckTask(ctx, task.ID, deviceID); err != nil {
		t.Fatalf("AckTask: %v", err)
	}

	reg := registry.New()
	ch, cancel := reg.Register(cn)
	defer cancel()

	h := worker.NewHandler(db, reg, discardLogger())
	if err := h.ProcessTask(ctx, deliverTask(task.ID)); err != nil {
		t.Fatalf("ProcessTask на acked-задаче вернул ошибку: %v", err)
	}
	select {
	case got := <-ch:
		t.Errorf("acked-задача не должна доставляться, но получили %q", got.TaskId)
	default:
	}
}

// Устройство не подключено (нет в registry) → ошибка с retry-семантикой.
func TestProcessTask_DeviceNotConnected_ReturnsError(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	deviceID, _ := setupDeviceWithCN(t, db)

	task, err := db.CreateTask(ctx, deviceID, "echo hi", "macos", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	// registry пустой — устройство не подключено.
	h := worker.NewHandler(db, registry.New(), discardLogger())
	if err := h.ProcessTask(ctx, deliverTask(task.ID)); err == nil {
		t.Error("ожидалась ошибка для неподключённого устройства, получили nil")
	}
}

// У устройства не проставлен cert_cn (pending-устройство) → ошибка получения CN.
func TestProcessTask_EmptyCN_ReturnsError(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	// CreatePendingDevice оставляет cert_cn = NULL → GetDeviceCN вернёт "".
	dev, err := db.CreatePendingDevice(ctx, "pending-host-"+fmt.Sprintf("%d", time.Now().UnixNano()), "macos")
	if err != nil {
		t.Fatalf("CreatePendingDevice: %v", err)
	}
	// Активируем (cert_cn остаётся NULL): CreateTask гейтит по status='active', а тест
	// проверяет именно ветку пустого cert_cn в ProcessTask, а не гейт создания задачи.
	if err := db.UpdateDeviceStatus(ctx, dev.ID, "active"); err != nil {
		t.Fatalf("UpdateDeviceStatus: %v", err)
	}
	task, err := db.CreateTask(ctx, dev.ID, "echo hi", "macos", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	h := worker.NewHandler(db, registry.New(), discardLogger())
	if err := h.ProcessTask(ctx, deliverTask(task.ID)); err == nil {
		t.Error("ожидалась ошибка при пустом cert_cn, получили nil")
	}
}

// Буфер канала переполнен → Send даёт false → ошибка "send failed, will retry".
func TestProcessTask_FullBuffer_ReturnsError(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	deviceID, cn := setupDeviceWithCN(t, db)

	task, err := db.CreateTask(ctx, deviceID, "echo hi", "macos", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	reg := registry.New()
	_, cancel := reg.Register(cn)
	defer cancel()
	// Забиваем весь буфер (16), никто не читает.
	for i := 0; i < 16; i++ {
		reg.Send(cn, &pb.Task{TaskId: "fill"})
	}

	h := worker.NewHandler(db, reg, discardLogger())
	if err := h.ProcessTask(ctx, deliverTask(task.ID)); err == nil {
		t.Error("ожидалась ошибка при переполненном буфере, получили nil")
	}
}
