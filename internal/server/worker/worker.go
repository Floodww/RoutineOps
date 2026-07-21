package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/registry"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	pb "github.com/Floodww/RoutineOps/proto"
	"github.com/hibiken/asynq"
)

const TypeDeliverTask = "task:deliver"

// offlineDeliveryRetries — сколько раз ретраить доставку, пока устройство не в
// registry. Покрывает гонку «агент как раз переподключается» (3с+6с+9с), дальше
// доставку возьмёт на себя gateway.Connect. См. ProcessTask.
const offlineDeliveryRetries = 3

// LockModeToProto маппит строковый lock_mode из БД в proto-enum. Fail-safe:
// пусто/неизвестно => OVERLAY, деструктивный FILEVAULT требует ЯВНОГО значения.
func LockModeToProto(m string) pb.LockMode {
	if m == storage.LockModeFileVault {
		return pb.LockMode_LOCK_MODE_FILEVAULT
	}
	return pb.LockMode_LOCK_MODE_OVERLAY
}

type DeliverTaskPayload struct {
	TaskID string `json:"task_id"`
}

func NewClient(redisAddr string) *asynq.Client {
	return asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr})
}

func Enqueue(client *asynq.Client, taskID string) error {
	if client == nil {
		return nil
	}
	payload, err := json.Marshal(DeliverTaskPayload{TaskID: taskID})
	if err != nil {
		return err
	}
	_, err = client.Enqueue(asynq.NewTask(TypeDeliverTask, payload),
		asynq.MaxRetry(10),
		asynq.Queue("default"),
		asynq.TaskID(taskID), // дедуп: повторный enqueue того же таска — no-op
	)
	if errors.Is(err, asynq.ErrTaskIDConflict) {
		return nil
	}
	return err
}

type Handler struct {
	db       *storage.DB
	registry *registry.Registry
	logger   *slog.Logger
}

func NewHandler(db *storage.DB, reg *registry.Registry, logger *slog.Logger) *Handler {
	return &Handler{db: db, registry: reg, logger: logger}
}

func (h *Handler) ProcessTask(ctx context.Context, t *asynq.Task) error {
	var p DeliverTaskPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	task, err := h.db.GetTask(ctx, p.TaskID)
	if err != nil {
		return fmt.Errorf("get task: %w", err)
	}
	if task == nil {
		return fmt.Errorf("task %s not found", p.TaskID)
	}
	if task.Status != "pending" {
		return nil
	}

	cn, err := h.db.GetDeviceCN(ctx, task.DeviceID)
	if err != nil || cn == "" {
		return fmt.Errorf("get device cn for %s: %w", task.DeviceID, err)
	}

	if !h.registry.Connected(cn) {
		// Несколько коротких ретраев закрывают гонку «устройство подключается прямо
		// сейчас». Дальше — сдаёмся УСПЕШНО, а не ошибкой: исчерпав MaxRetry, asynq
		// архивирует delivery-job ВМЕСТЕ с его TaskID, и повторный Enqueue при
		// реконнекте молча схлопывается в ErrTaskIDConflict — задача навсегда висла
		// в pending (закрытый на ночь ноут). Успешное завершение job'а освобождает
		// TaskID; строка задачи остаётся pending, и доставку заново инициирует
		// gateway.Connect при следующем подключении устройства.
		if retried, _ := asynq.GetRetryCount(ctx); retried >= offlineDeliveryRetries {
			// Пока мы решали сдаться, устройство могло подключиться — а его sweep
			// (gateway.Connect) в этот момент получил бы ErrTaskIDConflict на наш
			// ещё живой job и молча его проглотил. Перепроверяем перед возвратом;
			// остаточное окно закрывает реконсайлер pending-задач (cmd/server/main.go).
			if h.registry.Connected(cn) {
				return fmt.Errorf("device %s reconnected while giving up, retry delivery", cn)
			}
			h.logger.Info("device offline, delivery deferred until reconnect",
				"task_id", task.ID, "device_cn", cn)
			return nil
		}
		return fmt.Errorf("device %s not connected, will retry", cn)
	}

	pbTask := &pb.Task{
		TaskId:        task.ID,
		ScriptContent: task.ScriptContent,
		Platform:      task.Platform,
	}
	if task.TaskType == "lock" {
		pbTask.Lock = &pb.LockCommand{
			RequestId:    task.ID,
			Unlock:       task.LockUnlock,
			PasswordHash: task.LockHash,
			Reason:       task.LockReason,
			LockMode:     LockModeToProto(task.LockMode),
			// FilevaultTargetUsers пусто — advisory: агент сам
			// enumerate-ит держателей Secure Token по гейту G2, исключая escrow-админа.
		}
	}
	if task.TaskType == "decommission" {
		// request_id = task.ID: агент подтверждает ОБЫЧНЫМ ReportTaskResult(task_id,
		// SUCCESS) до сноса серта — по task_id gateway флипает устройство в
		// decommissioned. reason — advisory (агент логирует); детальная причина
		// оператора живёт в аудите (decommission_device), не в задаче.
		pbTask.Decommission = &pb.DecommissionCommand{
			RequestId: task.ID,
			Reason:    "устройство выведено из эксплуатации администратором",
		}
	}
	sent := h.registry.Send(cn, pbTask)
	if !sent {
		return fmt.Errorf("send to device %s failed, will retry", cn)
	}

	h.logger.Info("task delivered via queue", "task_id", task.ID, "device_cn", cn)
	return nil
}

func NewServer(redisAddr string) *asynq.Server {
	return asynq.NewServer(
		asynq.RedisClientOpt{Addr: redisAddr},
		asynq.Config{
			Concurrency:    10,
			RetryDelayFunc: deliverRetryDelay,
		},
	)
}

// deliverRetryDelay ограничивает задержку ретрая доставки задач. Дефолтный
// экспоненциальный backoff asynq дорастает до часов (БАГ 5) — для lock/unlock это
// неприемлемо. Доставка ретраится в основном из-за «устройство не подключено»,
// что разрешается быстро (реконнект + ре-энкью pending в gateway.Connect), поэтому
// держим короткий линейный backoff с потолком 30с. Прочие типы — дефолт asynq.
func deliverRetryDelay(n int, e error, t *asynq.Task) time.Duration {
	if t != nil && t.Type() == TypeDeliverTask {
		d := time.Duration(n) * 3 * time.Second // 3с, 6с, 9с…
		if d > 30*time.Second {
			d = 30 * time.Second
		}
		return d
	}
	return asynq.DefaultRetryDelayFunc(n, e, t)
}
