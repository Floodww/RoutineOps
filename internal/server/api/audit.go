package api

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/hibiken/asynq"
)

// audit пишет запись аудита best-effort: ошибка логируется, но не валит операцию.
func (h *Handler) audit(ctx context.Context, userID, userEmail, action, targetType, targetID string, details any) {
	// context.WithoutCancel: аудит — побочная запись, которая должна пережить отмену
	// запроса (клиент отключился / таймаут уже ПОСЛЕ успешной основной операции),
	// иначе запись о свершившемся действии молча теряется.
	bgCtx := context.WithoutCancel(ctx)
	if err := h.db.WriteAuditLog(bgCtx, userID, userEmail, action, targetType, targetID, details); err != nil {
		slog.Error("audit log write failed", "action", action, "target_type", targetType, "target_id", targetID, "err", err)
		return
	}

	// Выгрузка в SIEM (Q-47) — enterprise. В открытой сборке обработчика типа нет,
	// поэтому без флага задачу не ставим вовсе: иначе очередь копила бы задачи,
	// которые некому взять.
	if !h.siemExport {
		return
	}

	// Без тенанта задача бессмысленна: воркер ищет
	// интеграции ИМЕННО тенанта, и на пустом значении молча вышел бы успехом —
	// событие не доехало бы до приёмника ИБ, а узнали бы об этом при разборе
	// инцидента.
	tenantID, ok := storage.TenantIDFrom(ctx)
	if !ok || tenantID == "" {
		slog.Warn("siem export skipped: в контексте нет тенанта", "action", action)
		return
	}

	payload, _ := json.Marshal(map[string]any{
		"tenant_id":   tenantID,
		"action":      action,
		"user_email":  userEmail,
		"target_type": targetType,
		"target_id":   targetID,
		"details":     details,
	})

	if h.asynqClient != nil {
		if _, err := h.asynqClient.Enqueue(asynq.NewTask("siem:export", payload)); err != nil {
			slog.Error("siem export enqueue failed", "action", action, "err", err)
		}
	}
}
