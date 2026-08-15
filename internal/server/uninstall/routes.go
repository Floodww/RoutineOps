// Package uninstall — серверная половина удаления установленного ПО из карточки
// устройства: ручка ставит задачу удаления, агент её исполняет и сверяет цель.
//
// Селектор цели сервер собирает из своего инвентаря (storage.CreateUninstallTask), а не
// принимает из тела запроса: иначе сверка метода на агенте проверяла бы присланное против
// присланного. it_admin без requireHuman — удаление ПО не выдаёт и не повышает права, а
// массовая зачистка запрещённого софта — законный сценарий автоматизации (тот же уровень,
// что run-script и перезагрузка). Фича open-core на всех редакциях; агентская половина
// (internal/agent/uninstall) тоже не заперта тегом.
package uninstall

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Floodww/RoutineOps/internal/server/api"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/worker"
	"github.com/go-chi/chi/v5"
	"github.com/hibiken/asynq"
)

// Service — серверная половина удаления ПО.
type Service struct {
	db     *storage.DB
	asynq  *asynq.Client
	logger *slog.Logger
}

func NewService(db *storage.DB, asynqClient *asynq.Client, logger *slog.Logger) *Service {
	return &Service{db: db, asynq: asynqClient, logger: logger}
}

// Routes монтирует:
//
//	POST /devices/{id}/software/uninstall — поставить задачу удаления
//
// it_admin БЕЗ requireHuman (WithAdminRoutes), в отличие от вооружения лока: удаление
// ПО не выдаёт и не повышает права, а массовая зачистка запрещённого софта — законный
// сценарий для автоматизации. Тот же уровень, что у run-script и перезагрузки.
func Routes(svc *Service) api.RouterOption {
	return api.WithAdminRoutes(func(_ *api.Handler, r chi.Router) {
		r.Post("/devices/{id}/software/uninstall", svc.createHandler)
	})
}

// request — только ИДЕНТИФИКАЦИЯ цели, без метода и версии.
//
// 🔴 Селектор целиком собирает сервер из своего инвентаря (storage.CreateUninstallTask),
// а не принимает из тела. Иначе клиент прислал бы произвольный метод, и сверка метода
// на агенте — та самая, ради которой она заведена, — проверяла бы присланное против
// присланного.
type request struct {
	SoftwareName string `json:"software_name"`
	// UninstallID различает одноимённые записи разных вендоров и разные версии одного
	// продукта. На macOS пуст — там ключом служит install_location, и пустое значение
	// сверяется как есть.
	UninstallID string `json:"uninstall_id"`
	Reason      string `json:"reason"`
}

type response struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"`
}

func (s *Service) createHandler(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	var req request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.SoftwareName = strings.TrimSpace(req.SoftwareName)
	if req.SoftwareName == "" {
		http.Error(w, "software_name обязателен", http.StatusBadRequest)
		return
	}

	// 🔴 Скоуп открывается ЗДЕСЬ, чтобы задача и запись о ней легли ОДНОЙ транзакцией.
	//
	// Раньше каждый вызов открывал свою: строка задачи коммитилась до записи в журнал, и
	// при отказе журнала откатывать было уже нечего. Оператор получал 500 и считал, что
	// удаления не будет, — а задача оставалась в статусе pending, и gateway.Connect
	// раздаёт pending-задачи по ОДНОМУ статусу, без оглядки на журнал. То есть
	// деструктивная операция уезжала на машину при следующем подключении, и записи о ней
	// не существовало. Ровно то, что ветка отказа ниже обещала не допустить.
	//
	// Обе вложенные операции переиспользуют транзакцию из контекста (BindTenantForDevice и
	// beginScoped проверяют TxFrom), поэтому явных изменений в них не требуется.
	sctx, finish, err := s.db.BindTenantForDevice(r.Context(), deviceID)
	if err != nil {
		// Сюда же приходит несуществующее устройство: тенанта у него нет.
		s.logger.Error("uninstall: скоуп устройства", "device_id", deviceID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	committed := false
	defer func() {
		if !committed {
			finish(false)
		}
	}()

	task, err := s.db.CreateUninstallTask(sctx, deviceID, req.SoftwareName, strings.TrimSpace(req.UninstallID), strings.TrimSpace(req.Reason))
	switch {
	case errors.Is(err, storage.ErrSoftwareNotInInventory):
		// 409, а не 404: устройство существует, а вот снимок разъехался с тем, что
		// видит оператор. Действие для него — обновить инвентарь и повторить, и это
		// ровно то же, что означает TARGET_CHANGED со стороны агента.
		http.Error(w, "этого ПО нет в инвентаре устройства — обновите инвентарь и повторите", http.StatusConflict)
		return
	case errors.Is(err, storage.ErrSoftwareNotRemovable):
		// Метод определяет коллектор агента, и пустой он там, где снять нечем в
		// принципе: per-user установки под Windows (служба работает от LocalSystem и в
		// чужой профиль не ходит), защищённое SIP на macOS. Отбиваем здесь, а не ждём
		// NOT_REMOVABLE с устройства: оператору незачем ждать отчёта ради известного «нет».
		http.Error(w, "это ПО нечем снять с устройства", http.StatusConflict)
		return
	case errors.Is(err, storage.ErrDeviceNotActive):
		http.Error(w, "устройство не в статусе active", http.StatusConflict)
		return
	case errors.Is(err, storage.ErrAgentTooOld):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		s.logger.Error("create uninstall task", "device_id", deviceID, "software", req.SoftwareName, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	userID, email, _ := api.Actor(r.Context())
	// Аудит ДО постановки в очередь и fail-closed: удаление ПО — деструктивная операция
	// на живой машине, и она не должна уезжать, если запись о ней не сохранилась.
	// Записываем весь селектор: по одному имени потом не понять, какую из одноимённых
	// записей снесли.
	if err := s.db.WriteAuditLog(sctx, userID, email, "uninstall_software", "device", deviceID,
		map[string]any{
			"task_id":          task.ID,
			"software_name":    task.Uninstall.SoftwareName,
			"version":          task.Uninstall.Version,
			"uninstall_id":     task.Uninstall.UninstallID,
			"uninstall_method": task.Uninstall.Method,
			"scope":            task.Uninstall.Scope,
			"reason":           task.Uninstall.Reason,
		}); err != nil {
		s.logger.Error("audit uninstall_software", "device_id", deviceID, "task_id", task.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Коммит ДО постановки в очередь: воркер, забравший job раньше коммита, не увидел бы
	// задачу вовсе и списал бы её как несуществующую.
	finish(true)
	committed = true

	// Неудача постановки в очередь не терминальна: задача уже в БД со статусом pending,
	// и её доставит реконсайлер либо gateway.Connect при следующем подключении.
	if err := worker.Enqueue(s.asynq, task.ID); err != nil {
		s.logger.Error("enqueue uninstall task (доставит реконсайлер)", "task_id", task.ID, "err", err)
	}
	writeJSON(w, http.StatusAccepted, response{TaskID: task.ID, Status: task.Status})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
