package gateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/alerting"
	"github.com/Floodww/RoutineOps/internal/server/notifier"
	"github.com/Floodww/RoutineOps/internal/server/registry"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	pb "github.com/Floodww/RoutineOps/proto"
	"github.com/hibiken/asynq"

	"github.com/Floodww/RoutineOps/internal/server/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

type Notifier interface {
	// NotifyITAdmins — рассылка без критичности: заявки на права администратора и
	// служебные сообщения, которые нельзя «отфильтровать по важности».
	NotifyITAdmins(ctx context.Context, text string)
	// NotifyAlert — рассылка алерта с уважением порога доставки каждого получателя
	// (users.notify_min_severity, миграция 041).
	NotifyAlert(ctx context.Context, severity alerting.Severity, text string)
}

type Gateway struct {
	pb.UnimplementedAgentServiceServer
	db          *storage.DB
	registry    *registry.Registry
	asynqClient *asynq.Client
	logger      *slog.Logger
	bot         Notifier
	// escrowSvc — enterprise-шов FileVault recovery-escrow (internal/server/escrow).
	// nil в open-core → EscrowRecoveryKey отвечает Unimplemented. См. escrow_seam.go.
	escrowSvc EscrowService
	// inventoryHook — enterprise-обработка свежего инвентаря (пересчёт CVE).
	// nil в open-core: см. inventory_seam.go.
	inventoryHook InventoryHook
	// screenSvc — enterprise-шов удалённого рабочего стола (ADR-8).
	screenSvc ScreenService
	// lockVault — enterprise-шов вооружения FileVault-лока (ADR-F24).
	// nil в open-core → FetchLockSecrets отвечает Unimplemented. См. lockvault_seam.go.
	lockVault LockSecretVault
	// publicWebURL — база для ссылки на бинарь в манифесте обновления (Q-52).
	// Ставится SetPublicWebURL из composition-root. См. update_manifest.go.
	publicWebURL string
}

func New(db *storage.DB, reg *registry.Registry, asynqClient *asynq.Client, logger *slog.Logger, bot Notifier) *Gateway {
	return &Gateway{db: db, registry: reg, asynqClient: asynqClient, logger: logger, bot: bot}
}

func (g *Gateway) Connect(stream pb.AgentService_ConnectServer) error {
	deviceID, fingerprint, err := extractCertInfo(stream.Context())
	if err != nil {
		// Ранний выход без лога = «тишина gateway» при проблеме (БАГ 3). Сюда
		// попадаем, только если хендлер ВЫЗВАН (mTLS прошёл), но серт без CN/peer —
		// логируем причину, иначе отказ не виден ни в одном логе.
		g.logger.Warn("connect rejected: cert info", "err", err)
		return status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}

	devStatus, err := g.db.GetDeviceStatusByFingerprint(stream.Context(), fingerprint)
	if err != nil {
		g.logger.Error("connect rejected: status check", "device_id", deviceID, "err", err)
		return status.Errorf(codes.Internal, "status check: %v", err)
	}
	if isCutOff(devStatus) {
		g.logger.Warn("connect rejected", "device_id", deviceID, "status", devStatus)
		return status.Errorf(codes.PermissionDenied, "device is %s", devStatus)
	}
	if devStatus == "" {
		// Fingerprint неизвестен серверу. Два случая, неразличимых по самому серту:
		//   (a) легитимная первичная регистрация — устройство заводится из cert CN на
		//       первом Connect (ADR-1), строку создаёт heartbeat-upsert ниже;
		//   (b) агент УДАЛЁННОГО устройства пытается воскреснуть по всё ещё валидному
		//       серту — раньше это тоже проходило в (a) и заводило устройство-призрак.
		// Различаем тумбстоуном: отозванный при удалении отпечаток режем, новый — пускаем.
		// Реэнролл берёт новый серт → не отозван → регистрируется штатно (миграция 034).
		revoked, rerr := g.db.IsFingerprintRevoked(stream.Context(), fingerprint)
		if rerr != nil {
			g.logger.Error("connect: revoked-check", "device_id", deviceID, "err", rerr)
			return status.Errorf(codes.Internal, "revoked check: %v", rerr)
		}
		if revoked {
			g.logger.Warn("connect rejected: revoked cert (device deleted)", "device_id", deviceID)
			return status.Errorf(codes.NotFound, "device deleted: re-enroll required")
		}
		g.logger.Warn("device connected with unknown cert fingerprint", "device_id", deviceID)
	}

	taskCh, unregister := g.registry.Register(deviceID)
	defer unregister()

	// Жизненный цикл стрима. Если умирает send-горутина (разрыв на stream.Send),
	// надо завершить и recv-петлю — иначе устройство числится connected, а таски
	// ему уже не уходят (БАГ 8). Обе горутины сообщают причину в done; Connect
	// возвращает её, фреймворк закрывает стрим и разблокирует зависший Recv.
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	// Тенант кладём ЗНАЧЕНИЕМ, а не транзакцией: стрим живёт часами, и BindTenant
	// удерживал бы соединение из пула всё это время (см. scopeByFingerprint). Значения
	// достаточно — storage открывает короткий скоуп на каждый запрос сам. Без него
	// heartbeat, разбор pending-тасок и алерты уходили бы мимо тенанта: под FORCE RLS
	// это ноль строк без ошибки, то есть «устройство на связи, но ничего не происходит».
	tenantID, terr := g.tenantForFingerprint(ctx, fingerprint)
	if terr != nil {
		g.logger.Error("connect: lookup tenant", "device_id", deviceID, "err", terr)
		return status.Errorf(codes.Internal, "lookup tenant: %v", terr)
	}
	ctx = storage.WithTenantID(ctx, tenantID)
	done := make(chan error, 2)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case task, ok := <-taskCh:
				if !ok {
					return
				}
				if err := stream.Send(task); err != nil {
					g.logger.Warn("task send failed", "device_id", deviceID, "err", err)
					done <- status.Errorf(codes.Unavailable, "task send failed: %v", err)
					return
				}
				g.logger.Info("task sent", "device_id", deviceID, "task_id", task.TaskId)
			}
		}
	}()

	g.logger.Info("device connected", "device_id", deviceID)
	defer g.logger.Info("device disconnected", "device_id", deviceID)

	go func() {
		dbID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
		if err != nil {
			// Тишина здесь = pending-таски не передоставятся на reconnect без следа
			// (БАГ 9). Ошибку отмены при тендауне стрима не шумим.
			if ctx.Err() == nil {
				g.logger.Error("re-enqueue: lookup device by fingerprint", "device_id", deviceID, "err", err)
			}
			return
		}
		if dbID == "" {
			return
		}
		tasks, err := g.db.GetPendingTasks(ctx, dbID)
		if err != nil {
			g.logger.Error("get pending tasks", "device_id", deviceID, "err", err)
			return
		}
		for _, t := range tasks {
			if err := worker.Enqueue(g.asynqClient, t.ID); err != nil {
				g.logger.Error("enqueue pending task", "task_id", t.ID, "err", err)
			}
		}
	}()

	go func() {
		// Признак деградации приезжает в КАЖДОМ кадре (раз в 30 с), а алерт нужен на
		// переход. Помним предыдущее значение по стриму, а не спрашиваем БД: состояние
		// и так живёт ровно столько, сколько соединение. Реконнекты и рестарт сервера
		// подстрахованы дедупом внутри CreateAlert — непринятый такой же алерт повторно
		// не создастся. Принятый создастся снова, и это правильно: причина ещё жива.
		outboxWasDown := false
		for {
			req, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					done <- nil
				} else {
					done <- err
				}
				return
			}

			if err := g.db.UpsertDeviceHeartbeat(ctx, storage.HeartbeatData{
				CertFingerprint: fingerprint,
				DeviceID:        deviceID,
				CertCN:          deviceID,
				IPAddress:       req.IpAddress,
				PublicIP:        clientIP(ctx),

				OutboxUnavailable: req.GetOutboxUnavailable(),
				DegradedDetail:    req.GetDegradedDetail(),
			}); err != nil {
				g.logger.Error("upsert heartbeat", "device_id", deviceID, "err", err)
			}
			if down := req.GetOutboxUnavailable(); down != outboxWasDown {
				outboxWasDown = down
				g.reportOutboxHealth(ctx, fingerprint, deviceID, down, req.GetDegradedDetail())
			}
			// locked ≠ blocked: заблокированное устройство удерживает Connect-стрим
			// чтобы получить unlock-команду; рвём только по 'blocked'.
			s, err := g.db.GetDeviceStatusByFingerprint(ctx, fingerprint)
			if err != nil {
				// Не рвём стрим на временной ошибке БД (иначе дисконнект-шторм на
				// блипе), но логируем — раньше ошибка молча терялась (БАГ 7).
				g.logger.Error("heartbeat: status check", "device_id", deviceID, "err", err)
			} else if isCutOff(s) {
				done <- status.Errorf(codes.PermissionDenied, "device is %s", s)
				return
			}
		}
	}()

	err = <-done
	cancel()
	return err
}

// reportOutboxHealth — реакция на ПЕРЕХОД признака outbox_unavailable в heartbeat.
//
// Мёртвая durable-очередь означает, что с этой машины больше не придут ни отчёты о
// задачах, ни статусы лока, ни security-события: канал у них общий. То есть отсутствие
// алертов с устройства перестаёт быть свидетельством того, что там всё спокойно, — и
// узнать об этом можно ровно одним способом, из heartbeat, который идёт отдельным
// стримом и от очереди не зависит.
//
// Строка в alerts, а не только лог: состояние требует вмешательства руками (на Windows
// 2.5.1 это чинилось сбросом DACL каталога состояния), а значит обязано висеть в панели
// и требовать подтверждения. Ошибки здесь НЕ рвут heartbeat: устройство живо, и потерять
// его последний работающий канал из-за сбоя записи алерта — ровно та слепота, против
// которой всё это и сделано.
func (g *Gateway) reportOutboxHealth(ctx context.Context, fingerprint, deviceID string, down bool, detail string) {
	if !down {
		// Снятие флага само по себе алерта не требует: поле на устройстве уже очищено
		// тем же heartbeat'ом, а висящий алерт оператор закрывает сам — он же проверяет,
		// что за время слепоты на машине ничего не произошло.
		g.logger.Info("agent outbox recovered", "device_id", deviceID)
		return
	}
	g.logger.Warn("agent outbox unavailable", "device_id", deviceID, "detail", detail)

	dbID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil || dbID == "" {
		if ctx.Err() == nil {
			g.logger.Error("outbox alert: device lookup", "device_id", deviceID, "err", err)
		}
		return
	}
	created, err := g.db.CreateAlert(ctx, dbID, "outbox_unavailable", detail, "")
	if err != nil {
		g.logger.Error("create alert outbox_unavailable", "device_id", deviceID, "err", err)
		return
	}
	if created && g.bot != nil {
		hostname, _ := g.db.GetDeviceHostname(ctx, dbID)
		// NotifyAlert, не NotifyITAdmins: иначе порог users.notify_min_severity
		// (миграция 041) обходится — алерт high уходил бы даже тем, кто просил
		// только critical. Тот же путь, что у lock_tamper / filevault_*.
		sev := alerting.DefaultFor("outbox_unavailable")
		text := notifier.HTMLf("%s <b>Агент ослеп: очередь отчётов недоступна</b>\nКритичность: %s\nУстройство: <code>%s</code>\nОтчёты, статусы лока и security-события с него НЕ доходят — тишина больше не значит «всё спокойно».\nПричина: %s",
			alerting.Emoji(sev), alerting.Label(sev), hostname, detail)
		// DetachTenant, а не context.Background(): отправка переживает запрос (ходит в
		// сеть), но обязана остаться в тенанте устройства. Голый Background увёл бы
		// уведомление про эту машину администраторам всех подразделений сразу.
		go g.bot.NotifyAlert(storage.DetachTenant(ctx), sev, text)
	}
}

func (g *Gateway) AckTaskReceived(ctx context.Context, req *pb.TaskReceivedAck) (*pb.TaskReceivedAckResponse, error) {
	// Скоуп по вызывающему устройству: иначе устройство A по чужому task_id (виден
	// viewer'у через GET /devices/{id}/tasks) могло Ack'нуть задачу устройства B —
	// задача уходит из pending и НИКОГДА не доставится B, тихо (BOLA/IDOR).
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	ctx, scopeDone, err := g.scopeByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "scope tenant: %v", err)
	}
	defer scopeDone(true)

	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		g.logger.Error("ack task: device lookup", "err", err)
		return nil, status.Errorf(codes.Internal, "device lookup: %v", err)
	}
	if err := g.db.AckTask(ctx, req.TaskId, deviceID); err != nil {
		if errors.Is(err, storage.ErrTaskNotOwned) {
			g.logger.Warn("ack task: not owned by caller — ignored", "task_id", req.TaskId, "device_id", deviceID)
			return &pb.TaskReceivedAckResponse{Acknowledged: false}, nil
		}
		g.logger.Error("ack task", "task_id", req.TaskId, "err", err)
		return &pb.TaskReceivedAckResponse{Acknowledged: false}, nil
	}
	g.logger.Info("task acked", "task_id", req.TaskId, "device_id", deviceID)
	return &pb.TaskReceivedAckResponse{Acknowledged: true}, nil
}

func (g *Gateway) ReportInventory(ctx context.Context, req *pb.InventoryReport) (*pb.InventoryAck, error) {
	deviceID, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}

	tenantID, err := g.tenantForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup tenant: %v", err)
	}
	// Тенант — в контекст, а не только в переменную: методы storage, которые его
	// параметром не принимают, берут скоуп отсюда.
	ctx = storage.WithTenantID(ctx, tenantID)
	ctx = storage.WithTenantID(ctx, tenantID)

	if req.DeviceInfo == nil {
		return &pb.InventoryAck{Received: false}, nil
	}

	software := make([]storage.SoftwareItem, len(req.Software))
	for i, s := range req.Software {
		software[i] = storage.SoftwareItem{
			Name:            s.SoftwareName,
			Version:         s.Version,
			Vendor:          s.Vendor,
			InstallLocation: s.InstallLocation,
			Arch:            s.Arch,
			UninstallID:     s.UninstallId,
			UninstallMethod: uninstallMethodToString(s.UninstallMethod),
			Scope:           s.Scope,
		}
	}

	if err := g.db.UpsertInventory(ctx, storage.InventoryData{
		CertFingerprint: fingerprint,
		Hostname:        req.DeviceInfo.Hostname,
		OS:              req.DeviceInfo.Os,
		OSVersion:       req.DeviceInfo.OsVersion,
		CPU:             req.DeviceInfo.Cpu,
		RAM:             req.DeviceInfo.Ram,
		Disk:            req.DeviceInfo.Disk,
		IPAddress:       req.DeviceInfo.IpAddress,
		MACAddress:      req.DeviceInfo.MacAddress,
		SerialNumber:    req.DeviceInfo.SerialNumber,
		AgentVersion:    req.DeviceInfo.AgentVersion,
		Arch:            req.DeviceInfo.Arch,
		ConsoleUser:     req.DeviceInfo.ConsoleUser,
		ConsoleUserSid:  req.DeviceInfo.ConsoleUserSid,
		DiskEncryption:  req.DeviceInfo.DiskEncryption,
		OSPatchDate:     req.DeviceInfo.OsPatchDate,
		BootTime:        req.DeviceInfo.BootTime,
		DiskFree:        req.DeviceInfo.DiskFree,
		DomainJoined:    req.DeviceInfo.DomainJoined,
		TPM:             req.DeviceInfo.Tpm,
		SecureBoot:      req.DeviceInfo.SecureBoot,
		Capabilities:    req.DeviceInfo.Capabilities,
		Software:        software,
	}); err != nil {
		g.logger.Error("upsert inventory", "device_id", deviceID, "err", err)
		return nil, status.Errorf(codes.Internal, "store inventory: %v", err)
	}

	// Пересчёт уязвимостей — на СВЕЖЕМ инвентаре, иначе матчер CVE не запускается
	// никогда: другого события «список ПО изменился» в системе нет. Отдельной
	// задачей, а не здесь же: справочник CVE большой, а инвентарь приходит раз в
	// пять минут с каждой машины парка.
	//
	// Ошибка постановки не роняет приём инвентаря — он уже сохранён, — но и не
	// глотается молча: без неё оператор видел бы пустой список уязвимостей и считал
	// это отсутствием уязвимостей.
	if g.inventoryHook != nil {
		if dbID, derr := g.db.GetDeviceIDByFingerprint(ctx, fingerprint); derr == nil && dbID != "" {
			g.inventoryHook(ctx, tenantID, dbID)
		} else if derr != nil {
			g.logger.Error("inventory hook: lookup device", "fingerprint", fingerprint, "err", derr)
		}
	}

	g.logger.Info("inventory received", "device_id", deviceID, "software_count", len(req.Software))
	return &pb.InventoryAck{Received: true}, nil
}

func (g *Gateway) ReportTaskResult(ctx context.Context, req *pb.TaskResult) (*pb.TaskResultAck, error) {
	// Скоуп по вызывающему устройству: иначе устройство A по чужому task_id могло
	// пометить задачу устройства B «успешной» без исполнения (фальсификация compliance).
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	ctx, scopeDone, err := g.scopeByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "scope tenant: %v", err)
	}
	defer scopeDone(true)

	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		g.logger.Error("complete task: device lookup", "err", err)
		return nil, status.Errorf(codes.Internal, "device lookup: %v", err)
	}
	taskStatus := "completed"
	if req.Status == pb.TaskStatus_TASK_STATUS_ERROR {
		taskStatus = "failed"
	}
	prevStatus, taskType, err := g.db.CompleteTask(ctx, req.TaskId, deviceID, taskStatus, req.Output, req.ErrorLog)
	if err != nil {
		if errors.Is(err, storage.ErrTaskNotOwned) {
			// Чужой/несуществующий task_id: accept-and-drop (Received:true, без gRPC-ошибки),
			// чтобы не отравить FIFO-outbox агента и не палить существование задачи.
			g.logger.Warn("complete task: not owned by caller — ignored", "task_id", req.TaskId, "device_id", deviceID)
			return &pb.TaskResultAck{Received: true}, nil
		}
		g.logger.Error("complete task", "task_id", req.TaskId, "err", err)
		return &pb.TaskResultAck{Received: false}, nil
	}
	// Исход удаления ПО — отдельным полем, ДО остальной обработки: он значим и при
	// completed, и при failed. Например NOT_REMOVABLE приезжает с ошибкой задачи, а
	// TARGET_CHANGED — с успехом (агент отработал правильно, просто цель разъехалась).
	// Ошибку записи не поднимаем наверх: сам результат задачи уже сохранён, и терять
	// его из-за неудачной приписки исхода нельзя — агент отправил бы отчёт заново.
	if taskType == "uninstall" && req.UninstallOutcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_UNSPECIFIED {
		outcome := uninstallOutcomeToString(req.UninstallOutcome)
		if err := g.db.SetTaskUninstallOutcome(ctx, req.TaskId, deviceID, outcome); err != nil {
			g.logger.Error("save uninstall outcome", "task_id", req.TaskId, "outcome", outcome, "err", err)
		} else {
			g.logger.Info("uninstall reported", "task_id", req.TaskId, "device_id", deviceID, "outcome", outcome)
		}
	}
	// Задача уже была закрыта по таймауту (FailStaleAckedTasks), а результат приехал
	// после — консоль какое-то время показывала 'failed' для задачи, которая на самом
	// деле отработала. Результат мы приняли, но подменять статус задним числом молча
	// нельзя: по 'failed' могли завести тикет или перезапустить задачу вручную.
	// Поэтому WARN + запись в аудит. WithoutCancel — событие уже свершилось и должно
	// пережить обрыв соединения (тот же приём, что в api.Handler.audit).
	if prevStatus == "failed" {
		g.logger.Warn("task result received after timeout sweep — статус исправлен задним числом",
			"task_id", req.TaskId, "device_id", deviceID, "prev_status", prevStatus, "status", taskStatus)
		if err := g.db.WriteAuditLog(context.WithoutCancel(ctx), "", "agent:"+deviceID,
			"late_task_result", "task", req.TaskId,
			map[string]any{"prev_status": prevStatus, "status": taskStatus}); err != nil {
			g.logger.Warn("late task result: аудит не записан", "task_id", req.TaskId, "err", err)
		}
	}
	// Decommission-задача подтверждена агентом (он уже сносится) → флипаем устройство
	// в терминальный 'decommissioned': Connect/heartbeat/все RPC теперь отклоняются (как
	// blocked), heartbeat не воскрешает. Флип строго ПОСЛЕ приёма отчёта — до него статус
	// оставался прежним, чтобы Connect успел доставить команду. Только SUCCESS: FAILED
	// значит агент не смог снестись, устройство ещё живо — списывать нельзя.
	// Ошибку флипа НЕ возвращаем агенту: он не ретраит (ReportTaskResult у decommission
	// идёт мимо durable-очереди, агент уже мёртв) — но это ВИДИМАЯ ошибка в логе.
	// ponytail: остаточный потолок — если флип упал по транзиентной ошибке БД, устройство
	// останется 'active' с уже мёртвым сертом (active-unreachable); лечится повторной
	// ручкой или ручным статусом. Серверного форс-отзыва (без ack агента) здесь нет.
	if taskType == "decommission" && taskStatus == "completed" {
		if err := g.db.MarkDeviceDecommissioned(context.WithoutCancel(ctx), deviceID); err != nil {
			g.logger.Error("decommission: не удалось пометить устройство списанным",
				"device_id", deviceID, "task_id", req.TaskId, "err", err)
		} else {
			g.logger.Warn("decommission: устройство помечено списанным (отозвано)",
				"device_id", deviceID, "task_id", req.TaskId)
		}
	}

	g.logger.Info("task result received", "task_id", req.TaskId, "device_id", deviceID, "status", taskStatus)
	return &pb.TaskResultAck{Received: true}, nil
}

// isCutOff — терминальные/отклоняющие статусы, при которых gateway полностью
// отрезает устройство (Connect/heartbeat/все agent-RPC): 'blocked' (kill-switch),
// 'decommissioned' (снесён), 'rejected' (отклонён из очереди одобрения). Отличается
// от pending_approval — тот режется ТОЛЬКО на политиках/скриптах.
func isCutOff(deviceStatus string) bool {
	switch deviceStatus {
	case "blocked", "decommissioned", "rejected":
		return true
	}
	return false
}

// pendingApproval сообщает, стоит ли устройство в очереди одобрения (bulk-энролл).
// Такому режем ТОЛЬКО автоматические каналы исполнения (политики/скрипты) — Connect/
// heartbeat/инвентарь остаются, поэтому это НЕ blocked-интерсептор (тот рубит всё), а
// точечный гейт в FetchPolicy/FetchScriptPolicies.
func (g *Gateway) pendingApproval(ctx context.Context, fingerprint string) (bool, error) {
	st, err := g.db.GetDeviceStatusByFingerprint(ctx, fingerprint)
	if err != nil {
		return false, err
	}
	return st == "pending_approval", nil
}

func (g *Gateway) FetchPolicy(ctx context.Context, req *pb.FetchPolicyRequest) (*pb.FetchPolicyResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	ctx, scopeDone, err := g.scopeByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "scope tenant: %v", err)
	}
	defer scopeDone(true)

	// Неодобренное устройство (pending_approval) не получает политик: очередь одобрения
	// гейтит АВТОМАТИЧЕСКИЕ каналы исполнения (политики/скрипты), оставляя Connect/
	// heartbeat/инвентарь (чтобы админ видел машину). Пустой ответ = «политик нет».
	if gated, err := g.pendingApproval(ctx, fingerprint); err != nil {
		return nil, status.Errorf(codes.Internal, "status check: %v", err)
	} else if gated {
		return &pb.FetchPolicyResponse{}, nil
	}

	result, err := g.db.FetchPolicyRules(ctx, fingerprint)
	if err != nil {
		g.logger.Error("fetch policy rules", "err", err)
		return nil, status.Errorf(codes.Internal, "fetch policy: %v", err)
	}

	if result.Version != 0 && req.KnownVersion == result.Version {
		return &pb.FetchPolicyResponse{Unchanged: true, Version: result.Version}, nil
	}

	rules := make([]*pb.SoftwarePolicyRule, 0, len(result.Rules))
	for _, r := range result.Rules {
		rt := pb.PolicyRuleType_POLICY_RULE_TYPE_ALLOWED
		if r.RuleType == "forbidden" {
			rt = pb.PolicyRuleType_POLICY_RULE_TYPE_FORBIDDEN
		}
		rules = append(rules, &pb.SoftwarePolicyRule{SoftwareName: r.SoftwareName, RuleType: rt})
	}
	return &pb.FetchPolicyResponse{Rules: rules, Version: result.Version}, nil
}

// uninstallMethodToString — enum → канон БД (миграция 036). UNSPECIFIED = «снять
// нечем» и хранится пустой строкой, а не словом "unspecified": пустое значение уже
// означает «источник не отдал» у соседних колонок, и UI не должен различать два
// написания одного и того же «нельзя».
func uninstallMethodToString(m pb.UninstallMethod) string {
	if m == pb.UninstallMethod_UNINSTALL_METHOD_UNSPECIFIED {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(m.String(), "UNINSTALL_METHOD_"))
}

// uninstallOutcomeToString — enum → канон БД (миграция 041), тем же приёмом, что и
// uninstallMethodToString: из имени enum'а, а не из руками выписанной таблицы, которая
// разъехалась бы с proto молча при добавлении нового исхода. UNSPECIFIED сюда не
// доходит — вызывающий его отсекает (это «задача не про удаление», а не исход).
func uninstallOutcomeToString(o pb.UninstallOutcome) string {
	return strings.ToLower(strings.TrimPrefix(o.String(), "UNINSTALL_OUTCOME_"))
}

func (g *Gateway) ReportSecurityEvent(ctx context.Context, req *pb.SecurityEvent) (*pb.SecurityEventAck, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	ctx, scopeDone, err := g.scopeByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "scope tenant: %v", err)
	}
	defer scopeDone(true)

	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		// Временная ошибка БД: отдаём gRPC-ошибку, чтобы агент ретраил из outbox
		// (раньше Received:false без ошибки → событие молча терялось, БАГ 3).
		g.logger.Error("security event: lookup device", "err", err)
		return nil, status.Errorf(codes.Unavailable, "lookup device: %v", err)
	}
	if deviceID == "" {
		// Неизвестный fingerprint (серт валиден по mTLS, но строки устройства нет —
		// снятое/призрачное устройство). Принять-и-дропнуть, чтобы агент не ретраил
		// впустую до сброса по возрасту. Логируем тип и детали — это может быть
		// реальный сигнал с выведенной, но физически живой машины (для SIEM).
		g.logger.Warn("security event from unknown device, dropping",
			"fingerprint", fingerprint, "alert_type", req.AlertType.String(), "details", req.Details)
		return &pb.SecurityEventAck{Received: true}, nil
	}
	alertType := strings.ToLower(strings.TrimPrefix(req.AlertType.String(), "ALERT_TYPE_"))
	created, err := g.db.CreateAlert(ctx, deviceID, alertType, req.Details, req.AdminAccessRequestId)
	if err != nil {
		if errors.Is(err, storage.ErrForeignKeyViolation) {
			// Устройство/заявка удалены до доставки события (гонка с удалением или
			// retention-чисткой) — терминально, accept-and-drop по ack-контракту.
			// Детали остаются в Warn-логе (сигнал для SIEM), как и у unknown device.
			g.logger.Warn("security event references deleted row, dropping",
				"device_id", deviceID, "alert_type", alertType, "details", req.Details, "err", err)
			return &pb.SecurityEventAck{Received: true}, nil
		}
		g.logger.Error("create alert", "device_id", deviceID, "err", err)
		return nil, status.Errorf(codes.Unavailable, "create alert: %v", err)
	}
	if !created {
		// Дубль подавлен серверным дедупом (непринятый такой же уже висит): не спамим
		// Telegram. Ack положительный — агент не ретраит из outbox.
		g.logger.Info("security event deduped, not re-alerting", "device_id", deviceID, "type", alertType)
		return &pb.SecurityEventAck{Received: true}, nil
	}
	g.logger.Info("security event saved", "device_id", deviceID, "type", alertType)
	if g.bot != nil {
		hostname, _ := g.db.GetDeviceHostname(ctx, deviceID)
		alertLabel := map[string]string{
			"forbidden_software":           "Запрещённое ПО",
			"unauthorized_install":         "Неавторизованная установка",
			"unauthorized_settings_change": "Изменение настроек",
			"lock_tamper":                  "Попытка обхода блокировки",
			"filevault_secret_mismatch":    "FileVault: секрет не совпал с эскроу",
			"filevault_revoke_failed":      "FileVault: revoke не завершён",
			"outbox_unavailable":           "Агент ослеп: очередь отчётов недоступна",
		}[alertType]
		if alertLabel == "" {
			alertLabel = alertType
		}
		// Критичность берётся из той же чистой функции, что и в CreateAlert, —
		// значение в строке БД и значение, по которому маршрутизируется уведомление,
		// не могут разойтись.
		severity := alerting.DefaultFor(alertType)
		text := notifier.HTMLf("%s <b>Алерт безопасности</b>\nТип: %s\nКритичность: %s\nУстройство: <code>%s</code>\nДетали: %s",
			alerting.Emoji(severity), alertLabel, alerting.Label(severity), hostname, req.Details)
		go g.bot.NotifyAlert(storage.DetachTenant(ctx), severity, text)
	}
	return &pb.SecurityEventAck{Received: true}, nil
}

// scopeByFingerprint открывает скоуп тенанта устройства по отпечатку его сертификата.
//
// Агентские ручки — единственная точка, где тенант выводится из клиентского серта, и
// раньше почти все они ходили в БД без скоупа вообще. Под app-ролью из 049 это ломало
// их непредсказуемо: соединение из пула с пустым routineops.tenant_id даёт 22P02, ещё
// чистое — тихий ноль строк. Полевой e2e 30.07 ловил ровно это: FetchLockStatus,
// FetchScriptPolicies, FetchPolicy и приём результатов скрипта падали на живом парке,
// пока heartbeat и инвентарь работали и создавали видимость здоровья.
//
// Стрим Connect сюда НЕ заворачивается намеренно: он живёт часами, и транзакция
// удерживала бы соединение из пула всё это время.
func (g *Gateway) scopeByFingerprint(ctx context.Context, fingerprint string) (context.Context, func(bool), error) {
	tenantID, err := g.tenantForFingerprint(ctx, fingerprint)
	if err != nil {
		return ctx, nil, err
	}
	return g.db.BindTenant(ctx, tenantID)
}

func (g *Gateway) tenantForFingerprint(ctx context.Context, fingerprint string) (string, error) {
	_, tenantID, _, err := g.db.GetDeviceTenantByFingerprint(ctx, fingerprint)
	if err != nil {
		return "", err
	}
	if tenantID == "" {
		return tenancy.DefaultTenantID, nil
	}
	return tenantID, nil
}

func (g *Gateway) RequestAdminAccess(ctx context.Context, req *pb.RequestAdminAccessRequest) (*pb.RequestAdminAccessResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup device: %v", err)
	}
	if deviceID == "" {
		return nil, status.Errorf(codes.NotFound, "device not found")
	}
	tenantID, err := g.tenantForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup tenant: %v", err)
	}
	// Тенант — в контекст, а не только в переменную: методы storage, которые его
	// параметром не принимают, берут скоуп отсюда.
	ctx = storage.WithTenantID(ctx, tenantID)
	// requested_by пустой ВСЕГДА: с миграции 038 владелец устройства — карточка человека
	// (directory_persons), а не аккаунт панели, и ссылаться этому полю (FK→users) стало
	// не на что. Заявка от этого не ломается — она и раньше оформлялась без владельца:
	// пользователи панели это ИТ-операторы, а не сотрудники.

	timeoutStr, _ := g.db.GetSystemSetting(ctx, tenantID, "admin_request_timeout_minutes")
	timeoutMin, _ := strconv.Atoi(timeoutStr)
	if timeoutMin <= 0 {
		timeoutMin = 15
	}

	requestedAt := g.clampAgentTime("requested_at", req.RequestedAt)
	pendingExpiresAt := requestedAt.Add(time.Duration(timeoutMin) * time.Minute)

	row, err := g.db.CreateAdminAccessRequest(ctx, deviceID, "", req.Reason, requestedAt, pendingExpiresAt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create request: %v", err)
	}
	g.logger.Info("admin access requested", "device_id", deviceID, "request_id", row.ID)
	if g.bot != nil {
		hostname, _ := g.db.GetDeviceHostname(ctx, deviceID)
		reason := req.Reason
		if reason == "" {
			reason = "не указана"
		}
		text := notifier.HTMLf("🔐 <b>Заявка на права администратора</b>\nУстройство: <code>%s</code>\nПричина: %s\n\nОткройте панель MDM для рассмотрения заявки.",
			hostname, reason)
		go g.bot.NotifyITAdmins(storage.DetachTenant(ctx), text)
	}
	return &pb.RequestAdminAccessResponse{
		RequestId: row.ID,
		Status:    pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_PENDING,
	}, nil
}

func (g *Gateway) FetchAdminStatus(ctx context.Context, _ *pb.FetchAdminStatusRequest) (*pb.FetchAdminStatusResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup device: %v", err)
	}
	if deviceID == "" {
		return nil, status.Errorf(codes.NotFound, "device not found")
	}
	tenantID, err := g.tenantForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup tenant: %v", err)
	}
	// Тенант — в контекст, а не только в переменную: методы storage, которые его
	// параметром не принимают, берут скоуп отсюда.
	ctx = storage.WithTenantID(ctx, tenantID)

	collect, intervalSec := g.adminCollectFlags(ctx, tenantID)

	row, err := g.db.FetchActiveAdminRequest(ctx, deviceID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fetch: %v", err)
	}
	if row == nil {
		return &pb.FetchAdminStatusResponse{
			CollectSessionChanges: collect,
			SnapshotIntervalSec:   intervalSec,
		}, nil
	}

	resp := &pb.FetchAdminStatusResponse{
		RequestId:             row.ID,
		Status:                adminStatusToProto(row.Status),
		CollectSessionChanges: collect,
		SnapshotIntervalSec:   intervalSec,
	}
	if row.GrantedAt != nil {
		resp.GrantedAt = row.GrantedAt.Unix()
	}
	if row.ExpiresAt != nil {
		resp.ExpiresAt = row.ExpiresAt.Unix()
	}
	return resp, nil
}

func (g *Gateway) ReportAdminAccess(ctx context.Context, req *pb.ReportAdminAccessRequest) (*pb.ReportAdminAccessResponse, error) {
	// Скоуп по вызывающему устройству: иначе, зная чужой request_id, любое устройство
	// могло отозвать выданный грант другого устройства (IDOR).
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	ctx, scopeDone, err := g.scopeByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "scope tenant: %v", err)
	}
	defer scopeDone(true)

	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		g.logger.Error("report admin access: device lookup", "err", err)
		return nil, status.Errorf(codes.Internal, "device lookup: %v", err)
	}

	var reportStatus string
	switch req.Status {
	case pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED:
		reportStatus = "approved"
	case pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED:
		reportStatus = "revoked"
	default:
		return nil, status.Errorf(codes.InvalidArgument, "status must be APPROVED or REVOKED")
	}

	occurredAt := g.clampAgentTime("occurred_at", req.OccurredAt)

	if err := g.db.UpdateAdminAccessReport(ctx, req.RequestId, deviceID, reportStatus, occurredAt); err != nil {
		if errors.Is(err, storage.ErrAdminRequestNotFound) {
			// Заявки нет / уже закрыта (напр. revoke по устаревшему reqID). Идемпотентно
			// ничтожно. accept-and-drop, НЕ gRPC-ошибка: у агента outbox строго FIFO,
			// терминальная ошибка отравила бы голову очереди (poison pill).
			g.logger.Warn("admin access report for unknown/closed request, dropping",
				"request_id", req.RequestId, "status", reportStatus)
			return &pb.ReportAdminAccessResponse{Received: true}, nil
		}
		g.logger.Error("report admin access", "request_id", req.RequestId, "err", err)
		return nil, status.Errorf(codes.Unavailable, "report admin access: %v", err)
	}
	// Защёлка сбора улик: только при первом APPROVED с baseline_captured.
	if reportStatus == "approved" && req.GetBaselineCaptured() {
		if err := g.db.MarkAdminBaselineCaptured(ctx, req.RequestId, deviceID, occurredAt); err != nil {
			g.logger.Error("mark baseline captured", "request_id", req.RequestId, "err", err)
			return nil, status.Errorf(codes.Unavailable, "baseline: %v", err)
		}
	}
	g.logger.Info("admin access reported", "request_id", req.RequestId, "status", reportStatus, "details", req.Details)
	return &pb.ReportAdminAccessResponse{Received: true}, nil
}

func (g *Gateway) FetchScriptPolicies(ctx context.Context, req *pb.FetchScriptPoliciesRequest) (*pb.FetchScriptPoliciesResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	ctx, scopeDone, err := g.scopeByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "scope tenant: %v", err)
	}
	defer scopeDone(true)

	// Неодобренное устройство не тянет и не исполняет скрипты (скрипт-канал = RCE от
	// SYSTEM/root) — держим закрытым до одобрения. См. FetchPolicy.
	if gated, err := g.pendingApproval(ctx, fingerprint); err != nil {
		return nil, status.Errorf(codes.Internal, "status check: %v", err)
	} else if gated {
		return &pb.FetchScriptPoliciesResponse{}, nil
	}

	result, err := g.db.GetEffectiveScriptPoliciesForDevice(ctx, fingerprint)
	if err != nil {
		g.logger.Error("fetch script policies", "err", err)
		return nil, status.Errorf(codes.Internal, "fetch: %v", err)
	}

	if result.Version != 0 && req.KnownVersion == result.Version {
		return &pb.FetchScriptPoliciesResponse{Unchanged: true, Version: result.Version}, nil
	}

	policies := make([]*pb.ScriptPolicy, 0, len(result.Policies))
	for _, ep := range result.Policies {
		p := &pb.ScriptPolicy{
			PolicyId:      ep.PolicyID,
			Name:          ep.Name,
			ScriptContent: ep.Content,
			Interpreter:   platformToInterpreter(ep.Platform),
			Trigger:       triggerTypeToProto(ep.TriggerType),
			Cron:          ep.Cron,
			EventTrigger:  eventNameToProto(ep.EventName),
			UpdatedAt:     ep.UpdatedAt.Unix(),
		}
		policies = append(policies, p)
	}
	return &pb.FetchScriptPoliciesResponse{Policies: policies, Version: result.Version}, nil
}

func (g *Gateway) ReportScriptResult(ctx context.Context, req *pb.ScriptResult) (*pb.ScriptResultAck, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	ctx, scopeDone, err := g.scopeByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "scope tenant: %v", err)
	}
	defer scopeDone(true)

	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		g.logger.Error("script result: lookup device", "err", err)
		return nil, status.Errorf(codes.Unavailable, "lookup device: %v", err)
	}
	if deviceID == "" {
		g.logger.Warn("script result from unknown device, dropping", "fingerprint", fingerprint)
		return &pb.ScriptResultAck{Received: true}, nil
	}

	trigger := strings.ToLower(strings.TrimPrefix(req.Trigger.String(), "SCRIPT_TRIGGER_"))
	err = g.db.SaveScriptResult(ctx, storage.ScriptResultInput{
		PolicyID:   req.PolicyId,
		DeviceID:   deviceID,
		RunID:      req.RunId,
		ExitCode:   req.ExitCode,
		Stdout:     req.Stdout,
		Stderr:     req.Stderr,
		Trigger:    trigger,
		StartedAt:  g.clampAgentTime("started_at", req.StartedAt),
		FinishedAt: g.clampAgentTime("finished_at", req.FinishedAt),
	})
	if errors.Is(err, storage.ErrForeignKeyViolation) {
		// Политика или устройство удалены раньше, чем агент сдал результат: ретрай
		// с тем же payload не пройдёт никогда — accept-and-drop по ack-контракту
		// (Unavailable здесь = вечный poison pill в голове outbox агента).
		g.logger.Warn("script result references deleted policy/device, dropping",
			"policy_id", req.PolicyId, "run_id", req.RunId, "err", err)
		return &pb.ScriptResultAck{Received: true}, nil
	}
	if err != nil {
		g.logger.Error("save script result", "run_id", req.RunId, "err", err)
		return nil, status.Errorf(codes.Unavailable, "save script result: %v", err)
	}
	g.logger.Info("script result saved", "policy_id", req.PolicyId, "run_id", req.RunId, "exit_code", req.ExitCode)
	return &pb.ScriptResultAck{Received: true}, nil
}

func (g *Gateway) ReportLockStatus(ctx context.Context, req *pb.ReportLockStatusRequest) (*pb.ReportLockStatusResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	tenantID, err := g.tenantForFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, err
	}
	// Тенант в контекст: дальше идут SetDeviceLockActualState/UpdateDeviceLockStatus по
	// таблице под RLS. Без этого отчёт агента о состоянии замка трогал бы ноль строк и
	// возвращал бы «принято» — сервер считал бы устройство запертым, когда оно уже нет.
	ctx = storage.WithTenantID(ctx, tenantID)
	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		g.logger.Error("lock status: lookup device", "err", err)
		return nil, status.Errorf(codes.Unavailable, "lookup device: %v", err)
	}
	if deviceID == "" {
		g.logger.Warn("lock status from unknown device, dropping", "fingerprint", fingerprint)
		return &pb.ReportLockStatusResponse{Received: true}, nil
	}

	switch req.State {
	case pb.LockState_LOCK_STATE_UNSPECIFIED:
		// Живой агент всегда шлёт явный enum (reconcile/executor); 0 = кривой или
		// злой отправитель. Раньше 0 падал в ветку "unlocked" и СТИРАЛ desired
		// hash/reason — тот же класс порчи desired, что и state=3. Принять-и-дропнуть.
		g.logger.Warn("lock status UNSPECIFIED, dropping", "device_id", deviceID, "details", req.Details)
		return &pb.ReportLockStatusResponse{Received: true}, nil

	case pb.LockState_LOCK_STATE_FILEVAULT_REVOKED:
		// Half-state деструктива: Secure Token снят, PRK заэскроен, РЕБУТ ещё не
		// сделан — лок ещё НЕ эффективен. Пишем ТОЛЬКО actual; desired НЕ трогаем:
		// маппинг в "unlocked" (как было бы веткой ниже) стёр бы desired hash/reason,
		// и агент молча самоотменил бы собственный деструктивный лок через реконсайл.
		if err := g.db.SetDeviceLockActualState(ctx, deviceID, "filevault_revoked"); err != nil {
			g.logger.Error("update lock actual state", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "update lock actual state: %v", err) // transient → ретрай
		}
		// Аудит + алерт: отчёт о деструктивной операции. Ретрай после сбоя аудита
		// даст дубль записи — приемлемо, потеря записи хуже (идемпотентности тут нет).
		if err := g.db.WriteAuditLog(ctx, "", "agent", "filevault_revoked", "device", deviceID,
			map[string]any{"details": req.Details, "occurred_at": req.OccurredAt, "request_id": req.RequestId}); err != nil {
			g.logger.Error("audit filevault_revoked", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "audit: %v", err)
		}
		if g.bot != nil {
			hostname, _ := g.db.GetDeviceHostname(ctx, deviceID)
			text := notifier.HTMLf("🔐 <b>FileVault-лок: токен снят</b>\nУстройство: <code>%s</code>\nРебут ещё НЕ сделан — лок пока не эффективен.\nДетали: %s",
				hostname, req.Details)
			go g.bot.NotifyITAdmins(storage.DetachTenant(ctx), text)
		}
		g.logger.Info("lock actual state updated", "device_id", deviceID, "state", "filevault_revoked", "details", req.Details)
		return &pb.ReportLockStatusResponse{Received: true}, nil

	case pb.LockState_LOCK_STATE_FILEVAULT_REVOKE_FAILED:
		// Деструктивный revoke НЕ завершился (partial/ABORT/misbuild). Токен мог быть
		// снят у ЧАСТИ владельцев — security-релевантная незавершённая мутация, ради
		// которой агент шлёт durable-отчёт (filevault.RevokeAndShutdown). desired НЕ
		// трогаем (как и в FILEVAULT_REVOKED — иначе агент самоотменил бы лок), но
		// ОБЯЗАТЕЛЬНО оставляем след: actual-state + аудит + алерт IT. Раньше этот отчёт
		// шёл State=UNSPECIFIED и молча дропался (accept-and-drop) — IT не узнавал о
		// полу-локнутом устройстве.
		if err := g.db.SetDeviceLockActualState(ctx, deviceID, "filevault_revoke_failed"); err != nil {
			g.logger.Error("update lock actual state (revoke_failed)", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "update lock actual state: %v", err) // transient → ретрай
		}
		// Аудит + алерт: ретрай после сбоя даст дубль — приемлемо (потеря записи о
		// незавершённом деструктиве хуже). Алерт шлём ПОСЛЕ устойчивого аудита.
		if err := g.db.WriteAuditLog(ctx, "", "agent", "filevault_revoke_failed", "device", deviceID,
			map[string]any{"details": req.Details, "occurred_at": req.OccurredAt, "request_id": req.RequestId}); err != nil {
			g.logger.Error("audit filevault_revoke_failed", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "audit: %v", err)
		}
		// Строка в alerts, а не только телеграм: половинчатый деструктив обязан висеть
		// в панели ИБ и требовать подтверждения. Дедуп живёт ВНУТРИ CreateAlert — он же
		// закрывает повторы, которых у этой ветки своего гашения не было.
		//
		// Раньше сюда падал и pre-mutation ABORT, поэтому роутить в панель было нельзя:
		// засеяли бы её шумом с невооружённых машин. Теперь такие отчёты уезжают в 6/7,
		// и четвёрка вернулась к своему настоящему смыслу — начавшийся деструктив.
		if created, err := g.db.CreateAlert(ctx, deviceID, "filevault_revoke_failed", req.Details, ""); err != nil {
			g.logger.Error("create alert filevault_revoke_failed", "device_id", deviceID, "err", err)
		} else if created && g.bot != nil {
			hostname, _ := g.db.GetDeviceHostname(ctx, deviceID)
			text := notifier.HTMLf("🛑 <b>FileVault-лок: revoke НЕ завершён</b>\nУстройство: <code>%s</code>\nДеструктив мог примениться ЧАСТИЧНО — требуется ручной разбор IT.\nДетали: %s",
				hostname, req.Details)
			go g.bot.NotifyAlert(storage.DetachTenant(ctx), alerting.DefaultFor("filevault_revoke_failed"), text)
		}
		g.logger.Warn("filevault revoke FAILED reported", "device_id", deviceID, "details", req.Details, "request_id", req.RequestId)
		return &pb.ReportLockStatusResponse{Received: true}, nil

	case pb.LockState_LOCK_STATE_LOCK_FAILED:
		// Overlay-лок НЕ применился (оверлей не поднялся, состояние не записалось).
		// Агент откатывает состояние и ретраит, но машина ОСТАЁТСЯ РАБОЧЕЙ — а в
		// панели устройство числится заблокированным. Именно это расхождение и
		// закрывает ветка: actual-only, как у деструктивных состояний выше.
		// desired НЕ трогаем — иначе реконсайл снял бы лок, который оператор выдал,
		// из-за временной локальной ошибки на устройстве.
		if err := g.db.SetDeviceLockActualState(ctx, deviceID, "lock_failed"); err != nil {
			g.logger.Error("update lock actual state (lock_failed)", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "update lock actual state: %v", err) // transient → ретрай
		}
		// Аудит + алерт: ретрай после сбоя даст дубль — приемлемо (потеря записи о
		// неприменённом локе хуже: оператор считает машину закрытой, а она работает).
		if err := g.db.WriteAuditLog(ctx, "", "agent", "lock_failed", "device", deviceID,
			map[string]any{"details": req.Details, "occurred_at": req.OccurredAt, "request_id": req.RequestId}); err != nil {
			g.logger.Error("audit lock_failed", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "audit: %v", err)
		}
		if g.bot != nil {
			hostname, _ := g.db.GetDeviceHostname(ctx, deviceID)
			text := notifier.HTMLf("⚠️ <b>Блокировка НЕ применена</b>\nУстройство: <code>%s</code>\nАгент не смог поднять лок и продолжает попытки — машина пока РАБОЧАЯ, хотя в панели помечена как заблокированная.\nДетали: %s",
				hostname, req.Details)
			go g.bot.NotifyITAdmins(storage.DetachTenant(ctx), text)
		}
		g.logger.Warn("lock apply FAILED reported", "device_id", deviceID, "details", req.Details, "request_id", req.RequestId)
		return &pb.ReportLockStatusResponse{Received: true}, nil

	case pb.LockState_LOCK_STATE_FILEVAULT_NOT_ARMED:
		// Вооружения нет: не вооружали, истёк TTL, рестартовал сервер (vault в RAM).
		// Машина НЕ тронута, деструктив не начинался. desired НЕ трогаем — лок выдан
		// и остаётся выданным, не хватает только секрета.
		//
		// Алерт шлём, хотя это и штатный fail-closed: без него выданный FileVault-лок
		// молча не применялся бы, а оператор считал бы машину закрытой. Флуда не будет —
		// агент дедупит пару (request_id, state) раз в час и замолкает сразу, как
		// оператор вооружит. Строку в alerts НЕ заводим: это шаг рабочего процесса
		// («вооружите»), а не событие ИБ.
		applied, err := g.db.SetDeviceLockActualStateNoDowngrade(ctx, deviceID, "filevault_not_armed")
		if err != nil {
			g.logger.Error("update lock actual state (not_armed)", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "update lock actual state: %v", err)
		}
		// Аудит пишем всегда: агент действительно это отрепортил, и факт отчёта —
		// правда независимо от того, приняли мы его в actual_state или подавили.
		if err := g.db.WriteAuditLog(ctx, "", "agent", "filevault_not_armed", "device", deviceID,
			map[string]any{"details": req.Details, "occurred_at": req.OccurredAt,
				"request_id": req.RequestId, "actual_state_applied": applied}); err != nil {
			g.logger.Error("audit filevault_not_armed", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "audit: %v", err)
		}
		if !applied {
			// Машина полу-ревокнута: правда про неё — «деструктив начинался», а не
			// «не вооружена». Телеграм с действием «вооружите» увёл бы IT не туда.
			g.logger.Warn("filevault NOT_ARMED подавлен: по устройству уже зафиксирован начавшийся деструктив",
				"device_id", deviceID, "request_id", req.RequestId)
			return &pb.ReportLockStatusResponse{Received: true}, nil
		}
		if g.bot != nil {
			hostname, _ := g.db.GetDeviceHostname(ctx, deviceID)
			text := notifier.HTMLf("🔑 <b>FileVault-лок ждёт вооружения</b>\nУстройство: <code>%s</code>\nМашина НЕ тронута, лок НЕ применён: агенту нечем снять токен.\nДействие: выгрузите ключ из эскроу и вооружите лок (POST /devices/{id}/lock/arm).\nДетали: %s",
				hostname, req.Details)
			go g.bot.NotifyITAdmins(storage.DetachTenant(ctx), text)
		}
		g.logger.Warn("filevault lock NOT ARMED reported", "device_id", deviceID, "details", req.Details, "request_id", req.RequestId)
		return &pb.ReportLockStatusResponse{Received: true}, nil

	case pb.LockState_LOCK_STATE_FILEVAULT_SECRET_MISMATCH:
		// Секрет доставлен, но НЕ совпал с заэскроенным на ЭТОМ устройстве (сверка по
		// локальному дайджесту агента, ADR-F23). Машина не тронута — сверка стоит ДО
		// первой мутации. desired НЕ трогаем.
		//
		// В отличие от NOT_ARMED это НЕ шаг процесса, а расхождение: вооружили не тем
		// секретом либо эскроу разъехалось с тем, что реально лежит на диске. Поэтому
		// заводим строку в alerts — событие должно быть видно в панели ИБ и требовать
		// подтверждения, а не только мигнуть в телеге.
		// Та же durable-защита, что у NOT_ARMED, и по той же причине: SECRET_MISMATCH —
		// тоже pre-mutation ABORT, а агентский гард (Chain.partialReportedFor) глушит
		// ВЕСЬ класс таких отчётов и теряется при рестарте агента.
		applied, err := g.db.SetDeviceLockActualStateNoDowngrade(ctx, deviceID, "filevault_secret_mismatch")
		if err != nil {
			g.logger.Error("update lock actual state (secret_mismatch)", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "update lock actual state: %v", err)
		}
		if err := g.db.WriteAuditLog(ctx, "", "agent", "filevault_secret_mismatch", "device", deviceID,
			map[string]any{"details": req.Details, "occurred_at": req.OccurredAt,
				"request_id": req.RequestId, "actual_state_applied": applied}); err != nil {
			g.logger.Error("audit filevault_secret_mismatch", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "audit: %v", err)
		}
		if !applied {
			g.logger.Warn("filevault SECRET_MISMATCH подавлен: по устройству уже зафиксирован начавшийся деструктив",
				"device_id", deviceID, "request_id", req.RequestId)
			return &pb.ReportLockStatusResponse{Received: true}, nil
		}
		// Дедуп внутри CreateAlert (непринятый такой же уже висит) не даёт часовым
		// повторам плодить строки. Ошибку не роняем наверх: аудит выше уже устойчив,
		// а ретрай агента прислал бы всё заново и без строки алерта.
		if created, err := g.db.CreateAlert(ctx, deviceID, "filevault_secret_mismatch", req.Details, ""); err != nil {
			g.logger.Error("create alert filevault_secret_mismatch", "device_id", deviceID, "err", err)
		} else if created && g.bot != nil {
			hostname, _ := g.db.GetDeviceHostname(ctx, deviceID)
			text := notifier.HTMLf("🛑 <b>FileVault-лок: секрет не тот</b>\nУстройство: <code>%s</code>\nМашина НЕ тронута — расхождение поймано ДО деструктива.\nВооружили не тем секретом либо эскроу разъехалось.\nДействие: выгрузите АКТУАЛЬНУЮ строку эскроу и вооружите заново.\nДетали: %s",
				hostname, req.Details)
			go g.bot.NotifyAlert(storage.DetachTenant(ctx), alerting.DefaultFor("filevault_secret_mismatch"), text)
		}
		g.logger.Warn("filevault SECRET MISMATCH reported", "device_id", deviceID, "details", req.Details, "request_id", req.RequestId)
		return &pb.ReportLockStatusResponse{Received: true}, nil
	}

	// Терминальные состояния маппим ЯВНО. default (любой будущий/битый enum; 6 и 7
	// заняты вооружением и разобраны выше) — accept-and-drop как UNSPECIFIED: НЕ
	// трогаем desired, иначе неизвестный отчёт стёр бы hash/reason и реконсайл
	// самоотменил бы лок.
	var lockStatus string
	switch req.State {
	case pb.LockState_LOCK_STATE_LOCKED:
		lockStatus = "locked"
		// Блокировку хешем сюда не тащим (его нет в отчёте) — hash/reason уже
		// проставил эндпоинт lock; здесь лишь подтверждаем статус.
		if err := g.db.UpdateDeviceLockStatus(ctx, deviceID, "locked"); err != nil {
			if !errors.Is(err, storage.ErrNoDesiredLock) {
				g.logger.Error("update lock status", "device_id", deviceID, "err", err)
				return nil, status.Errorf(codes.Unavailable, "update lock status: %v", err)
			}
			// Симметрично гарду ветки UNLOCKED ниже: устаревший/дубликатный LOCKED из
			// durable-outbox, доехавший ПОСЛЕ снятия, воскресил бы desired 'locked' с уже
			// вычищенным lock_hash. Агент такую команду выполнить не может
			// (validateBcryptHash) — устройство навсегда числилось бы заблокированным в
			// панели, оставаясь рабочим. desired НЕ трогаем; actual зеркалим ниже, чтобы
			// расхождение desired=unlocked / actual=locked было видно, а реконсиляция
			// сама доснимет лок на агенте.
			g.logger.Warn("lock status LOCKED не применён к desired: устройство уже разблокировано (устаревший отчёт из outbox)",
				"device_id", deviceID, "request_id", req.RequestId, "details", req.Details)
		}
	case pb.LockState_LOCK_STATE_UNLOCKED:
		lockStatus = "unlocked"
		// H2: overlay-UNLOCKED НЕ должен отменять desired FILEVAULT-лок.
		// Агент никогда не шлёт UNLOCKED для filevault (снятие такого лока — только через
		// unlock-эндпоинт, пишущий desired напрямую). Устаревший/дубликатный UNLOCKED из
		// durable-outbox (оффлайн-снятие overlay-лока) мог бы прийти ПОСЛЕ того, как IT
		// поставил деструктивный filevault-лок, и стереть его desired → offboarding-лок
		// самоотменился бы, revoke не запустился. Такой отчёт игнорируем.
		curStatus, curHash, _, curMode, curReqID, derr := g.db.GetDesiredLockState(ctx, deviceID)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "check desired lock state: %v", derr)
		}
		if curStatus == "locked" && curMode == storage.LockModeFileVault {
			g.logger.Warn("lock status UNLOCKED проигнорирован: desired = активный FILEVAULT-лок (устаревший/дубликатный overlay-unlock не может отменить деструктивный лок)",
				"device_id", deviceID, "request_id", req.RequestId, "details", req.Details)
			return &pb.ReportLockStatusResponse{Received: true}, nil
		}
		// Отчёт о снятии обязан относиться к ТОМУ ЖЕ локу, что сейчас желаем. Отчёты
		// едут через durable-outbox агента: снятие, случившееся до отъезда ноутбука в
		// офлайн, доезжает после того, как IT выдал НОВУЮ блокировку другим паролем —
		// и без этой проверки стирало её desired, молча разоружая свежий kill-switch.
		// Гард FileVault выше от этого не спасал: overlay-лок проваливался насквозь.
		//
		// Идентификатор лока приходит двумя способами, оба точные:
		//   push  — id lock-задачи (сервер кладёт его в LockCommand.RequestId, worker);
		//   pull  — сам lock_hash (агент применяет лок реконсиляцией и им же
		//           представляется, см. reconcile).
		// Пустой lock_request_id = лок выдан до миграции 032: отличить нельзя, пускаем
		// как раньше — исключение самозакрывается на следующей блокировке.
		//
		// Направление отказа выбрано fail-closed сознательно: лишний расхождение
		// desired/actual виден оператору и чинится одним unlock'ом, а тихо снятая
		// блокировка не обнаруживается вообще. Сотрудника это не запирает — локально
		// лок уже снят верным паролем, а durable-память агента не даёт пере-запереть.
		if curStatus == "locked" && curReqID != "" &&
			req.RequestId != curReqID && req.RequestId != curHash {
			g.logger.Warn("lock status UNLOCKED проигнорирован: отчёт относится к ДРУГОМУ локу (устаревший из durable-outbox), текущая блокировка сохранена",
				"device_id", deviceID, "report_request_id", req.RequestId,
				"desired_request_id", curReqID, "details", req.Details)
			if err := g.db.SetDeviceLockActualState(ctx, deviceID, "unlocked"); err != nil {
				g.logger.Warn("mirror lock actual state (best-effort)", "device_id", deviceID, "err", err)
			}
			return &pb.ReportLockStatusResponse{Received: true}, nil
		}
		// Разблокировку (в т.ч. локальный ввод пароля) отражаем в ЖЕЛАЕМОМ: чистим
		// hash/reason, режим сбрасываем в overlay (fail-safe), иначе реконсиляция
		// пере-заблокировала бы устройство, которое сотрудник легитимно разблокировал
		// (полевой re-lock-баг).
		if err := g.db.SetDeviceLockState(ctx, tenantID, deviceID, "unlocked", "", "", storage.LockModeOverlay, ""); err != nil {
			g.logger.Error("update lock status", "device_id", deviceID, "err", err)
			return nil, status.Errorf(codes.Unavailable, "update lock status: %v", err)
		}
	default:
		g.logger.Warn("lock status unknown state, dropping", "device_id", deviceID, "state", int32(req.State), "details", req.Details)
		return &pb.ReportLockStatusResponse{Received: true}, nil
	}

	// Зеркалим в actual BEST-EFFORT (для FILEVAULT: LOCKED после ребута = деструктив
	// ПОДТВЕРЖДЁН, actual перестаёт висеть в filevault_revoked). НЕ fatal: авторитетна
	// запись desired выше, а колонка lock_actual_state из 022 — телеметрия. Иначе
	// деплой бинаря раньше ручной миграции 022 сломал бы ВЕСЬ overlay-lock-репортинг
	// (missing column → вечный ретрай), не только FileVault-путь.
	if err := g.db.SetDeviceLockActualState(ctx, deviceID, lockStatus); err != nil {
		g.logger.Warn("mirror lock actual state (best-effort)", "device_id", deviceID, "err", err)
	}
	g.logger.Info("lock status updated", "device_id", deviceID, "status", lockStatus, "details", req.Details)
	return &pb.ReportLockStatusResponse{Received: true}, nil
}

// FetchLockStatus отдаёт агенту ЖЕЛАЕМОЕ состояние блокировки устройства
// (реконсиляция): агент поллит это, чтобы пережить потерю push-команды (Task.lock
// едет раз по Connect-стриму) и ребут (после рестарта агент теряет "живую" очередь
// задач сервера — только локальный lock.json и этот pull-канал).
func (g *Gateway) FetchLockStatus(ctx context.Context, _ *pb.FetchLockStatusRequest) (*pb.FetchLockStatusResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	ctx, scopeDone, err := g.scopeByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "scope tenant: %v", err)
	}
	defer scopeDone(true)

	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup device: %v", err)
	}
	if deviceID == "" {
		return nil, status.Errorf(codes.NotFound, "device not found")
	}

	lockStatus, lockHash, lockReason, lockMode, _, err := g.db.GetDesiredLockState(ctx, deviceID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fetch desired lock state: %v", err)
	}
	if lockStatus != "locked" {
		return &pb.FetchLockStatusResponse{}, nil
	}
	if lockHash == "" {
		// Растяжка, а не защита: desired 'locked' с пустым хешем возникать не должен
		// (см. storage.ErrNoDesiredLock), и если он всё же есть — значит его создал
		// путь, которого мы не знаем (ручной SQL, будущий bulk-лок, миграция).
		// Команду отдаём КАК ЕСТЬ: агент откажется её применять (validateBcryptHash,
		// fail-safe) и отчитается о провале — расхождение станет видно в панели.
		// Подавить её здесь означало бы снять с устройства лок, которого никто не
		// снимал, поэтому — только громкий лог на сервере.
		g.logger.Error("desired lock БЕЗ password_hash — агент не сможет применить блокировку, устройство числится locked, оставаясь рабочим",
			"device_id", deviceID)
	}
	return &pb.FetchLockStatusResponse{
		Locked:       true,
		PasswordHash: lockHash,
		Reason:       lockReason,
		LockMode:     worker.LockModeToProto(lockMode),
		// FilevaultTargetUsers пусто — advisory (агент enumerate-all по G2).
	}, nil
}

// EscrowRecoveryKey — тонкий nil-guarded диспатчер, реализация в escrow_seam.go.
// Тело (валидация/crypto/StoreRecoveryKeyEscrow) вынесено в enterprise EscrowService.Store.

func platformToInterpreter(platform string) string {
	if platform == "Windows" {
		return "powershell"
	}
	return "shell"
}

func triggerTypeToProto(t string) pb.ScriptTrigger {
	switch t {
	case "schedule":
		return pb.ScriptTrigger_SCRIPT_TRIGGER_SCHEDULE
	case "event_trigger":
		return pb.ScriptTrigger_SCRIPT_TRIGGER_EVENT
	case "on_connect":
		return pb.ScriptTrigger_SCRIPT_TRIGGER_ON_CONNECT
	default:
		return pb.ScriptTrigger_SCRIPT_TRIGGER_UNSPECIFIED
	}
}

func eventNameToProto(name string) pb.ScriptEventType {
	switch name {
	case "login":
		return pb.ScriptEventType_SCRIPT_EVENT_TYPE_LOGIN
	case "logout":
		return pb.ScriptEventType_SCRIPT_EVENT_TYPE_LOGOUT
	case "network_change":
		return pb.ScriptEventType_SCRIPT_EVENT_TYPE_NETWORK_CHANGE
	default:
		return pb.ScriptEventType_SCRIPT_EVENT_TYPE_UNSPECIFIED
	}
}

func adminStatusToProto(s string) pb.AdminAccessStatus {
	switch s {
	case "pending":
		return pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_PENDING
	case "approved":
		return pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED
	case "rejected":
		return pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REJECTED
	case "expired":
		return pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_EXPIRED
	case "revoked":
		return pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED
	default:
		return pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_UNSPECIFIED
	}
}

// deviceStatusLookup — минимальный интерфейс для blocked-интерсептора (не тащим весь Store).
type deviceStatusLookup interface {
	GetDeviceStatusByFingerprint(ctx context.Context, fingerprint string) (string, error)
}

// NewBlockedInterceptors — unary+stream интерсепторы, отклоняющие ЛЮБОЙ agent-RPC от
// устройства со status='blocked' ИЛИ 'decommissioned' (оба терминально режут доступ;
// decommissioned — необратимо, после подтверждённого сноса). Раньше проверка стояла ТОЛЬКО в Connect, и
// заблокированное (украденное/офбординг) устройство с валидным сертом продолжало тянуть
// и исполнять script-политики через FetchScriptPolicies и остальные 8 RPC: прежний
// kill-switch стоял только в Connect и покрывал 1 RPC из 10. Единая точка на границе
// gRPC закрывает все разом и убирает дублирование по хендлерам.
//
// Семантика повторяет проверку в Connect: extractCertInfo → GetDeviceStatusByFingerprint;
// "blocked"/"decommissioned" → PermissionDenied; неизвестный fingerprint ("") → пропускаем (устройство ещё
// не в БД — как в Connect); ошибка БД → Internal (fail-closed). Стоимость — один
// индексируемый lookup по cert_fingerprint на RPC; агенты поллят редко.
func NewBlockedInterceptors(db deviceStatusLookup, logger *slog.Logger) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	guard := func(ctx context.Context) error {
		_, fingerprint, err := extractCertInfo(ctx)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "cert: %v", err)
		}
		st, err := db.GetDeviceStatusByFingerprint(ctx, fingerprint)
		if err != nil {
			return status.Errorf(codes.Internal, "status check: %v", err)
		}
		if isCutOff(st) {
			logger.Warn("rpc rejected", "fingerprint", fingerprint, "status", st)
			return status.Errorf(codes.PermissionDenied, "device is %s", st)
		}
		return nil
	}
	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
	stream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := guard(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}
	return unary, stream
}

// clampAgentTime защищает audit-таймстампы от кривых/злых значений агента (M-8):
// epoch 0 или значения вне окна вокруг серверного now заменяются на now. Верхняя
// граница критична — будущий RequestedAt иначе растягивает pendingExpiresAt (окно
// админ-доступа); нижняя отсекает мусорные нулевые/древние даты. Клампинг логируем,
// иначе при сбитых часах агента восстановить хронологию инцидента по логам нельзя.
//
// Для окон улик admin-session НЕ использовать: stale_final датирует финал концом
// сессии на машине, пролежавшей выключенной дольше суток — нижняя граница 24ч
// стирала бы ровно этот случай (см. clampAgentEvidenceTime).
func (g *Gateway) clampAgentTime(field string, unix int64) time.Time {
	now := time.Now()
	if unix == 0 {
		return now
	}
	t := time.Unix(unix, 0)
	if t.Before(now.Add(-24*time.Hour)) || t.After(now.Add(5*time.Minute)) {
		g.logger.Warn("clamped out-of-range agent timestamp", "field", field, "value", unix)
		return now
	}
	return t
}

// clampAgentEvidenceTime — для ReportAdminSessionChanges. Будущее и epoch 0 → now;
// прошлое сохраняем (в т.ч. старше 24ч): иначе stale_final теряет даты сессии.
// Абсурдное прошлое до 2020-01-01 всё же режем как мусор/атаку.
func (g *Gateway) clampAgentEvidenceTime(field string, unix int64) time.Time {
	now := time.Now()
	if unix == 0 {
		return now
	}
	t := time.Unix(unix, 0)
	floor := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if t.Before(floor) || t.After(now.Add(5*time.Minute)) {
		g.logger.Warn("clamped out-of-range evidence timestamp", "field", field, "value", unix)
		return now
	}
	return t
}

func extractCertInfo(ctx context.Context) (deviceID, fingerprint string, err error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", "", fmt.Errorf("no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", "", fmt.Errorf("no client certificate")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	return cert.Subject.CommonName, fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), nil
}

// clientIP возвращает IP пира gRPC-соединения (внешний/публичный адрес устройства за NAT).
// Пусто, если peer недоступен. Порт отбрасываем.
func clientIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return "" // не host:port (напр. bufconn в тестах) — публичный IP неизвестен
	}
	return host
}
