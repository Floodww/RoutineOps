package gateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/registry"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/worker"
	pb "github.com/Floodww/RoutineOps/proto"
	"github.com/hibiken/asynq"
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
	NotifyITAdmins(ctx context.Context, text string)
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
			}); err != nil {
				g.logger.Error("upsert heartbeat", "device_id", deviceID, "err", err)
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

func (g *Gateway) AckTaskReceived(ctx context.Context, req *pb.TaskReceivedAck) (*pb.TaskReceivedAckResponse, error) {
	// Скоуп по вызывающему устройству: иначе устройство A по чужому task_id (виден
	// viewer'у через GET /devices/{id}/tasks) могло Ack'нуть задачу устройства B —
	// задача уходит из pending и НИКОГДА не доставится B, тихо (BOLA/IDOR).
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
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

	if req.DeviceInfo == nil {
		return &pb.InventoryAck{Received: false}, nil
	}

	software := make([]storage.SoftwareItem, len(req.Software))
	for i, s := range req.Software {
		software[i] = storage.SoftwareItem{Name: s.SoftwareName, Version: s.Version}
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
		Software:        software,
	}); err != nil {
		g.logger.Error("upsert inventory", "device_id", deviceID, "err", err)
		return nil, status.Errorf(codes.Internal, "store inventory: %v", err)
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

func (g *Gateway) ReportSecurityEvent(ctx context.Context, req *pb.SecurityEvent) (*pb.SecurityEventAck, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
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
		}[alertType]
		if alertLabel == "" {
			alertLabel = alertType
		}
		text := fmt.Sprintf("🚨 <b>Алерт безопасности</b>\nТип: %s\nУстройство: <code>%s</code>\nДетали: %s",
			alertLabel, hostname, req.Details)
		go g.bot.NotifyITAdmins(context.Background(), text)
	}
	return &pb.SecurityEventAck{Received: true}, nil
}

func (g *Gateway) RequestAdminAccess(ctx context.Context, req *pb.RequestAdminAccessRequest) (*pb.RequestAdminAccessResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	deviceID, ownerID, err := g.db.GetDeviceOwner(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup device: %v", err)
	}
	if deviceID == "" {
		return nil, status.Errorf(codes.NotFound, "device not found")
	}
	// Владелец устройства необязателен: MDM-пользователи — это ИТ-операторы, а не
	// сотрудники, поэтому заявка оформляется и без назначенного владельца (ownerID == "").

	timeoutStr, _ := g.db.GetSystemSetting(ctx, "admin_request_timeout_minutes")
	timeoutMin, _ := strconv.Atoi(timeoutStr)
	if timeoutMin <= 0 {
		timeoutMin = 15
	}

	requestedAt := g.clampAgentTime("requested_at", req.RequestedAt)
	pendingExpiresAt := requestedAt.Add(time.Duration(timeoutMin) * time.Minute)

	row, err := g.db.CreateAdminAccessRequest(ctx, deviceID, ownerID, req.Reason, requestedAt, pendingExpiresAt)
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
		text := fmt.Sprintf("🔐 <b>Заявка на права администратора</b>\nУстройство: <code>%s</code>\nПричина: %s\n\nОткройте панель MDM для рассмотрения заявки.",
			hostname, reason)
		go g.bot.NotifyITAdmins(context.Background(), text)
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
	deviceID, _, err := g.db.GetDeviceOwner(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup device: %v", err)
	}
	if deviceID == "" {
		return nil, status.Errorf(codes.NotFound, "device not found")
	}

	row, err := g.db.FetchActiveAdminRequest(ctx, deviceID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fetch: %v", err)
	}
	if row == nil {
		return &pb.FetchAdminStatusResponse{}, nil
	}

	resp := &pb.FetchAdminStatusResponse{
		RequestId: row.ID,
		Status:    adminStatusToProto(row.Status),
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
	g.logger.Info("admin access reported", "request_id", req.RequestId, "status", reportStatus, "details", req.Details)
	return &pb.ReportAdminAccessResponse{Received: true}, nil
}

func (g *Gateway) FetchScriptPolicies(ctx context.Context, req *pb.FetchScriptPoliciesRequest) (*pb.FetchScriptPoliciesResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}

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
			text := fmt.Sprintf("🔐 <b>FileVault-лок: токен снят</b>\nУстройство: <code>%s</code>\nРебут ещё НЕ сделан — лок пока не эффективен.\nДетали: %s",
				hostname, req.Details)
			go g.bot.NotifyITAdmins(context.Background(), text)
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
		if g.bot != nil {
			hostname, _ := g.db.GetDeviceHostname(ctx, deviceID)
			text := fmt.Sprintf("🛑 <b>FileVault-лок: revoke НЕ завершён</b>\nУстройство: <code>%s</code>\nДеструктив мог примениться ЧАСТИЧНО — требуется ручной разбор IT.\nДетали: %s",
				hostname, req.Details)
			go g.bot.NotifyITAdmins(context.Background(), text)
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
			text := fmt.Sprintf("⚠️ <b>Блокировка НЕ применена</b>\nУстройство: <code>%s</code>\nАгент не смог поднять лок и продолжает попытки — машина пока РАБОЧАЯ, хотя в панели помечена как заблокированная.\nДетали: %s",
				hostname, req.Details)
			go g.bot.NotifyITAdmins(context.Background(), text)
		}
		g.logger.Warn("lock apply FAILED reported", "device_id", deviceID, "details", req.Details, "request_id", req.RequestId)
		return &pb.ReportLockStatusResponse{Received: true}, nil
	}

	// Терминальные состояния маппим ЯВНО. default (любой будущий/битый enum, напр.
	// ещё не занятый 6) — accept-and-drop как UNSPECIFIED: НЕ трогаем desired,
	// иначе неизвестный отчёт стёр бы hash/reason и реконсайл самоотменил бы лок.
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
		if err := g.db.SetDeviceLockState(ctx, deviceID, "unlocked", "", "", storage.LockModeOverlay, ""); err != nil {
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
