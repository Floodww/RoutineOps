package gateway

import (
	"context"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LockSecretVault — шов ВООРУЖЕНИЯ FileVault-лока (ADR-F24). Реализуется
// enterprise-оверлеем (internal/server/escrow.Vault, //go:build enterprise).
// Open-core НИКОГДА его не регистрирует → FetchLockSecrets отвечает Unimplemented.
type LockSecretVault interface {
	// TakeLockSecrets отдаёт вооружение ОДИН раз и тут же его забывает.
	//
	// Статус возвращается значением, а не sentinel-ошибкой: различие «не вооружено»
	// и «вооружено под другой лок-инстанс» обязано доехать до агента (proto
	// ArmStatus), а открытое ядро не может импортировать enterprise-ошибки, чтобы
	// разобрать их через errors.Is.
	TakeLockSecrets(deviceID, requestID string) (st pb.ArmStatus, mdmadminPassword, personalRecoveryKey string)
}

// RegisterLockVault подключает enterprise-vault. Зовётся только из
// enterprise-composition-root (cmd/server, //go:build enterprise).
func (g *Gateway) RegisterLockVault(v LockSecretVault) { g.lockVault = v }

// FetchLockSecrets — агент забирает секреты вооружения для КОНКРЕТНОГО лок-инстанса.
// Обязан существовать во free (часть общего pb.AgentServiceServer).
//
// Авторизация двухслойная, и второй слой не декоративный. Vault сверяет request_id с
// тем, под который вооружали, но он ничего не знает про ОТМЕНУ лока: снятый оператором
// FileVault-лок оставил бы вооружение висеть до истечения TTL, и агент, доехавший в
// этом окне, получил бы живой пароль mdmadmin под уже отменённую команду. Поэтому
// состояние сверяется с БД на КАЖДЫЙ запрос, и только потом трогается vault.
func (g *Gateway) FetchLockSecrets(ctx context.Context, req *pb.FetchLockSecretsRequest) (*pb.FetchLockSecretsResponse, error) {
	_, fingerprint, err := extractCertInfo(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "cert: %v", err)
	}
	if g.lockVault == nil {
		return nil, status.Errorf(codes.Unimplemented, "filevault lock arming is an enterprise feature (not built)")
	}
	deviceID, err := g.db.GetDeviceIDByFingerprint(ctx, fingerprint)
	if err != nil {
		// Временная ошибка БД — РЕАЛЬНАЯ ошибка, а не «не вооружено»: агент обязан
		// ретраить, а не уходить в ABORT с отчётом о несуществующей мисконфигурации.
		g.logger.Error("fetch lock secrets: lookup device", "err", err)
		return nil, status.Errorf(codes.Unavailable, "lookup device: %v", err)
	}
	if deviceID == "" {
		// Серт валиден по mTLS, но строки устройства нет (снятое/призрачное).
		// Секрета такому не даём и вооружение не трогаем.
		g.logger.Warn("fetch lock secrets from unknown device", "fingerprint", fingerprint)
		return &pb.FetchLockSecretsResponse{Status: pb.ArmStatus_ARM_STATUS_NOT_ARMED}, nil
	}

	lockStatus, _, _, lockMode, lockRequestID, err := g.db.GetDesiredLockState(ctx, deviceID)
	if err != nil {
		g.logger.Error("fetch lock secrets: desired lock", "device_id", deviceID, "err", err)
		return nil, status.Errorf(codes.Unavailable, "desired lock: %v", err)
	}
	if lockStatus != "locked" || lockMode != storage.LockModeFileVault {
		// Лока нет или он не деструктивный. Vault НЕ трогаем: Take одноразовый, и
		// слитое здесь вооружение не досталось бы уже никому.
		g.logger.Warn("fetch lock secrets without active filevault lock",
			"device_id", deviceID, "lock_status", lockStatus, "lock_mode", lockMode)
		return &pb.FetchLockSecretsResponse{Status: pb.ArmStatus_ARM_STATUS_NOT_ARMED}, nil
	}
	if lockRequestID != req.GetRequestId() {
		// Агент держит устаревший лок-инстанс (лок перевыдали между FetchLockStatus и
		// этим вызовом). Самозаживает: следующий тик реконсиляции принесёт свежий id.
		g.logger.Info("fetch lock secrets for stale lock instance", "device_id", deviceID)
		return &pb.FetchLockSecretsResponse{Status: pb.ArmStatus_ARM_STATUS_REQUEST_MISMATCH}, nil
	}

	st, password, prk := g.lockVault.TakeLockSecrets(deviceID, req.GetRequestId())
	// Секреты в лог НЕ идут — только факт и статус.
	g.logger.Info("lock secrets fetched", "device_id", deviceID, "status", st.String())
	return &pb.FetchLockSecretsResponse{
		Status:              st,
		MdmadminPassword:    password,
		PersonalRecoveryKey: prk,
	}, nil
}
