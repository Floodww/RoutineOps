package gateway_test

import (
	"context"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeVault считает вызовы: выдача одноразовая, поэтому «сколько раз дёрнули» —
// такое же свойство контракта, как и возвращённый статус.
type fakeVault struct {
	calls      int
	lastDevice string
	lastReq    string
	st         pb.ArmStatus
	password   string
	prk        string
}

func (f *fakeVault) TakeLockSecrets(deviceID, requestID string) (pb.ArmStatus, string, string) {
	f.calls++
	f.lastDevice, f.lastReq = deviceID, requestID
	return f.st, f.password, f.prk
}

// armDevice регистрирует устройство и ставит ему ЖИВОЙ desired-лок нужного режима.
// Возвращает devices.id: это uuid, а CN серта им не является.
func armDevice(t *testing.T, db *storage.DB, cn, fingerprint, mode, requestID string) string {
	t.Helper()
	registerDevice(t, db, cn, fingerprint)
	devID, err := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err != nil || devID == "" {
		t.Fatalf("GetDeviceIDByFingerprint: %v (id=%q)", err, devID)
	}
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", "bcrypt-hash", "увольнение",
		mode, requestID); err != nil {
		t.Fatalf("SetDeviceLockState: %v", err)
	}
	return devID
}

func TestFetchLockSecrets_ArmedUnderActiveLock(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	certCtx, fp := makeCertCtx(t, "fv-armed")
	devID := armDevice(t, db, "fv-armed", fp, storage.LockModeFileVault, "req-1")

	v := &fakeVault{st: pb.ArmStatus_ARM_STATUS_ARMED, password: "pw", prk: "PRK"}
	gw.RegisterLockVault(v)

	resp, err := gw.FetchLockSecrets(certCtx, &pb.FetchLockSecretsRequest{RequestId: "req-1"})
	if err != nil {
		t.Fatalf("FetchLockSecrets: %v", err)
	}
	if resp.GetStatus() != pb.ArmStatus_ARM_STATUS_ARMED {
		t.Fatalf("status = %v, want ARMED", resp.GetStatus())
	}
	if resp.GetMdmadminPassword() != "pw" || resp.GetPersonalRecoveryKey() != "PRK" {
		t.Fatalf("секреты не доехали: %+v", resp)
	}
	if v.calls != 1 || v.lastDevice != devID || v.lastReq != "req-1" {
		t.Fatalf("vault дёрнут неверно: calls=%d device=%q req=%q", v.calls, v.lastDevice, v.lastReq)
	}
}

// 🔴 Ключевое свойство. Vault одноразовый и ничего не знает про ОТМЕНУ лока: снятый
// оператором лок оставил бы вооружение висеть до TTL. Если бы gateway шёл в vault не
// глядя на БД, агент в этом окне получил бы живой пароль mdmadmin под уже отменённую
// команду — а вооружение при этом сгорело бы впустую.
func TestFetchLockSecrets_LockCancelled_DoesNotTouchVault(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	certCtx, fp := makeCertCtx(t, "fv-cancelled")
	devID := armDevice(t, db, "fv-cancelled", fp, storage.LockModeFileVault, "req-1")

	// Оператор снял лок: desired сбрасывается, режим возвращается в overlay.
	if err := db.SetDeviceLockState(context.Background(), devID, "unlocked", "", "", "", ""); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	v := &fakeVault{st: pb.ArmStatus_ARM_STATUS_ARMED, password: "pw", prk: "PRK"}
	gw.RegisterLockVault(v)

	resp, err := gw.FetchLockSecrets(certCtx, &pb.FetchLockSecretsRequest{RequestId: "req-1"})
	if err != nil {
		t.Fatalf("FetchLockSecrets: %v", err)
	}
	if resp.GetStatus() != pb.ArmStatus_ARM_STATUS_NOT_ARMED {
		t.Fatalf("status = %v, want NOT_ARMED", resp.GetStatus())
	}
	if resp.GetMdmadminPassword() != "" || resp.GetPersonalRecoveryKey() != "" {
		t.Fatal("🔴 секрет выдан под отменённый лок")
	}
	if v.calls != 0 {
		t.Fatalf("vault дёрнут (%d раз) при отменённом локе — одноразовое вооружение сгорело бы впустую", v.calls)
	}
}

// Overlay-лок деструктива не несёт: секрет ему не нужен, vault не трогаем.
func TestFetchLockSecrets_OverlayLock_DoesNotTouchVault(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	certCtx, fp := makeCertCtx(t, "fv-overlay")
	armDevice(t, db, "fv-overlay", fp, storage.LockModeOverlay, "req-1")

	v := &fakeVault{st: pb.ArmStatus_ARM_STATUS_ARMED, password: "pw"}
	gw.RegisterLockVault(v)

	resp, err := gw.FetchLockSecrets(certCtx, &pb.FetchLockSecretsRequest{RequestId: "req-1"})
	if err != nil {
		t.Fatalf("FetchLockSecrets: %v", err)
	}
	if resp.GetStatus() != pb.ArmStatus_ARM_STATUS_NOT_ARMED || v.calls != 0 {
		t.Fatalf("status=%v calls=%d — overlay не должен доходить до vault", resp.GetStatus(), v.calls)
	}
}

// Устаревший лок-инстанс: агент держит id, который сервер уже перевыпустил. Гонка
// самозаживает на следующем тике, но СВЕЖЕЕ вооружение сливать нельзя.
func TestFetchLockSecrets_StaleRequestID_DoesNotTouchVault(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	certCtx, fp := makeCertCtx(t, "fv-stale")
	armDevice(t, db, "fv-stale", fp, storage.LockModeFileVault, "req-new")

	v := &fakeVault{st: pb.ArmStatus_ARM_STATUS_ARMED, password: "pw"}
	gw.RegisterLockVault(v)

	resp, err := gw.FetchLockSecrets(certCtx, &pb.FetchLockSecretsRequest{RequestId: "req-old"})
	if err != nil {
		t.Fatalf("FetchLockSecrets: %v", err)
	}
	if resp.GetStatus() != pb.ArmStatus_ARM_STATUS_REQUEST_MISMATCH {
		t.Fatalf("status = %v, want REQUEST_MISMATCH", resp.GetStatus())
	}
	if v.calls != 0 {
		t.Fatal("свежее вооружение слито устаревшим request_id")
	}
}

// Open-core: vault не зарегистрирован → Unimplemented, как EscrowRecoveryKey. Агент
// трактует транспортную ошибку как «спросить не удалось» и НЕ мутирует машину.
func TestFetchLockSecrets_FreeBuildUnimplemented(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	certCtx, fp := makeCertCtx(t, "fv-free")
	armDevice(t, db, "fv-free", fp, storage.LockModeFileVault, "req-1")

	_, err := gw.FetchLockSecrets(certCtx, &pb.FetchLockSecretsRequest{RequestId: "req-1"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented (err=%v)", status.Code(err), err)
	}
}

func lockActualState(t *testing.T, db *storage.DB, deviceID string) string {
	t.Helper()
	var s *string
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT lock_actual_state FROM devices WHERE id = $1`, deviceID).Scan(&s); err != nil {
		t.Fatalf("select lock_actual_state: %v", err)
	}
	if s == nil {
		return ""
	}
	return *s
}

func alertCount(t *testing.T, db *storage.DB, deviceID, alertType string) int {
	t.Helper()
	var n int
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM alerts WHERE device_id = $1 AND alert_type = $2`,
		deviceID, alertType).Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

// NOT_ARMED — шаг рабочего процесса, а не событие ИБ: actual-state и аудит есть,
// строки в alerts нет. desired при этом обязан уцелеть, иначе реконсиляция сняла бы
// лок, которого оператор не отменял.
func TestReportLockStatus_NotArmed_NoAlertRow(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	certCtx, fp := makeCertCtx(t, "fv-report-notarmed")
	devID := armDevice(t, db, "fv-report-notarmed", fp, storage.LockModeFileVault, "req-1")

	_, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		RequestId: "req-1",
		State:     pb.LockState_LOCK_STATE_FILEVAULT_NOT_ARMED,
		Details:   "ABORT ДО мутации: вооружения нет",
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if got := lockActualState(t, db, devID); got != "filevault_not_armed" {
		t.Fatalf("lock_actual_state = %q, want filevault_not_armed", got)
	}
	if n := alertCount(t, db, devID, "filevault_not_armed"); n != 0 {
		t.Fatalf("заведено %d строк alerts — NOT_ARMED не событие ИБ", n)
	}
	lockStatus, _, _, lockMode, _, err := db.GetDesiredLockState(context.Background(), devID)
	if err != nil {
		t.Fatalf("GetDesiredLockState: %v", err)
	}
	if lockStatus != "locked" || lockMode != storage.LockModeFileVault {
		t.Fatalf("desired затёрт отчётом: status=%q mode=%q", lockStatus, lockMode)
	}
}

// SECRET_MISMATCH — расхождение кастодии: помимо actual-state и аудита заводит строку
// в alerts, чтобы событие требовало подтверждения в панели, а не мигало в телеге.
// Повтор (агент напоминает раз в час) новой строки НЕ плодит — дедуп в CreateAlert.
func TestReportLockStatus_SecretMismatch_RaisesDedupedAlert(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	certCtx, fp := makeCertCtx(t, "fv-report-mismatch")
	devID := armDevice(t, db, "fv-report-mismatch", fp, storage.LockModeFileVault, "req-1")

	req := &pb.ReportLockStatusRequest{
		RequestId: "req-1",
		State:     pb.LockState_LOCK_STATE_FILEVAULT_SECRET_MISMATCH,
		Details:   "ABORT ДО мутации: секрет не совпал с заэскроенным (prk)",
	}
	if _, err := gw.ReportLockStatus(certCtx, req); err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if got := lockActualState(t, db, devID); got != "filevault_secret_mismatch" {
		t.Fatalf("lock_actual_state = %q, want filevault_secret_mismatch", got)
	}
	if n := alertCount(t, db, devID, "filevault_secret_mismatch"); n != 1 {
		t.Fatalf("строк alerts = %d, want 1", n)
	}

	if _, err := gw.ReportLockStatus(certCtx, req); err != nil {
		t.Fatalf("повторный ReportLockStatus: %v", err)
	}
	if n := alertCount(t, db, devID, "filevault_secret_mismatch"); n != 1 {
		t.Fatalf("часовой повтор расплодил строки: %d", n)
	}
}

// 🔴 Защита от понижения. Выдача вооружения одноразовая, поэтому после частичного
// ревока следующий тик реконсиляции ГАРАНТИРОВАННО пришлёт pre-mutation ABORT. Без
// durable-защиты он затёр бы filevault_revoke_failed, и полу-ревокнутая машина
// показалась бы в панели просто невооружённой — теряется единственное состояние,
// означающее начавшийся деструктив. Агент глушит это маркером, но маркер in-memory и
// не переживает рестарт агента, поэтому защита обязана быть здесь.
func TestReportLockStatus_PreMutationAbort_DoesNotDowngradeRevokeFailed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state pb.LockState
	}{
		{"NOT_ARMED", pb.LockState_LOCK_STATE_FILEVAULT_NOT_ARMED},
		{"SECRET_MISMATCH", pb.LockState_LOCK_STATE_FILEVAULT_SECRET_MISMATCH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			gw := newGW(t, db)
			cn := "fv-downgrade-" + tc.name
			certCtx, fp := makeCertCtx(t, cn)
			devID := armDevice(t, db, cn, fp, storage.LockModeFileVault, "req-1")

			// Деструктив начался и не завершился.
			if _, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
				RequestId: "req-1",
				State:     pb.LockState_LOCK_STATE_FILEVAULT_REVOKE_FAILED,
				Details:   "токен снят у части владельцев",
			}); err != nil {
				t.Fatalf("REVOKE_FAILED: %v", err)
			}
			if got := lockActualState(t, db, devID); got != "filevault_revoke_failed" {
				t.Fatalf("подготовка не удалась: actual=%q", got)
			}

			// Рестарт агента потерял маркер — прилетает pre-mutation ABORT.
			if _, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
				RequestId: "req-1",
				State:     tc.state,
				Details:   "ABORT до мутации",
			}); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if got := lockActualState(t, db, devID); got != "filevault_revoke_failed" {
				t.Fatalf("🔴 %s понизил actual_state до %q — начавшийся деструктив потерян", tc.name, got)
			}
		})
	}
}

// FILEVAULT_REVOKE_FAILED заводит строку в панели ИБ (раньше был только телеграм и
// аудит), и часовые повторы её не плодят — дедуп внутри CreateAlert.
func TestReportLockStatus_RevokeFailed_RaisesDedupedAlert(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	certCtx, fp := makeCertCtx(t, "fv-revokefailed-alert")
	devID := armDevice(t, db, "fv-revokefailed-alert", fp, storage.LockModeFileVault, "req-1")

	req := &pb.ReportLockStatusRequest{
		RequestId: "req-1",
		State:     pb.LockState_LOCK_STATE_FILEVAULT_REVOKE_FAILED,
		Details:   "partial revoke: mdmadmin остался, сотрудник отозван",
	}
	for i := 0; i < 2; i++ {
		if _, err := gw.ReportLockStatus(certCtx, req); err != nil {
			t.Fatalf("ReportLockStatus #%d: %v", i+1, err)
		}
	}
	if n := alertCount(t, db, devID, "filevault_revoke_failed"); n != 1 {
		t.Fatalf("строк alerts = %d, want 1 (повтор не должен плодить)", n)
	}
}
