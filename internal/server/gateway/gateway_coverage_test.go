package gateway_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	pb "github.com/Floodww/RoutineOps/proto"
	"github.com/jackc/pgx/v5/pgxpool"
)

// updateAdminRequestStatus forcibly sets status on an admin access request via
// direct SQL. FetchActiveAdminRequest only returns pending/approved rows, so
// the only way to exercise approved status through FetchAdminStatus is to seed
// an approved row directly.
func updateAdminRequestStatus(t *testing.T, requestID, newStatus string) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("updateAdminRequestStatus pool: %v", err)
	}
	defer pool.Close()
	_, err = pool.Exec(context.Background(),
		`UPDATE admin_access_requests SET status = $2 WHERE id = $1`, requestID, newStatus)
	if err != nil {
		t.Fatalf("updateAdminRequestStatus: %v", err)
	}
}

// ── FetchAdminStatus with active requests ─────────────────────────────────────

func TestFetchAdminStatus_PendingRequest(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := context.Background()

	owner, err := db.CreateUser(ctx, "Owner", uniqEmail("owner_pending"), "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	certCtx, fingerprint := makeCertCtx(t, "device-status-pending")
	registerDevice(t, db, "device-status-pending", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fingerprint)
	setDeviceOwner(t, devID, owner.ID)

	now := time.Now()
	row, err := db.CreateAdminAccessRequest(ctx, devID, owner.ID, "need access", now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}

	resp, err := gw.FetchAdminStatus(certCtx, &pb.FetchAdminStatusRequest{})
	if err != nil {
		t.Fatalf("FetchAdminStatus: %v", err)
	}
	if resp.RequestId != row.ID {
		t.Errorf("RequestId = %q, want %q", resp.RequestId, row.ID)
	}
	if resp.Status != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_PENDING {
		t.Errorf("Status = %v, want PENDING", resp.Status)
	}
}

func TestFetchAdminStatus_ApprovedRequest(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := context.Background()

	owner, err := db.CreateUser(ctx, "Owner", uniqEmail("owner_approved"), "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	certCtx, fingerprint := makeCertCtx(t, "device-status-approved")
	registerDevice(t, db, "device-status-approved", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fingerprint)
	setDeviceOwner(t, devID, owner.ID)

	now := time.Now()
	row, err := db.CreateAdminAccessRequest(ctx, devID, owner.ID, "approved reason", now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}
	updateAdminRequestStatus(t, row.ID, "approved")

	resp, err := gw.FetchAdminStatus(certCtx, &pb.FetchAdminStatusRequest{})
	if err != nil {
		t.Fatalf("FetchAdminStatus: %v", err)
	}
	if resp.Status != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED {
		t.Errorf("Status = %v, want APPROVED", resp.Status)
	}
}

// TestFetchAdminStatus_ApprovedWithTimestamps покрывает ветки
// row.GrantedAt != nil и row.ExpiresAt != nil в FetchAdminStatus.
func TestFetchAdminStatus_ApprovedWithTimestamps(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "Admin", uniqEmail("admin_ts"), "hash", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser admin: %v", err)
	}
	owner, err := db.CreateUser(ctx, "Owner", uniqEmail("owner_ts"), "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser owner: %v", err)
	}
	certCtx, fingerprint := makeCertCtx(t, "device-status-timestamps")
	registerDevice(t, db, "device-status-timestamps", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fingerprint)
	setDeviceOwner(t, devID, owner.ID)

	now := time.Now()
	row, err := db.CreateAdminAccessRequest(ctx, devID, owner.ID, "ts reason", now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}

	// IT-админ одобряет заявку — устанавливает expires_at
	expiresAt := now.Add(30 * time.Minute)
	if err := db.RespondToAdminRequest(ctx, row.ID, "approved", admin.ID, &expiresAt); err != nil {
		t.Fatalf("RespondToAdminRequest: %v", err)
	}
	// Агент рапортует об активации — устанавливает granted_at
	if err := db.UpdateAdminAccessReport(ctx, row.ID, devID, "approved", now); err != nil {
		t.Fatalf("UpdateAdminAccessReport: %v", err)
	}

	resp, err := gw.FetchAdminStatus(certCtx, &pb.FetchAdminStatusRequest{})
	if err != nil {
		t.Fatalf("FetchAdminStatus: %v", err)
	}
	if resp.GrantedAt == 0 {
		t.Error("GrantedAt not set, want non-zero")
	}
	if resp.ExpiresAt == 0 {
		t.Error("ExpiresAt not set, want non-zero")
	}
}

// ── RequestAdminAccess ────────────────────────────────────────────────────────

// TestRequestAdminAccess_CustomRequestedAt покрывает ветку req.RequestedAt != 0.
func TestRequestAdminAccess_CustomRequestedAt(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := context.Background()

	owner, err := db.CreateUser(ctx, "Owner", uniqEmail("owner_reqat"), "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	certCtx, fingerprint := makeCertCtx(t, "device-reqat")
	registerDevice(t, db, "device-reqat", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fingerprint)
	setDeviceOwner(t, devID, owner.ID)

	customTS := time.Now().Add(-5 * time.Minute).Unix()
	resp, err := gw.RequestAdminAccess(certCtx, &pb.RequestAdminAccessRequest{
		Reason:      "custom timestamp",
		RequestedAt: customTS,
	})
	if err != nil {
		t.Fatalf("RequestAdminAccess: %v", err)
	}
	if resp.RequestId == "" {
		t.Error("expected non-empty RequestId")
	}
	if resp.Status != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_PENDING {
		t.Errorf("Status = %v, want PENDING", resp.Status)
	}
}

// ── ReportAdminAccess ─────────────────────────────────────────────────────────

// TestReportAdminAccess_Revoked покрывает ветку status=REVOKED в ReportAdminAccess.
func TestReportAdminAccess_Revoked(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := context.Background()

	owner, err := db.CreateUser(ctx, "Owner", uniqEmail("owner_revoke"), "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	certCtx, fingerprint := makeCertCtx(t, "device-revoke")
	registerDevice(t, db, "device-revoke", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fingerprint)
	setDeviceOwner(t, devID, owner.ID)

	now := time.Now()
	row, err := db.CreateAdminAccessRequest(ctx, devID, owner.ID, "to revoke", now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}
	updateAdminRequestStatus(t, row.ID, "approved")

	resp, err := gw.ReportAdminAccess(certCtx, &pb.ReportAdminAccessRequest{
		RequestId: row.ID,
		Status:    pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED,
	})
	if err != nil {
		t.Fatalf("ReportAdminAccess: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}
}

// ── AckTaskReceived error path ────────────────────────────────────────────────

// AckTask passes taskID straight to a UUID column. A non-UUID value causes
// a PostgreSQL cast error, which exercises the error branch (Acknowledged=false).
func TestAckTaskReceived_InvalidTaskID(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	certCtx, fingerprint := makeCertCtx(t, "device-ack-invalid")
	registerDevice(t, db, "device-ack-invalid", fingerprint)

	resp, err := gw.AckTaskReceived(certCtx, &pb.TaskReceivedAck{TaskId: "not-a-uuid"})
	if err != nil {
		t.Fatalf("AckTaskReceived returned unexpected error: %v", err)
	}
	if resp.Acknowledged {
		t.Error("expected Acknowledged=false for invalid task ID")
	}
}

// ── Bot Notifications ─────────────────────────────────────────────────────────

func TestReportSecurityEvent_BotNotified(t *testing.T) {
	db := newDB(t)
	mock := newMockNotifier()
	gw := newGWWithBot(t, db, mock)

	certCtx, fingerprint := makeCertCtx(t, "device-sec-notify")
	registerDevice(t, db, "device-sec-notify", fingerprint)

	_, err := gw.ReportSecurityEvent(certCtx, &pb.SecurityEvent{
		AlertType: pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE,
		Details:   "found bad app",
	})
	if err != nil {
		t.Fatalf("ReportSecurityEvent: %v", err)
	}

	select {
	case <-mock.notified:
		// success
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for bot notification")
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.Messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(mock.Messages))
	} else if !strings.Contains(mock.Messages[0], "device-sec-notify") {
		t.Errorf("expected message to contain hostname, got: %s", mock.Messages[0])
	}
}

func TestRequestAdminAccess_BotNotified(t *testing.T) {
	db := newDB(t)
	mock := newMockNotifier()
	gw := newGWWithBot(t, db, mock)
	ctx := context.Background()

	owner, err := db.CreateUser(ctx, "Owner", uniqEmail("owner_notify"), "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	certCtx, fingerprint := makeCertCtx(t, "device-admin-notify")
	registerDevice(t, db, "device-admin-notify", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fingerprint)
	setDeviceOwner(t, devID, owner.ID)

	_, err = gw.RequestAdminAccess(certCtx, &pb.RequestAdminAccessRequest{
		Reason: "тест уведомления",
	})
	if err != nil {
		t.Fatalf("RequestAdminAccess: %v", err)
	}

	select {
	case <-mock.notified:
		// success
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for bot notification")
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.Messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(mock.Messages))
	}
}

func TestReportSecurityEvent_NoBotConfigured(t *testing.T) {
	db := newDB(t)
	gw := newGWWithBot(t, db, nil) // bot = nil

	certCtx, fingerprint := makeCertCtx(t, "device-sec-nobot")
	registerDevice(t, db, "device-sec-nobot", fingerprint)

	resp, err := gw.ReportSecurityEvent(certCtx, &pb.SecurityEvent{
		AlertType: pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE,
		Details:   "found bad app",
	})
	if err != nil {
		t.Fatalf("ReportSecurityEvent: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}
}

func TestRequestAdminAccess_NoBotConfigured(t *testing.T) {
	db := newDB(t)
	gw := newGWWithBot(t, db, nil) // bot = nil
	ctx := context.Background()

	owner, err := db.CreateUser(ctx, "Owner", uniqEmail("owner_nobot"), "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	certCtx, fingerprint := makeCertCtx(t, "device-admin-nobot")
	registerDevice(t, db, "device-admin-nobot", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fingerprint)
	setDeviceOwner(t, devID, owner.ID)

	resp, err := gw.RequestAdminAccess(certCtx, &pb.RequestAdminAccessRequest{
		Reason: "тест без бота",
	})
	if err != nil {
		t.Fatalf("RequestAdminAccess: %v", err)
	}
	if resp.RequestId == "" {
		t.Error("expected RequestId to be populated")
	}
}

// gwLockHash — непустой bcrypt-хеш desired-лока. Агентский отчёт LOCKED лишь
// ПОДТВЕРЖДАЕТ намерение IT, выставленное lock-эндпоинтом, и без него не применяется
// (storage.ErrNoDesiredLock) — тесты обязаны воспроизводить этот порядок.
const gwLockHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

func TestReportLockStatus_Locked(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "lock-agent")
	registerDevice(t, db, "lock-agent", fingerprint)
	gw := newGW(t, db)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", gwLockHash, "test", storage.LockModeOverlay, "lock-task-1"); err != nil {
		t.Fatalf("seed desired lock: %v", err)
	}

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		State:      pb.LockState_LOCK_STATE_LOCKED,
		OccurredAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}

	dev, _, _ := db.GetDevice(context.Background(), devID)
	if dev.LockStatus != "locked" {
		t.Errorf("LockStatus = %q, want locked", dev.LockStatus)
	}
}

// Устаревший LOCKED из durable-outbox агента, доехавший ПОСЛЕ снятия, не должен
// воскрешать desired: unlock вычистил lock_hash, и 'locked' без хеша — команда,
// которую агент выполнить не может, то есть устройство навсегда числилось бы
// заблокированным в панели, оставаясь рабочим. Отчёт при этом ПРИНИМАЕТСЯ
// (Received=true, агент не должен ретраить вечно) и зеркалится в actual —
// расхождение desired=unlocked / actual=locked обязано быть видимым.
func TestReportLockStatus_StaleLockedAfterUnlock_DesiredUntouched(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "stale-lock-agent")
	registerDevice(t, db, "stale-lock-agent", fingerprint)
	gw := newGW(t, db)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	ctx := context.Background()
	if err := db.SetDeviceLockState(ctx, devID, "locked", gwLockHash, "test", storage.LockModeOverlay, "lock-task-1"); err != nil {
		t.Fatalf("seed desired lock: %v", err)
	}
	if err := db.SetDeviceLockState(ctx, devID, "unlocked", "", "", storage.LockModeOverlay, ""); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		State:      pb.LockState_LOCK_STATE_LOCKED,
		OccurredAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true (иначе агент ретраит устаревший отчёт вечно)")
	}

	dev, _, _ := db.GetDevice(ctx, devID)
	if dev.LockStatus != "unlocked" {
		t.Errorf("LockStatus = %q, want unlocked — устаревший LOCKED воскресил desired", dev.LockStatus)
	}
	if state, _ := readLockActual(t, devID); state != "locked" {
		t.Errorf("actual = %q, want locked — расхождение должно быть видно оператору", state)
	}
}

// Устаревший UNLOCKED из durable-outbox агента, доехавший ПОСЛЕ выдачи НОВОЙ
// блокировки, не должен стирать её желаемое состояние: ноутбук, вернувшийся из
// офлайна, молча разоружал бы свежий kill-switch. Отчёт при этом принимается
// (Received=true — иначе агент ретраит вечно) и зеркалится в actual.
//
// Вторая половина теста не менее важна: гард обязан пропускать снятие ТЕКУЩЕГО
// лока обоими путями — по id lock-задачи (push) и по lock_hash (pull-реконсиляция).
func TestReportLockStatus_StaleUnlockedAfterRelock_DesiredKept(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "stale-unlock-agent")
	registerDevice(t, db, "stale-unlock-agent", fingerprint)
	gw := newGW(t, db)
	ctx := context.Background()
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fingerprint)

	report := func(reqID string) {
		t.Helper()
		resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
			RequestId:  reqID,
			State:      pb.LockState_LOCK_STATE_UNLOCKED,
			OccurredAt: time.Now().Unix(),
		})
		if err != nil {
			t.Fatalf("ReportLockStatus(%s): %v", reqID, err)
		}
		if !resp.Received {
			t.Errorf("Received=false для %s — агент будет ретраить вечно", reqID)
		}
	}
	desiredStatus := func() string {
		t.Helper()
		st, _, _, _, _, err := db.GetDesiredLockState(ctx, devID)
		if err != nil {
			t.Fatalf("GetDesiredLockState: %v", err)
		}
		return st
	}
	seedLock := func(reqID string) {
		t.Helper()
		if err := db.SetDeviceLockState(ctx, devID, "locked", gwLockHash, "повторная блокировка", storage.LockModeOverlay, reqID); err != nil {
			t.Fatalf("seed desired lock: %v", err)
		}
	}

	// Лок №1 сняли офлайн, отчёт лёг в outbox. Пока машина была офлайн, IT выдал
	// лок №2 другим паролем — и только теперь доезжает снятие ПЕРВОГО.
	seedLock("lock-task-2")
	report("lock-task-1")
	if got := desiredStatus(); got != "locked" {
		t.Errorf("desired = %q, want locked — устаревший UNLOCKED разоружил свежий лок", got)
	}
	if state, _ := readLockActual(t, devID); state != "unlocked" {
		t.Errorf("actual = %q, want unlocked — расхождение должно быть видно оператору", state)
	}

	// Снятие ТЕКУЩЕГО лока по id задачи (push-путь) проходит.
	report("lock-task-2")
	if got := desiredStatus(); got != "unlocked" {
		t.Errorf("desired = %q, want unlocked — гард отверг снятие текущего лока (push)", got)
	}

	// И по lock_hash (pull-путь: лок применён реконсиляцией, агент представляется хешем).
	seedLock("lock-task-3")
	report(gwLockHash)
	if got := desiredStatus(); got != "unlocked" {
		t.Errorf("desired = %q, want unlocked — гард отверг снятие текущего лока (pull)", got)
	}
}

func TestReportLockStatus_Unlocked(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "unlock-agent")
	registerDevice(t, db, "unlock-agent", fingerprint)
	gw := newGW(t, db)

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		State:      pb.LockState_LOCK_STATE_UNLOCKED,
		OccurredAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	dev, _, _ := db.GetDevice(context.Background(), devID)
	if dev.LockStatus != "unlocked" {
		t.Errorf("LockStatus = %q, want unlocked", dev.LockStatus)
	}
}

// readLockActual читает REPORTED состояние лока прямым SQL (публичного геттера
// нет намеренно — UI-wiring это отдельный отложенный кусок).
func readLockActual(t *testing.T, deviceID string) (state string, atSet bool) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("readLockActual pool: %v", err)
	}
	defer pool.Close()
	var at *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT lock_actual_state, lock_actual_at FROM devices WHERE id = $1`, deviceID).
		Scan(&state, &at); err != nil {
		t.Fatalf("readLockActual: %v", err)
	}
	return state, at != nil
}

// state=3 (FILEVAULT_REVOKED) — half-state деструктива: actual пишется, desired
// НЕ трогается (иначе агент молча самоотменил бы собственный деструктивный лок),
// аудит и алерт админам уходят.
func TestReportLockStatus_FilevaultRevoked_ActualOnly(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "fv-revoked-agent")
	registerDevice(t, db, "fv-revoked-agent", fingerprint)
	bot := newMockNotifier()
	gw := newGWWithBot(t, db, bot)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", "hash-fv", "утеря устройства", "filevault", "lock-task-fv"); err != nil {
		t.Fatalf("seed desired: %v", err)
	}

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		RequestId:  "fv-req-1",
		State:      pb.LockState_LOCK_STATE_FILEVAULT_REVOKED,
		OccurredAt: time.Now().Unix(),
		Details:    "secure token revoked, reboot pending",
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}

	// desired ЦЕЛ: статус/хеш/причина не тронуты.
	lockStatus, lockHash, lockReason, _, _, err := db.GetDesiredLockState(context.Background(), devID)
	if err != nil {
		t.Fatalf("GetDesiredLockState: %v", err)
	}
	if lockStatus != "locked" || lockHash != "hash-fv" || lockReason != "утеря устройства" {
		t.Errorf("desired corrupted: status=%q hash=%q reason=%q", lockStatus, lockHash, lockReason)
	}
	// actual записан.
	state, atSet := readLockActual(t, devID)
	if state != "filevault_revoked" || !atSet {
		t.Errorf("actual = (%q, at set=%v), want (filevault_revoked, true)", state, atSet)
	}
	// Аудит есть (общая БД — фильтруем по target_id).
	entries, _, err := db.ListAuditLog(context.Background(), storage.AuditFilter{Action: "filevault_revoked"}, 100, 0)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.TargetID == devID {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit entry filevault_revoked for device not found")
	}
	// Алерт админам ушёл (notify асинхронный — ждём канал).
	select {
	case <-bot.notified:
	case <-time.After(2 * time.Second):
		t.Error("NotifyITAdmins was not called")
	}
}

// state=0 (UNSPECIFIED) — ни один живой агент его не шлёт; раньше падал в ветку
// "unlocked" и стирал desired hash/reason. Теперь принять-и-дропнуть.
func TestReportLockStatus_Unspecified_Dropped(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "unspec-agent")
	registerDevice(t, db, "unspec-agent", fingerprint)
	gw := newGW(t, db)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", "hash-u", "лок", "overlay", "lock-task-seed"); err != nil {
		t.Fatalf("seed desired: %v", err)
	}

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		State:      pb.LockState_LOCK_STATE_UNSPECIFIED,
		OccurredAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true (accept-and-drop)")
	}
	lockStatus, lockHash, _, _, _, err := db.GetDesiredLockState(context.Background(), devID)
	if err != nil {
		t.Fatalf("GetDesiredLockState: %v", err)
	}
	if lockStatus != "locked" || lockHash != "hash-u" {
		t.Errorf("desired corrupted by UNSPECIFIED: status=%q hash=%q", lockStatus, lockHash)
	}
	if state, _ := readLockActual(t, devID); state != "" {
		t.Errorf("actual polluted by UNSPECIFIED: %q", state)
	}
}

// Неизвестный/будущий enum (напр. ещё не занятый 6) — accept-and-drop как
// UNSPECIFIED; НЕ маппится в "unlocked" и НЕ стирает desired (форвард-компат:
// иначе новый агент, эмитящий будущий enum, самоотменил бы лок против старого
// сервера). NB: 4 = FILEVAULT_REVOKE_FAILED и 5 = LOCK_FAILED — ТЕПЕРЬ реальные
// state'ы, у каждого своя ветка+тест; здесь берём следующий свободный 6.
func TestReportLockStatus_UnknownState_Dropped(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "unknown-state-agent")
	registerDevice(t, db, "unknown-state-agent", fingerprint)
	gw := newGW(t, db)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", "hash-x", "лок", "overlay", "lock-task-seed"); err != nil {
		t.Fatalf("seed desired: %v", err)
	}

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		State:      pb.LockState(6), // не занят в прото, живой агент не шлёт
		OccurredAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true (accept-and-drop)")
	}
	lockStatus, lockHash, _, _, _, err := db.GetDesiredLockState(context.Background(), devID)
	if err != nil {
		t.Fatalf("GetDesiredLockState: %v", err)
	}
	if lockStatus != "locked" || lockHash != "hash-x" {
		t.Errorf("desired corrupted by unknown state: status=%q hash=%q", lockStatus, lockHash)
	}
	if state, _ := readLockActual(t, devID); state != "" {
		t.Errorf("actual polluted by unknown state: %q", state)
	}
}

// state=4 (FILEVAULT_REVOKE_FAILED) — незавершённый деструктив:
// actual=filevault_revoke_failed, desired НЕ трогается, аудит + алерт IT уходят.
// Раньше этот отчёт слался UNSPECIFIED и молча дропался (IT не узнавал о полу-локе).
func TestReportLockStatus_FilevaultRevokeFailed_AuditedAndAlerted(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "fv-failed-agent")
	registerDevice(t, db, "fv-failed-agent", fingerprint)
	bot := newMockNotifier()
	gw := newGWWithBot(t, db, bot)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", "hash-fv", "утеря устройства", "filevault", "lock-task-seed"); err != nil {
		t.Fatalf("seed desired: %v", err)
	}

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		RequestId:  "fv-fail-1",
		State:      pb.LockState_LOCK_STATE_FILEVAULT_REVOKE_FAILED,
		OccurredAt: time.Now().Unix(),
		Details:    "PARTIAL REVOKE (требует ручного разбора IT), уже отозвано у [emp]",
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}

	// desired ЦЕЛ (как и для FILEVAULT_REVOKED) — иначе агент самоотменил бы лок.
	lockStatus, lockHash, lockReason, lockMode, _, err := db.GetDesiredLockState(context.Background(), devID)
	if err != nil {
		t.Fatalf("GetDesiredLockState: %v", err)
	}
	if lockStatus != "locked" || lockHash != "hash-fv" || lockReason != "утеря устройства" || lockMode != "filevault" {
		t.Errorf("desired corrupted: status=%q hash=%q reason=%q mode=%q", lockStatus, lockHash, lockReason, lockMode)
	}
	// actual = filevault_revoke_failed.
	state, atSet := readLockActual(t, devID)
	if state != "filevault_revoke_failed" || !atSet {
		t.Errorf("actual = (%q, at set=%v), want (filevault_revoke_failed, true)", state, atSet)
	}
	// Аудит есть.
	entries, _, err := db.ListAuditLog(context.Background(), storage.AuditFilter{Action: "filevault_revoke_failed"}, 100, 0)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.TargetID == devID {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit entry filevault_revoke_failed for device not found")
	}
	// Алерт админам ушёл.
	select {
	case <-bot.notified:
	case <-time.After(2 * time.Second):
		t.Error("NotifyITAdmins was not called for revoke-failed")
	}
}

// state=5 (LOCK_FAILED) — лок НЕ применился на устройстве: actual=lock_failed,
// desired НЕ трогается, аудит + алерт IT уходят. Смысл ветки: без неё панель
// показывает «заблокировано», машина при этом полностью рабочая, и расхождение
// не видно оператору вообще (известное ограничение 2.4.6).
func TestReportLockStatus_LockFailed_AuditedAndAlerted(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "lock-failed-agent")
	registerDevice(t, db, "lock-failed-agent", fingerprint)
	bot := newMockNotifier()
	gw := newGWWithBot(t, db, bot)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", "hash-ov", "утеря устройства", "overlay", "lock-task-seed"); err != nil {
		t.Fatalf("seed desired: %v", err)
	}

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		RequestId:  "lock-fail-1",
		State:      pb.LockState_LOCK_STATE_LOCK_FAILED,
		OccurredAt: time.Now().Unix(),
		Details:    "overlay не поднялся: CreateWindowEx failed",
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}

	// desired ЦЕЛ: временный локальный сбой на устройстве НЕ снимает выданный лок.
	lockStatus, lockHash, lockReason, lockMode, _, err := db.GetDesiredLockState(context.Background(), devID)
	if err != nil {
		t.Fatalf("GetDesiredLockState: %v", err)
	}
	if lockStatus != "locked" || lockHash != "hash-ov" || lockReason != "утеря устройства" || lockMode != "overlay" {
		t.Errorf("desired corrupted: status=%q hash=%q reason=%q mode=%q", lockStatus, lockHash, lockReason, lockMode)
	}
	state, atSet := readLockActual(t, devID)
	if state != "lock_failed" || !atSet {
		t.Errorf("actual = (%q, at set=%v), want (lock_failed, true)", state, atSet)
	}
	entries, _, err := db.ListAuditLog(context.Background(), storage.AuditFilter{Action: "lock_failed"}, 100, 0)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.TargetID == devID {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit entry lock_failed for device not found")
	}
	select {
	case <-bot.notified:
	case <-time.After(2 * time.Second):
		t.Error("NotifyITAdmins was not called for lock-failed")
	}
}

// H2: устаревший/дубликатный overlay-UNLOCKED НЕ должен отменять
// desired FILEVAULT-лок. Агент никогда не шлёт UNLOCKED для filevault; такой отчёт
// (напр. поздний флаш outbox от прежнего overlay-снятия) обязан игнорироваться,
// иначе offboarding-лок самоотменился бы до выполнения revoke.
func TestReportLockStatus_Unlocked_IgnoredWhenFilevaultDesired(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "fv-unlock-guard-agent")
	registerDevice(t, db, "fv-unlock-guard-agent", fingerprint)
	gw := newGW(t, db)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", "hash-fv", "увольнение", "filevault", "lock-task-fv"); err != nil {
		t.Fatalf("seed desired: %v", err)
	}

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		RequestId:  "stale-overlay-unlock",
		State:      pb.LockState_LOCK_STATE_UNLOCKED,
		OccurredAt: time.Now().Unix(),
		Details:    "offline unlock",
	})
	if err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true (accept-and-ignore)")
	}

	// desired FILEVAULT-лок ЦЕЛ: не понижен в unlocked/overlay.
	lockStatus, lockHash, _, lockMode, _, err := db.GetDesiredLockState(context.Background(), devID)
	if err != nil {
		t.Fatalf("GetDesiredLockState: %v", err)
	}
	if lockStatus != "locked" || lockHash != "hash-fv" || lockMode != "filevault" {
		t.Errorf("FILEVAULT desired cancelled by stale UNLOCKED: status=%q hash=%q mode=%q", lockStatus, lockHash, lockMode)
	}
}

// FetchLockStatus отдаёт агенту lock_mode: filevault-лок доедет как FILEVAULT
// (без wiring деградировал бы в overlay). target_users пусто (advisory).
func TestFetchLockStatus_FileVaultMode(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "fv-fetch-agent")
	registerDevice(t, db, "fv-fetch-agent", fingerprint)
	gw := newGW(t, db)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", "hash-fv", "утеря", "filevault", "lock-task-seed"); err != nil {
		t.Fatalf("seed desired: %v", err)
	}
	resp, err := gw.FetchLockStatus(certCtx, &pb.FetchLockStatusRequest{})
	if err != nil {
		t.Fatalf("FetchLockStatus: %v", err)
	}
	if !resp.Locked || resp.LockMode != pb.LockMode_LOCK_MODE_FILEVAULT {
		t.Fatalf("locked=%v mode=%v, want locked + FILEVAULT", resp.Locked, resp.LockMode)
	}
	if len(resp.FilevaultTargetUsers) != 0 {
		t.Errorf("target_users=%v, want empty (advisory)", resp.FilevaultTargetUsers)
	}
}

// Дефолт/overlay-лок отдаётся как OVERLAY (fail-safe): пустой lock_mode в БД →
// overlay, никогда не FILEVAULT.
func TestFetchLockStatus_OverlayDefault(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "ov-fetch-agent")
	registerDevice(t, db, "ov-fetch-agent", fingerprint)
	gw := newGW(t, db)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockState(context.Background(), devID, "locked", "hash-ov", "лок", "overlay", "lock-task-seed"); err != nil {
		t.Fatalf("seed desired: %v", err)
	}
	resp, err := gw.FetchLockStatus(certCtx, &pb.FetchLockStatusRequest{})
	if err != nil {
		t.Fatalf("FetchLockStatus: %v", err)
	}
	if resp.LockMode != pb.LockMode_LOCK_MODE_OVERLAY {
		t.Fatalf("mode=%v, want OVERLAY", resp.LockMode)
	}
}

// Терминальные состояния зеркалятся в actual: LOCKED после ребута = FILEVAULT
// подтверждён, actual перестаёт висеть в filevault_revoked.
func TestReportLockStatus_Locked_MirrorsActual(t *testing.T) {
	db := newDB(t)
	certCtx, fingerprint := makeCertCtx(t, "lock-actual-agent")
	registerDevice(t, db, "lock-actual-agent", fingerprint)
	gw := newGW(t, db)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err := db.SetDeviceLockActualState(context.Background(), devID, "filevault_revoked"); err != nil {
		t.Fatalf("seed actual: %v", err)
	}

	if _, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		State:      pb.LockState_LOCK_STATE_LOCKED,
		OccurredAt: time.Now().Unix(),
	}); err != nil {
		t.Fatalf("ReportLockStatus: %v", err)
	}
	if state, atSet := readLockActual(t, devID); state != "locked" || !atSet {
		t.Errorf("actual = (%q, at set=%v), want (locked, true)", state, atSet)
	}
}

func TestReportLockStatus_UnknownDevice_AcceptAndDrop(t *testing.T) {
	db := newDB(t)
	certCtx, _ := makeCertCtx(t, "unknown-agent")
	gw := newGW(t, db)

	resp, err := gw.ReportLockStatus(certCtx, &pb.ReportLockStatusRequest{
		State:      pb.LockState_LOCK_STATE_LOCKED,
		OccurredAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("ReportLockStatus returned error: %v", err)
	}
	// Неизвестное устройство → accept-and-drop (Received=true), иначе агент ретраит
	// призрак вечно (6d4a660).
	if !resp.Received {
		t.Error("expected Received=true (accept-and-drop) for unknown device")
	}
}
