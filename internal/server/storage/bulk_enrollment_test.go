package storage_test

import (
	"errors"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

func bulkToken(t *testing.T, db *storage.DB, groupID string, maxUses *int, requireApproval bool, ttl time.Duration) *storage.EnrollmentToken {
	t.Helper()
	ctx := tenantCtx()
	token := "bulk-" + uniq(t)
	if err := db.CreateBulkEnrollmentToken(ctx, tenancy.DefaultTenantID, token, groupID, maxUses, requireApproval, time.Now().Add(ttl)); err != nil {
		t.Fatalf("CreateBulkEnrollmentToken: %v", err)
	}
	tok, err := db.GetEnrollmentToken(ctx, token)
	if err != nil || tok == nil {
		t.Fatalf("GetEnrollmentToken: %v (nil=%v)", err, tok == nil)
	}
	return tok
}

func TestBulkEnroll_FullFlow_PendingApproval(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	tok := bulkToken(t, db, "", nil, true, time.Hour)
	if tok.DeviceID != "" {
		t.Errorf("bulk-токен DeviceID = %q, want пусто", tok.DeviceID)
	}
	if !tok.RequireApproval {
		t.Errorf("RequireApproval = false, want true")
	}

	devID, requireApproval, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "bulk-host-1", "windows")
	if err != nil {
		t.Fatalf("BeginBulkEnroll: %v", err)
	}
	if !requireApproval {
		t.Errorf("requireApproval = false, want true")
	}
	if err := db.FinalizeBulkEnroll(ctx, tenancy.DefaultTenantID, devID, "serial-1", "fp-bulk-"+uniq(t), true); err != nil {
		t.Fatalf("FinalizeBulkEnroll: %v", err)
	}
	if st, _ := db.GetDeviceStatusByID(ctx, tenancy.DefaultTenantID, devID); st != "pending_approval" {
		t.Errorf("status = %q, want pending_approval", st)
	}
	// (инкремент uses покрыт TestBulkEnroll_MaxUsesLimit — без него лимит бы не сработал)
}

func TestBulkEnroll_NoApproval_GoesEnrolled(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	tok := bulkToken(t, db, "", nil, false, time.Hour)

	devID, requireApproval, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "auto-host", "linux")
	if err != nil {
		t.Fatalf("BeginBulkEnroll: %v", err)
	}
	if requireApproval {
		t.Errorf("requireApproval = true, want false (auto-join)")
	}
	if err := db.FinalizeBulkEnroll(ctx, tenancy.DefaultTenantID, devID, "s", "fp-auto-"+uniq(t), requireApproval); err != nil {
		t.Fatalf("FinalizeBulkEnroll: %v", err)
	}
	if st, _ := db.GetDeviceStatusByID(ctx, tenancy.DefaultTenantID, devID); st != "enrolled" {
		t.Errorf("status = %q, want enrolled (heartbeat поднимет в active)", st)
	}
}

func TestBulkEnroll_MaxUsesLimit(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	max := 2
	tok := bulkToken(t, db, "", &max, true, time.Hour)

	for i := 0; i < 2; i++ {
		if _, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, fmt.Sprintf("lim-h%d", i), "linux"); err != nil {
			t.Fatalf("BeginBulkEnroll #%d: %v", i, err)
		}
	}
	// третье использование — лимит исчерпан
	if _, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "lim-h3", "linux"); !errors.Is(err, storage.ErrEnrollTokenAlreadyUsed) {
		t.Errorf("3-е использование: err = %v, want ErrEnrollTokenAlreadyUsed", err)
	}
}

func TestBulkEnroll_Expired(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	tok := bulkToken(t, db, "", nil, true, -time.Hour) // истёк

	if _, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "exp-h", "linux"); !errors.Is(err, storage.ErrEnrollTokenAlreadyUsed) {
		t.Errorf("истёкший токен: err = %v, want ErrEnrollTokenAlreadyUsed", err)
	}
}

func TestBulkEnroll_GroupAssignment(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	group, err := db.CreateDeviceGroup(ctx, tenancy.DefaultTenantID, "bulk-grp-"+uniq(t), "", "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	tok := bulkToken(t, db, group.ID, nil, true, time.Hour)
	if tok.GroupID != group.ID {
		t.Errorf("token GroupID = %q, want %q", tok.GroupID, group.ID)
	}

	devID, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "grp-host", "windows")
	if err != nil {
		t.Fatalf("BeginBulkEnroll: %v", err)
	}
	dev, _, err := db.GetDevice(ctx, tenancy.DefaultTenantID, devID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	found := false
	for _, g := range dev.Groups {
		if g.ID == group.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("устройство не попало в группу токена: groups=%+v", dev.Groups)
	}
}

func TestApproveRejectDevice(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	tok := bulkToken(t, db, "", nil, true, time.Hour)
	mk := func(h string) string {
		id, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, h, "linux")
		if err != nil {
			t.Fatalf("BeginBulkEnroll %s: %v", h, err)
		}
		if err := db.FinalizeBulkEnroll(ctx, tenancy.DefaultTenantID, id, "s", fmt.Sprintf("fp-%s-%s", h, uniq(t)), true); err != nil {
			t.Fatalf("FinalizeBulkEnroll %s: %v", h, err)
		}
		return id
	}
	a, b := mk("appr"), mk("rej")

	if ok, err := db.ApproveDevice(ctx, tenancy.DefaultTenantID, a); err != nil || !ok {
		t.Fatalf("ApproveDevice: ok=%v err=%v", ok, err)
	}
	if st, _ := db.GetDeviceStatusByID(ctx, tenancy.DefaultTenantID, a); st != "active" {
		t.Errorf("approved status = %q, want active", st)
	}
	// повторный approve по уже active — guard возвращает false
	if ok, _ := db.ApproveDevice(ctx, tenancy.DefaultTenantID, a); ok {
		t.Error("повторный approve не-pending должен быть false")
	}

	if ok, err := db.RejectDevice(ctx, tenancy.DefaultTenantID, b); err != nil || !ok {
		t.Fatalf("RejectDevice: ok=%v err=%v", ok, err)
	}
	if st, _ := db.GetDeviceStatusByID(ctx, tenancy.DefaultTenantID, b); st != "rejected" {
		t.Errorf("rejected status = %q, want rejected", st)
	}
}

// Реенролл был обходной дверью в managed-статусы: он ставит 'pending', а хартбит
// поднимает 'pending' → 'active', причём сертификат устройства остаётся валидным
// (обнуляется только cert_serial). То есть отклонённая машина возвращалась в строй БЕЗ
// повторного одобрения, заблокированная — в обход kill-switch. Гейт в updateDeviceStatus
// эту дверь закрывал, а реенролл её не проверял вовсе и вдобавок не под requireHuman.
func TestResetDeviceForReenroll_BlockedForTerminalStatuses(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	tok := bulkToken(t, db, "", nil, true, time.Hour)

	mk := func(h string) string {
		id, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, h, "linux")
		if err != nil {
			t.Fatalf("BeginBulkEnroll %s: %v", h, err)
		}
		if err := db.FinalizeBulkEnroll(ctx, tenancy.DefaultTenantID, id, "s", fmt.Sprintf("fp-%s-%s", h, uniq(t)), true); err != nil {
			t.Fatalf("FinalizeBulkEnroll %s: %v", h, err)
		}
		return id
	}

	for _, c := range []struct{ name, status string }{
		{"rejected", "rejected"},
		{"blocked", "blocked"},
		{"decommissioned", "decommissioned"},
		{"pending_approval", "pending_approval"},
	} {
		t.Run(c.name, func(t *testing.T) {
			id := mk("re-" + c.name)
			switch c.status {
			case "rejected":
				if ok, err := db.RejectDevice(ctx, tenancy.DefaultTenantID, id); err != nil || !ok {
					t.Fatalf("RejectDevice: ok=%v err=%v", ok, err)
				}
			case "pending_approval":
				// FinalizeBulkEnroll уже оставил его в очереди — ничего не делаем.
			default:
				if err := db.UpdateDeviceStatus(ctx, tenancy.DefaultTenantID, id, c.status); err != nil {
					t.Fatalf("UpdateDeviceStatus %s: %v", c.status, err)
				}
			}

			err := db.ResetDeviceForReenroll(ctx, tenancy.DefaultTenantID, id, "re-tok-"+uniq(t), time.Now().Add(time.Hour))
			if !errors.Is(err, storage.ErrDeviceNotReenrollable) {
				t.Fatalf("реенролл из %s разрешён (err=%v) — статус обходится через pending→active", c.status, err)
			}
			if st, _ := db.GetDeviceStatusByID(ctx, tenancy.DefaultTenantID, id); st != c.status {
				t.Errorf("статус после отказанного реенролла = %q, want %q", st, c.status)
			}
		})
	}

	// Штатный путь не задет: активную машину перерегистрировать по-прежнему можно.
	id := mk("re-ok")
	if ok, err := db.ApproveDevice(ctx, tenancy.DefaultTenantID, id); err != nil || !ok {
		t.Fatalf("ApproveDevice: ok=%v err=%v", ok, err)
	}
	if err := db.ResetDeviceForReenroll(ctx, tenancy.DefaultTenantID, id, "re-tok-"+uniq(t), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("реенролл активной машины сломан: %v", err)
	}
	if st, _ := db.GetDeviceStatusByID(ctx, tenancy.DefaultTenantID, id); st != "pending" {
		t.Errorf("статус после штатного реенролла = %q, want pending", st)
	}
}

func TestApprovePendingDevices_BatchByGroup(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	group, err := db.CreateDeviceGroup(ctx, tenancy.DefaultTenantID, "batch-grp-"+uniq(t), "", "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	tok := bulkToken(t, db, group.ID, nil, true, time.Hour)
	for i := 0; i < 3; i++ {
		id, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, fmt.Sprintf("batch-h%d", i), "linux")
		if err != nil {
			t.Fatalf("BeginBulkEnroll #%d: %v", i, err)
		}
		if err := db.FinalizeBulkEnroll(ctx, tenancy.DefaultTenantID, id, "s", fmt.Sprintf("fp-batch-%d-%s", i, uniq(t)), true); err != nil {
			t.Fatalf("FinalizeBulkEnroll #%d: %v", i, err)
		}
	}
	// batch по группе — изолированно (shared DB): трогаем только свою группу
	n, err := db.ApprovePendingDevices(ctx, tenancy.DefaultTenantID, group.ID)
	if err != nil {
		t.Fatalf("ApprovePendingDevices: %v", err)
	}
	if n != 3 {
		t.Errorf("approved (group) = %d, want 3", n)
	}
}

// РЕГРЕСС (адверс-ревью 20.07): скрипт-ПУШ не уходит на неодобренное устройство.
// pending_approval — член группы ДО одобрения, но FanOutScriptToGroup гейтит по
// status='active', а прямой CreateTask возвращает ErrDeviceNotActive. Это парный
// гейт к FetchScriptPolicies (pull-канал); без него был RCE от SYSTEM/root на
// неодобренной машине через рутинный групповой скрипт.
func TestScriptPush_GatedForPendingApproval(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	group, err := db.CreateDeviceGroup(ctx, tenancy.DefaultTenantID, "push-gate-grp-"+uniq(t), "", "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	tok := bulkToken(t, db, group.ID, nil, true, time.Hour)
	devID, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "push-host", "windows")
	if err != nil {
		t.Fatalf("BeginBulkEnroll: %v", err)
	}
	if err := db.FinalizeBulkEnroll(ctx, tenancy.DefaultTenantID, devID, "s", "fp-push-"+uniq(t), true); err != nil {
		t.Fatalf("FinalizeBulkEnroll: %v", err)
	}

	// fan-out по группе НЕ создаёт задачу для pending_approval-члена
	tasks, err := db.FanOutScriptToGroup(ctx, group.ID, "whoami", "Windows", "medium")
	if err != nil {
		t.Fatalf("FanOutScriptToGroup: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("fan-out создал %d задач для pending_approval, want 0 (RCE-гейт)", len(tasks))
	}
	// прямой CreateTask отказывает
	if _, err := db.CreateTask(ctx, devID, "whoami", "windows", "normal"); !errors.Is(err, storage.ErrDeviceNotActive) {
		t.Errorf("CreateTask для pending_approval: err = %v, want ErrDeviceNotActive", err)
	}

	// после approve оба канала работают
	if _, err := db.ApproveDevice(ctx, tenancy.DefaultTenantID, devID); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	tasks, err = db.FanOutScriptToGroup(ctx, group.ID, "whoami", "Windows", "medium")
	if err != nil {
		t.Fatalf("FanOutScriptToGroup (approved): %v", err)
	}
	if len(tasks) != 1 {
		t.Errorf("после approve fan-out создал %d, want 1", len(tasks))
	}
	if _, err := db.CreateTask(ctx, devID, "whoami", "windows", "normal"); err != nil {
		t.Errorf("CreateTask после approve: %v", err)
	}
}

// РЕГРЕСС: batch reject/approve с невалидным group_id возвращает 0 без ошибки
// (group_id::text = $1, без каста ВХОДА в ::uuid) — иначе pg 22P02 → HTTP 500.
func TestBatchApprove_GarbageGroupID_NoError(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	if n, err := db.RejectPendingDevices(ctx, tenancy.DefaultTenantID, "not-a-uuid"); err != nil || n != 0 {
		t.Errorf("RejectPendingDevices(garbage): n=%d err=%v, want 0,nil", n, err)
	}
	if n, err := db.ApprovePendingDevices(ctx, tenancy.DefaultTenantID, "also-garbage"); err != nil || n != 0 {
		t.Errorf("ApprovePendingDevices(garbage): n=%d err=%v, want 0,nil", n, err)
	}
}

// Прощальный/штатный heartbeat НЕ поднимает pending_approval в active (как blocked/
// decommissioned): устройство в очереди остаётся гейтнутым до явного одобрения.
func TestBulkEnroll_HeartbeatDoesNotLiftPendingApproval(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	tok := bulkToken(t, db, "", nil, true, time.Hour)
	fp := "fp-hb-" + uniq(t)
	devID, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "hb-host", "linux")
	if err != nil {
		t.Fatalf("BeginBulkEnroll: %v", err)
	}
	if err := db.FinalizeBulkEnroll(ctx, tenancy.DefaultTenantID, devID, "s", fp, true); err != nil {
		t.Fatalf("FinalizeBulkEnroll: %v", err)
	}
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, "hb-host", "hb-host", "192.0.2.7")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}
	if st, _ := db.GetDeviceStatusByID(ctx, tenancy.DefaultTenantID, devID); st != "pending_approval" {
		t.Errorf("heartbeat поднял pending_approval → %q, want pending_approval", st)
	}
}

func TestBulkEnroll_TenantScopeFromToken(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	tenantB := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'B') ON CONFLICT DO NOTHING`, tenantB,
	); err != nil {
		t.Fatalf("tenant B: %v", err)
	}
	token := "bulk-tenant-" + uniq(t)
	if err := db.CreateBulkEnrollmentToken(ctx, tenantB, token, "", nil, true, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateBulkEnrollmentToken B: %v", err)
	}
	tok, err := db.GetEnrollmentToken(ctx, token)
	if err != nil || tok == nil {
		t.Fatalf("GetEnrollmentToken: %v nil=%v", err, tok == nil)
	}
	if tok.TenantID != tenantB {
		t.Fatalf("token tenant = %q, want %q", tok.TenantID, tenantB)
	}

	// Чужой тенант не списывает чужой токен.
	if _, _, err := db.BeginBulkEnroll(ctx, tenancy.DefaultTenantID, tok.ID, "x", "linux"); !errors.Is(err, storage.ErrEnrollTokenAlreadyUsed) {
		t.Fatalf("cross-tenant begin: %v, want ErrEnrollTokenAlreadyUsed", err)
	}

	devID, _, err := db.BeginBulkEnroll(ctx, tenantB, tok.ID, "tenant-b-host", "linux")
	if err != nil {
		t.Fatalf("BeginBulkEnroll B: %v", err)
	}
	if err := db.FinalizeBulkEnroll(ctx, tenantB, devID, "s", "fp-tenant-b-"+uniq(t), true); err != nil {
		t.Fatalf("FinalizeBulkEnroll: %v", err)
	}
	dev, _, err := db.GetDevice(ctx, tenantB, devID)
	if err != nil || dev == nil {
		t.Fatalf("GetDevice B: %v nil=%v", err, dev == nil)
	}
	if st, _ := db.GetDeviceStatusByID(ctx, tenantB, devID); st != "pending_approval" {
		t.Errorf("status = %q, want pending_approval", st)
	}
	// Default-тенант не одобряет чужое устройство.
	if ok, err := db.ApproveDevice(ctx, tenancy.DefaultTenantID, devID); err != nil || ok {
		t.Fatalf("ApproveDevice wrong tenant: ok=%v err=%v", ok, err)
	}
	if ok, err := db.ApproveDevice(ctx, tenantB, devID); err != nil || !ok {
		t.Fatalf("ApproveDevice B: ok=%v err=%v", ok, err)
	}
}
