package gateway_test

import (
	"context"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/gateway"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// H2-регресс: устройство A НЕ может Ack'нуть задачу устройства B (BOLA/IDOR). Раньше
// AckTask скоупился только по task_id → чужой Ack уводил задачу из pending, и она
// НИКОГДА не доставлялась жертве.
func TestAckTaskReceived_ForeignDeviceCannotAck(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := tenantCtx()

	attackerCtx, aFP := makeCertCtx(t, "device-attacker-ack")
	registerDevice(t, db, "device-attacker-ack", aFP)
	_, vFP := makeCertCtx(t, "device-victim-ack")
	registerDevice(t, db, "device-victim-ack", vFP)
	victimID, _ := db.GetDeviceIDByFingerprint(ctx, vFP)

	task, err := db.CreateTask(ctx, victimID, "lock", "linux", "high")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	resp, err := gw.AckTaskReceived(attackerCtx, &pb.TaskReceivedAck{TaskId: task.ID})
	if err != nil {
		t.Fatalf("AckTaskReceived: %v", err)
	}
	if resp.Acknowledged {
		t.Error("чужое устройство не должно Ack'ать задачу жертвы")
	}
	got, _ := db.GetTask(ctx, task.ID)
	if got == nil || got.Status != "pending" {
		t.Errorf("задача жертвы уведена из pending: status=%q", statusOf(got))
	}
}

// H2-регресс: устройство A НЕ может пометить задачу устройства B «успешной»
// (фальсификация compliance).
func TestReportTaskResult_ForeignDeviceCannotComplete(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := tenantCtx()

	attackerCtx, aFP := makeCertCtx(t, "device-attacker-res")
	registerDevice(t, db, "device-attacker-res", aFP)
	_, vFP := makeCertCtx(t, "device-victim-res")
	registerDevice(t, db, "device-victim-res", vFP)
	victimID, _ := db.GetDeviceIDByFingerprint(ctx, vFP)

	task, err := db.CreateTask(ctx, victimID, "patch", "linux", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	// accept-and-drop (Received=true), но задача жертвы НЕ должна стать completed.
	if _, err := gw.ReportTaskResult(attackerCtx, &pb.TaskResult{
		TaskId: task.ID,
		Status: pb.TaskStatus_TASK_STATUS_SUCCESS,
		Output: "pretend-patched",
	}); err != nil {
		t.Fatalf("ReportTaskResult: %v", err)
	}
	got, _ := db.GetTask(ctx, task.ID)
	if got == nil || got.Status != "pending" {
		t.Errorf("чужой репорт подделал статус задачи жертвы: status=%q", statusOf(got))
	}
}

// L2-регресс: устройство A НЕ может отозвать выданный грант устройства B по чужому
// request_id (IDOR).
func TestReportAdminAccess_ForeignDeviceIgnored(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := tenantCtx()

	owner, _ := db.CreateUser(ctx, tenancy.DefaultTenantID, "Owner", uniqEmail("owner_idor"), "hash", "user")
	attackerCtx, aFP := makeCertCtx(t, "device-attacker-adm")
	registerDevice(t, db, "device-attacker-adm", aFP)
	_, vFP := makeCertCtx(t, "device-victim-adm")
	registerDevice(t, db, "device-victim-adm", vFP)
	victimID, _ := db.GetDeviceIDByFingerprint(ctx, vFP)

	now := time.Now()
	req, err := db.CreateAdminAccessRequest(ctx, victimID, owner.ID, "reason", now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}
	exp := now.Add(30 * time.Minute)
	if err := db.RespondToAdminRequest(ctx, req.ID, "approved", owner.ID, &exp); err != nil {
		t.Fatalf("RespondToAdminRequest: %v", err)
	}

	// accept-and-drop (Received=true), но грант жертвы НЕ должен быть отозван.
	if _, err := gw.ReportAdminAccess(attackerCtx, &pb.ReportAdminAccessRequest{
		RequestId:  req.ID,
		Status:     pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED,
		OccurredAt: now.Unix(),
	}); err != nil {
		t.Fatalf("ReportAdminAccess: %v", err)
	}

	rows, err := db.ListAdminAccessRequests(ctx, tenancy.DefaultTenantID, "")
	if err != nil {
		t.Fatalf("ListAdminAccessRequests: %v", err)
	}
	for _, r := range rows {
		if r.ID == req.ID && r.Status == "revoked" {
			t.Fatal("чужое устройство отозвало грант жертвы (IDOR не закрыт)")
		}
	}
}

// IDOR-регресс: устройство A присылает ReportSecurityEvent с admin_access_request_id
// ЖЕРТВЫ B. Раньше сервер линковал чужую заявку в alerts без проверки владельца, и
// FK на неё (ON DELETE RESTRICT изнутри каскада) намертво блокировал удаление B: DELETE
// devices B падал 23503, а оператор получал ложное «device has escrow». Теперь INSERT
// скоупит заявку по отправителю → чужой id молча становится NULL → удаление B проходит.
func TestReportSecurityEvent_ForeignAdminRequestCannotPinVictim(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)
	ctx := tenantCtx()

	owner, _ := db.CreateUser(ctx, tenancy.DefaultTenantID, "Owner", uniqEmail("owner_secidor"), "hash", "user")
	attackerCtx, aFP := makeCertCtx(t, "device-attacker-sec")
	registerDevice(t, db, "device-attacker-sec", aFP)
	_, vFP := makeCertCtx(t, "device-victim-sec")
	registerDevice(t, db, "device-victim-sec", vFP)
	victimID, _ := db.GetDeviceIDByFingerprint(ctx, vFP)

	now := time.Now()
	// Заявка принадлежит ЖЕРТВЕ.
	victimReq, err := db.CreateAdminAccessRequest(ctx, victimID, owner.ID, "reason", now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}

	// Атакующий закрепляет чужую заявку за своим security-событием. accept-and-drop.
	if _, err := gw.ReportSecurityEvent(attackerCtx, &pb.SecurityEvent{
		AlertType:            pb.AlertType_ALERT_TYPE_UNAUTHORIZED_INSTALL,
		Details:              "pinning victim's request",
		AdminAccessRequestId: victimReq.ID,
	}); err != nil {
		t.Fatalf("ReportSecurityEvent: %v", err)
	}

	// Жертву обязано быть можно удалить: чужой alert не должен держать её заявку.
	found, err := db.DeleteDevice(ctx, tenancy.DefaultTenantID, victimID)
	if err != nil {
		t.Fatalf("удаление жертвы заблокировано чужим alert (IDOR не закрыт): %v", err)
	}
	if !found {
		t.Fatal("устройство жертвы не найдено при удалении")
	}
}

// H1-регресс: blocked-интерсептор отклоняет ЛЮБОЙ RPC заблокированного устройства до
// хендлера; после разблокировки — пропускает.
func TestBlockedInterceptor_RejectsBlockedDevice(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	certCtx, fp := makeCertCtx(t, "device-blocked-intr")
	registerDevice(t, db, "device-blocked-intr", fp)
	devID, _ := db.GetDeviceIDByFingerprint(ctx, fp)

	unary, _ := gateway.NewBlockedInterceptors(db, logger)
	called := false
	handler := func(context.Context, any) (any, error) { called = true; return "ok", nil }
	info := &grpc.UnaryServerInfo{}

	// Заблокировано → PermissionDenied, хендлер не вызван.
	if err := db.UpdateDeviceStatus(ctx, tenancy.DefaultTenantID, devID, "blocked"); err != nil {
		t.Fatalf("UpdateDeviceStatus blocked: %v", err)
	}
	if _, err := unary(certCtx, nil, info, handler); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ждали PermissionDenied для blocked, got %v", err)
	}
	if called {
		t.Fatal("хендлер вызван для заблокированного устройства")
	}

	// Разблокировано → хендлер вызван.
	if err := db.UpdateDeviceStatus(ctx, tenancy.DefaultTenantID, devID, "active"); err != nil {
		t.Fatalf("UpdateDeviceStatus active: %v", err)
	}
	if _, err := unary(certCtx, nil, info, handler); err != nil {
		t.Fatalf("активное устройство не должно отклоняться: %v", err)
	}
	if !called {
		t.Fatal("хендлер не вызван для активного устройства")
	}
}

func statusOf(t *storage.Task) string {
	if t == nil {
		return "<nil>"
	}
	return t.Status
}
