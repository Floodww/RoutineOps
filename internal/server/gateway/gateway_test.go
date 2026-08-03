package gateway_test

import (
	"context"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/gateway"
	"github.com/Floodww/RoutineOps/internal/server/registry"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ── Connect ──────────────────────────────────────────────────────────────────

func TestConnect_NoCert(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	stream := &mockStream{ctx: context.Background()}
	err := gw.Connect(stream)

	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got %v, want Unauthenticated", code)
	}
}

func TestConnect_HappyPath(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-happy")
	stream := &mockStream{
		ctx:  ctx,
		msgs: []*pb.HeartbeatRequest{{IpAddress: "192.0.2.1"}},
	}

	if err := gw.Connect(stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	dbID, err := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err != nil || dbID == "" {
		t.Fatalf("device not in DB after Connect: id=%q err=%v", dbID, err)
	}
}

// ADR-1: device_id must come from cert CN, never from the request body.
func TestConnect_ADR1_HostnameFromCert(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	const cn = "adr1-device"
	ctx, fingerprint := makeCertCtx(t, cn)
	stream := &mockStream{
		ctx:  ctx,
		msgs: []*pb.HeartbeatRequest{{IpAddress: "192.168.1.1"}},
	}

	if err := gw.Connect(stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	dbID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	device, _, err := db.GetDevice(context.Background(), tenancy.DefaultTenantID, dbID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if device.Hostname != cn {
		t.Errorf("ADR-1 violation: hostname=%q, want cert CN %q", device.Hostname, cn)
	}
}

func TestConnect_BlockedDevice(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-blocked")
	registerDevice(t, db, "device-blocked", fingerprint)

	dbID, err := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	if err != nil || dbID == "" {
		t.Fatalf("registerDevice: id=%q err=%v", dbID, err)
	}
	if err := db.UpdateDeviceStatus(context.Background(), tenancy.DefaultTenantID, dbID, "blocked"); err != nil {
		t.Fatalf("block device: %v", err)
	}

	stream := &mockStream{ctx: ctx}
	if code := status.Code(gw.Connect(stream)); code != codes.PermissionDenied {
		t.Errorf("got %v, want PermissionDenied", code)
	}
}

func TestConnect_RecvError(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-recv-err")
	registerDevice(t, db, "device-recv-err", fingerprint)

	expectedErr := fmt.Errorf("custom recv error")
	stream := &mockStream{
		ctx:     ctx,
		RecvErr: expectedErr,
	}

	err := gw.Connect(stream)
	if err != expectedErr {
		t.Errorf("got %v, want %v", err, expectedErr)
	}
}

func TestConnect_StatusCheckDBError(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	// Cancel context to force DB error on GetDeviceStatusByFingerprint
	ctx, _ := makeCertCtx(t, "device-status-err")
	ctx, cancel := context.WithCancel(ctx)
	cancel() // Immediately cancel

	stream := &mockStream{ctx: ctx}
	err := gw.Connect(stream)
	if code := status.Code(err); code != codes.Internal {
		t.Errorf("got %v, want Internal", code)
	}
}

func TestConnect_TaskSentToDevice(t *testing.T) {
	db := newDB(t)
	// Create gw manually to access its registry, or use global registry
	// Wait, we need to extract reg from somewhere or just create our own reg and gw.
	// But `gateway.New` needs asynqClient which is nil in tests.
	reg := registry.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw := gateway.New(db, reg, nil, logger, &MockNotifier{})

	cn := "device-task-sent"
	ctx, fingerprint := makeCertCtx(t, cn)
	registerDevice(t, db, cn, fingerprint)

	block := make(chan struct{})
	stream := &mockStream{
		ctx:       ctx,
		BlockRecv: block,
	}

	go func() {
		// Wait for Connect to register device in reg
		time.Sleep(100 * time.Millisecond)
		reg.Send(cn, &pb.Task{TaskId: "t1"})
		time.Sleep(100 * time.Millisecond)
		close(block)
	}()

	_ = gw.Connect(stream)

	if len(stream.Sent) == 0 || stream.Sent[0].TaskId != "t1" {
		t.Errorf("task not sent")
	}
}

func TestConnect_TaskSendFails(t *testing.T) {
	db := newDB(t)
	reg := registry.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw := gateway.New(db, reg, nil, logger, &MockNotifier{})

	cn := "device-task-fail"
	ctx, fingerprint := makeCertCtx(t, cn)
	registerDevice(t, db, cn, fingerprint)

	block := make(chan struct{})
	stream := &mockStream{
		ctx:       ctx,
		SendErr:   fmt.Errorf("send error"),
		BlockRecv: block,
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		reg.Send(cn, &pb.Task{TaskId: "t2"})
		time.Sleep(100 * time.Millisecond)
		close(block)
	}()

	// F-8 (6d4a660): при ошибке stream.Send рвём весь Connect, чтобы агент
	// переподключился — раньше send-горутина молча умирала, стрим висел half-open.
	err := gw.Connect(stream)
	if code := status.Code(err); code != codes.Unavailable {
		t.Errorf("expected Connect to tear down on Send error with Unavailable, got %v", code)
	}
}

func TestConnect_BlockedMidSession(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-blocked-mid")
	registerDevice(t, db, "device-blocked-mid", fingerprint)

	dbID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)

	hookCalls := 0
	stream := &mockStream{
		ctx: ctx,
		msgs: []*pb.HeartbeatRequest{
			{IpAddress: "192.0.2.1"},
			{IpAddress: "192.0.2.1"},
		},
		RecvHook: func() {
			hookCalls++
			if hookCalls == 2 {
				// Block device before processing second message
				_ = db.UpdateDeviceStatus(context.Background(), tenancy.DefaultTenantID, dbID, "blocked")
			}
		},
	}

	err := gw.Connect(stream)
	if code := status.Code(err); code != codes.PermissionDenied {
		t.Errorf("got %v, want PermissionDenied", code)
	}
}

// ── AckTaskReceived ───────────────────────────────────────────────────────────

func TestAckTaskReceived_Success(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	certCtx, fingerprint := makeCertCtx(t, "device-ack")
	registerDevice(t, db, "device-ack", fingerprint)

	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	task, err := db.CreateTask(context.Background(), devID, "echo hi", "linux", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	resp, err := gw.AckTaskReceived(certCtx, &pb.TaskReceivedAck{TaskId: task.ID})
	if err != nil {
		t.Fatalf("AckTaskReceived: %v", err)
	}
	if !resp.Acknowledged {
		t.Error("expected Acknowledged=true")
	}

	got, _ := db.GetTask(context.Background(), task.ID)
	if got == nil || got.Status != "acked" {
		t.Errorf("task status = %q, want acked", got.Status)
	}
}

// ── ReportInventory ───────────────────────────────────────────────────────────

func TestReportInventory_NoCert(t *testing.T) {
	gw := newGW(t, newDB(t))
	_, err := gw.ReportInventory(context.Background(), &pb.InventoryReport{})
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got %v, want Unauthenticated", code)
	}
}

func TestReportInventory_NilDeviceInfo(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, _ := makeCertCtx(t, "device-inv-nil")
	resp, err := gw.ReportInventory(ctx, &pb.InventoryReport{DeviceInfo: nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Received {
		t.Error("expected Received=false for nil DeviceInfo")
	}
}

func TestReportInventory_Success(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-inv")
	registerDevice(t, db, "device-inv", fingerprint)

	resp, err := gw.ReportInventory(ctx, &pb.InventoryReport{
		DeviceInfo: &pb.DeviceInfo{
			Hostname:  "device-inv",
			Os:        "linux",
			OsVersion: "Ubuntu 22.04",
			IpAddress: "192.0.2.2",
		},
		Software: []*pb.SoftwareItem{
			{SoftwareName: "curl", Version: "7.81"},
		},
	})
	if err != nil {
		t.Fatalf("ReportInventory: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}
}

// ── ReportTaskResult ──────────────────────────────────────────────────────────

func TestReportTaskResult_Completed(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	certCtx, fingerprint := makeCertCtx(t, "device-result-ok")
	registerDevice(t, db, "device-result-ok", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	task, err := db.CreateTask(context.Background(), devID, "echo done", "linux", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	resp, err := gw.ReportTaskResult(certCtx, &pb.TaskResult{
		TaskId: task.ID,
		Status: pb.TaskStatus_TASK_STATUS_SUCCESS,
		Output: "done\n",
	})
	if err != nil {
		t.Fatalf("ReportTaskResult: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}

	got, _ := db.GetTask(context.Background(), task.ID)
	if got == nil || got.Status != "completed" {
		t.Errorf("task status = %q, want completed", got.Status)
	}
}

func TestReportTaskResult_Error(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	certCtx, fingerprint := makeCertCtx(t, "device-result-err")
	registerDevice(t, db, "device-result-err", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)
	task, err := db.CreateTask(context.Background(), devID, "false", "linux", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	resp, err := gw.ReportTaskResult(certCtx, &pb.TaskResult{
		TaskId:   task.ID,
		Status:   pb.TaskStatus_TASK_STATUS_ERROR,
		ErrorLog: "exit code 1",
	})
	if err != nil {
		t.Fatalf("ReportTaskResult: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}

	got, _ := db.GetTask(context.Background(), task.ID)
	if got == nil || got.Status != "failed" {
		t.Errorf("task status = %q, want failed", got.Status)
	}
}

// ── FetchPolicy ───────────────────────────────────────────────────────────────

func TestFetchPolicy_NoCert(t *testing.T) {
	gw := newGW(t, newDB(t))
	_, err := gw.FetchPolicy(context.Background(), &pb.FetchPolicyRequest{})
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got %v, want Unauthenticated", code)
	}
}

func TestFetchPolicy_NoPolicies(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-policy")
	registerDevice(t, db, "device-policy", fingerprint)

	resp, err := gw.FetchPolicy(ctx, &pb.FetchPolicyRequest{})
	if err != nil {
		t.Fatalf("FetchPolicy: %v", err)
	}
	if len(resp.Rules) != 0 {
		t.Errorf("expected empty rules, got %d", len(resp.Rules))
	}
}

// ── ReportSecurityEvent ───────────────────────────────────────────────────────

func TestReportSecurityEvent_NoCert(t *testing.T) {
	gw := newGW(t, newDB(t))
	_, err := gw.ReportSecurityEvent(context.Background(), &pb.SecurityEvent{})
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got %v, want Unauthenticated", code)
	}
}

func TestReportSecurityEvent_UnknownDevice(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, _ := makeCertCtx(t, "device-sec-unknown")
	// device NOT registered — fingerprint not in DB
	resp, err := gw.ReportSecurityEvent(ctx, &pb.SecurityEvent{
		AlertType: pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE,
		Details:   "curl 7.81",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Неизвестное устройство → accept-and-drop (Received=true), иначе агент ретраит
	// призрак вечно (6d4a660).
	if !resp.Received {
		t.Error("expected Received=true (accept-and-drop) for unknown device")
	}
}

func TestReportSecurityEvent_Success(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-sec-ok")
	registerDevice(t, db, "device-sec-ok", fingerprint)

	resp, err := gw.ReportSecurityEvent(ctx, &pb.SecurityEvent{
		AlertType: pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE,
		Details:   "BitTorrent 7.10",
	})
	if err != nil {
		t.Fatalf("ReportSecurityEvent: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}
}

// ── RequestAdminAccess ────────────────────────────────────────────────────────

func TestRequestAdminAccess_NoCert(t *testing.T) {
	gw := newGW(t, newDB(t))
	_, err := gw.RequestAdminAccess(context.Background(), &pb.RequestAdminAccessRequest{})
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got %v, want Unauthenticated", code)
	}
}

func TestRequestAdminAccess_DeviceNotFound(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, _ := makeCertCtx(t, "device-adm-notfound")
	// device NOT registered
	_, err := gw.RequestAdminAccess(ctx, &pb.RequestAdminAccessRequest{Reason: "need access"})
	if code := status.Code(err); code != codes.NotFound {
		t.Errorf("got %v, want NotFound", code)
	}
}

func TestRequestAdminAccess_NoOwner(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-adm-noowner")
	registerDevice(t, db, "device-adm-noowner", fingerprint)
	// device exists but owner_id is NULL — владелец необязателен, заявка должна
	// успешно создаться (MDM-пользователи — ИТ-операторы, а не сотрудники).

	resp, err := gw.RequestAdminAccess(ctx, &pb.RequestAdminAccessRequest{Reason: "need access"})
	if err != nil {
		t.Fatalf("RequestAdminAccess без владельца: %v", err)
	}
	if resp.RequestId == "" {
		t.Error("expected non-empty RequestId")
	}
	if resp.Status != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_PENDING {
		t.Errorf("status = %v, want PENDING", resp.Status)
	}
}

func TestRequestAdminAccess_WithOwner(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	// create a user to be the owner

	ctx, fingerprint := makeCertCtx(t, "device-adm-owner")
	registerDevice(t, db, "device-adm-owner", fingerprint)

	resp, err := gw.RequestAdminAccess(ctx, &pb.RequestAdminAccessRequest{Reason: "install software"})
	if err != nil {
		t.Fatalf("RequestAdminAccess: %v", err)
	}
	if resp.RequestId == "" {
		t.Error("expected non-empty RequestId")
	}
	if resp.Status != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_PENDING {
		t.Errorf("status = %v, want PENDING", resp.Status)
	}
}

// ── FetchAdminStatus ──────────────────────────────────────────────────────────

func TestFetchAdminStatus_NoCert(t *testing.T) {
	gw := newGW(t, newDB(t))
	_, err := gw.FetchAdminStatus(context.Background(), &pb.FetchAdminStatusRequest{})
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got %v, want Unauthenticated", code)
	}
}

func TestFetchAdminStatus_DeviceNotFound(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, _ := makeCertCtx(t, "device-fetchstatus-notfound")
	// device NOT registered
	_, err := gw.FetchAdminStatus(ctx, &pb.FetchAdminStatusRequest{})
	if code := status.Code(err); code != codes.NotFound {
		t.Errorf("got %v, want NotFound", code)
	}
}

func TestFetchAdminStatus_NoActiveRequest(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-fetchstatus-empty")
	registerDevice(t, db, "device-fetchstatus-empty", fingerprint)

	resp, err := gw.FetchAdminStatus(ctx, &pb.FetchAdminStatusRequest{})
	if err != nil {
		t.Fatalf("FetchAdminStatus: %v", err)
	}
	if resp.RequestId != "" {
		t.Errorf("expected empty RequestId, got %q", resp.RequestId)
	}
}

// ── ReportAdminAccess ─────────────────────────────────────────────────────────

func TestReportAdminAccess_NoCert(t *testing.T) {
	gw := newGW(t, newDB(t))
	_, err := gw.ReportAdminAccess(context.Background(), &pb.ReportAdminAccessRequest{
		RequestId: "00000000-0000-0000-0000-000000000000",
		Status:    pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED,
	})
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got %v, want Unauthenticated", code)
	}
}

func TestReportAdminAccess_InvalidStatus(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, _ := makeCertCtx(t, "device-reportadm-invalid")
	_, err := gw.ReportAdminAccess(ctx, &pb.ReportAdminAccessRequest{
		RequestId: "00000000-0000-0000-0000-000000000000",
		Status:    pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_PENDING, // invalid for agent reports
	})
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("got %v, want InvalidArgument", code)
	}
}

func TestReportAdminAccess_ApprovedStatus(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	// create a real request so UpdateAdminAccessReport has a row to touch
	owner, _ := db.CreateUser(context.Background(), tenancy.DefaultTenantID, "Owner2", uniqEmail("owner2_adm"), "hash", "user")
	certCtx, fingerprint := makeCertCtx(t, "device-reportadm-ok")
	registerDevice(t, db, "device-reportadm-ok", fingerprint)
	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fingerprint)

	now := time.Now()
	row, err := db.CreateAdminAccessRequest(context.Background(), devID, owner.ID, "test", now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}

	// Отчёт шлёт САМО устройство-владелец заявки (device-scoping): чужое устройство
	// теперь получило бы accept-and-drop (см. TestReportAdminAccess_ForeignDeviceIgnored).
	resp, err := gw.ReportAdminAccess(certCtx, &pb.ReportAdminAccessRequest{
		RequestId:  row.ID,
		Status:     pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED,
		OccurredAt: now.Unix(),
	})
	if err != nil {
		t.Fatalf("ReportAdminAccess: %v", err)
	}
	if !resp.Received {
		t.Error("expected Received=true")
	}
}

// ── FetchScriptPolicies ───────────────────────────────────────────────────────

func TestFetchScriptPolicies_NoCert(t *testing.T) {
	gw := newGW(t, newDB(t))
	_, err := gw.FetchScriptPolicies(context.Background(), &pb.FetchScriptPoliciesRequest{})
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got %v, want Unauthenticated", code)
	}
}

func TestFetchScriptPolicies_NoPolicies(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fingerprint := makeCertCtx(t, "device-scripts")
	registerDevice(t, db, "device-scripts", fingerprint)

	resp, err := gw.FetchScriptPolicies(ctx, &pb.FetchScriptPoliciesRequest{})
	if err != nil {
		t.Fatalf("FetchScriptPolicies: %v", err)
	}
	if len(resp.Policies) != 0 {
		t.Errorf("expected empty policies, got %d", len(resp.Policies))
	}
}

// ── ReportScriptResult ────────────────────────────────────────────────────────

func TestReportScriptResult_NoCert(t *testing.T) {
	gw := newGW(t, newDB(t))
	_, err := gw.ReportScriptResult(context.Background(), &pb.ScriptResult{})
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got %v, want Unauthenticated", code)
	}
}

func TestReportScriptResult_UnknownDevice(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, _ := makeCertCtx(t, "device-script-unknown")
	// device NOT registered
	resp, err := gw.ReportScriptResult(ctx, &pb.ScriptResult{
		PolicyId: "00000000-0000-0000-0000-000000000000",
		RunId:    "run-001",
		ExitCode: 0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Неизвестное устройство → accept-and-drop (Received=true) (6d4a660).
	if !resp.Received {
		t.Error("expected Received=true (accept-and-drop) for unknown device")
	}
}
