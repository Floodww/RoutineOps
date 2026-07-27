package gateway_test

import (
	"context"
	"io"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

// Дополнение к gateway_mtls_test.go: happy-path через НАСТОЯЩИЙ mTLS-стек
// (bufconn + grpc TLS) для остальных RPC, которые раньше проверялись только на
// app-уровне (peer-cert в контексте). Так весь контракт AgentService прогоняется
// через транспортный барьер, а не только 4 unary-метода.

// ── Connect (bidi stream) ─────────────────────────────────────────────────────

// Connect сам регистрирует устройство по heartbeat (как в проде первый старт):
// открываем стрим, шлём один heartbeat, закрываем отправку и ждём EOF — к этому
// моменту сервер успел сделать upsert. Затем проверяем, что устройство в БД.
func TestMTLS_Connect_HappyPath(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))

	cert, der := issueCert(t, env.caCert, env.caKey, "device-mtls-connect", false)
	fp := fingerprintOf(der)
	client := env.dial(t, &cert)

	stream, err := client.Connect(callCtx(t))
	if err != nil {
		t.Fatalf("Connect через mTLS: %v", err)
	}
	if err := stream.Send(&pb.HeartbeatRequest{IpAddress: "192.0.2.5"}); err != nil {
		t.Fatalf("Send heartbeat: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	// Дренируем стрим до конца: когда сервер обработал heartbeat и получил EOF,
	// он закрывает стрим — клиент видит io.EOF.
	for {
		if _, err := stream.Recv(); err != nil {
			if err != io.EOF {
				t.Fatalf("Recv: %v", err)
			}
			break
		}
	}

	dbID, err := db.GetDeviceIDByFingerprint(context.Background(), fp)
	if err != nil || dbID == "" {
		t.Fatalf("устройство не появилось в БД после Connect: id=%q err=%v", dbID, err)
	}
}

// ── AckTaskReceived ───────────────────────────────────────────────────────────

func TestMTLS_AckTaskReceived_HappyPath(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, deviceID := env.validClient(t, db, "device-mtls-ack")

	task, err := db.CreateTask(context.Background(), deviceID, "echo hi", "linux", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	resp, err := client.AckTaskReceived(callCtx(t), &pb.TaskReceivedAck{TaskId: task.ID})
	if err != nil {
		t.Fatalf("AckTaskReceived через mTLS: %v", err)
	}
	if !resp.Acknowledged {
		t.Error("ожидали Acknowledged=true")
	}

	got, _ := db.GetTask(context.Background(), task.ID)
	if got == nil || got.Status != "acked" {
		t.Errorf("статус задачи = %v, want acked", got)
	}
}

// ── ReportInventory ───────────────────────────────────────────────────────────

func TestMTLS_ReportInventory_HappyPath(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, _ := env.validClient(t, db, "device-mtls-inv")

	resp, err := client.ReportInventory(callCtx(t), &pb.InventoryReport{
		DeviceInfo: &pb.DeviceInfo{
			Hostname:  "device-mtls-inv",
			Os:        "linux",
			OsVersion: "Ubuntu 22.04",
			IpAddress: "192.0.2.6",
		},
		Software: []*pb.SoftwareItem{{SoftwareName: "curl", Version: "7.81"}},
	})
	if err != nil {
		t.Fatalf("ReportInventory через mTLS: %v", err)
	}
	if !resp.Received {
		t.Error("ожидали Received=true")
	}
}

// ── ReportTaskResult ──────────────────────────────────────────────────────────

func TestMTLS_ReportTaskResult_HappyPath(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, deviceID := env.validClient(t, db, "device-mtls-taskresult")

	task, err := db.CreateTask(context.Background(), deviceID, "echo done", "linux", "normal")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	resp, err := client.ReportTaskResult(callCtx(t), &pb.TaskResult{
		TaskId: task.ID,
		Status: pb.TaskStatus_TASK_STATUS_SUCCESS,
		Output: "done\n",
	})
	if err != nil {
		t.Fatalf("ReportTaskResult через mTLS: %v", err)
	}
	if !resp.Received {
		t.Error("ожидали Received=true")
	}

	got, _ := db.GetTask(context.Background(), task.ID)
	if got == nil || got.Status != "completed" {
		t.Errorf("статус задачи = %v, want completed", got)
	}
}

// ── RequestAdminAccess ────────────────────────────────────────────────────────

func TestMTLS_RequestAdminAccess_HappyPath(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, _ := env.validClient(t, db, "device-mtls-admreq")

	resp, err := client.RequestAdminAccess(callCtx(t), &pb.RequestAdminAccessRequest{Reason: "install software"})
	if err != nil {
		t.Fatalf("RequestAdminAccess через mTLS: %v", err)
	}
	if resp.RequestId == "" {
		t.Error("ожидали непустой RequestId")
	}
	if resp.Status != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_PENDING {
		t.Errorf("status = %v, want PENDING", resp.Status)
	}
}

// ── FetchAdminStatus ──────────────────────────────────────────────────────────

func TestMTLS_FetchAdminStatus_NoActiveRequest(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, _ := env.validClient(t, db, "device-mtls-admstatus")

	resp, err := client.FetchAdminStatus(callCtx(t), &pb.FetchAdminStatusRequest{})
	if err != nil {
		t.Fatalf("FetchAdminStatus через mTLS: %v", err)
	}
	if resp.RequestId != "" {
		t.Errorf("ожидали пустой RequestId без активной заявки, получили %q", resp.RequestId)
	}
}

// ── ReportAdminAccess ─────────────────────────────────────────────────────────

func TestMTLS_ReportAdminAccess_HappyPath(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, deviceID := env.validClient(t, db, "device-mtls-admreport")

	owner, err := db.CreateUser(context.Background(), "Owner", uniqEmail("owner_mtls_admrep"), "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Now()
	row, err := db.CreateAdminAccessRequest(context.Background(), deviceID, owner.ID, "test", now, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}

	resp, err := client.ReportAdminAccess(callCtx(t), &pb.ReportAdminAccessRequest{
		RequestId:  row.ID,
		Status:     pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED,
		OccurredAt: now.Unix(),
	})
	if err != nil {
		t.Fatalf("ReportAdminAccess через mTLS: %v", err)
	}
	if !resp.Received {
		t.Error("ожидали Received=true")
	}
}
