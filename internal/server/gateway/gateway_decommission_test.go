package gateway_test

import (
	"context"
	"testing"

	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Decommission-задача, подтверждённая агентом (SUCCESS), переводит устройство в
// терминальный 'decommissioned'. Флип делает gateway ПОСЛЕ приёма отчёта — до этого
// статус оставался прежним, чтобы Connect успел доставить команду сноса.
func TestReportTaskResult_DecommissionFlipsStatus(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	certCtx, fp := makeCertCtx(t, "device-decomm-ok")
	registerDevice(t, db, "device-decomm-ok", fp)
	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fp)

	task, err := db.CreateDecommissionTask(context.Background(), devID)
	if err != nil {
		t.Fatalf("CreateDecommissionTask: %v", err)
	}

	if _, err := gw.ReportTaskResult(certCtx, &pb.TaskResult{
		TaskId: task.ID,
		Status: pb.TaskStatus_TASK_STATUS_SUCCESS,
	}); err != nil {
		t.Fatalf("ReportTaskResult: %v", err)
	}

	if st, _ := db.GetDeviceStatusByID(context.Background(), devID); st != "decommissioned" {
		t.Errorf("device status = %q, want decommissioned", st)
	}
}

// FAILED decommission (агент не смог снестись) НЕ списывает устройство — оно ещё живо,
// списывать по несостоявшемуся сносу нельзя.
func TestReportTaskResult_DecommissionFailedKeepsDevice(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	certCtx, fp := makeCertCtx(t, "device-decomm-fail")
	registerDevice(t, db, "device-decomm-fail", fp)
	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fp)

	task, _ := db.CreateDecommissionTask(context.Background(), devID)
	if _, err := gw.ReportTaskResult(certCtx, &pb.TaskResult{
		TaskId:   task.ID,
		Status:   pb.TaskStatus_TASK_STATUS_ERROR,
		ErrorLog: "teardown failed",
	}); err != nil {
		t.Fatalf("ReportTaskResult: %v", err)
	}

	if st, _ := db.GetDeviceStatusByID(context.Background(), devID); st == "decommissioned" {
		t.Errorf("устройство списано по FAILED decommission — не должно (status=%q)", st)
	}
}

// Connect отклоняет списанное устройство — это и есть отзыв серта на границе gateway
// (как blocked). Даже если недоснесённый агент сохранил валидный серт, стрим не встаёт.
func TestConnect_DecommissionedDevice(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fp := makeCertCtx(t, "device-decomm-conn")
	registerDevice(t, db, "device-decomm-conn", fp)
	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fp)
	if err := db.MarkDeviceDecommissioned(context.Background(), devID); err != nil {
		t.Fatalf("MarkDeviceDecommissioned: %v", err)
	}

	stream := &mockStream{ctx: ctx}
	if code := status.Code(gw.Connect(stream)); code != codes.PermissionDenied {
		t.Errorf("got %v, want PermissionDenied для decommissioned", code)
	}
}

// Удаление устройства отзывает его серт (тумбстоун, миграция 034). Агент по всё ещё
// валидному серту переподключается — Connect режет отозванный fingerprint и НЕ заводит
// устройство заново. Регрессия на воскрешение через hard-delete + ADR-1 регистрацию.
// Отличие от нового устройства: у того fingerprint неизвестен, но НЕ отозван → проходит.
func TestConnect_RevokedFingerprintRejectedNoResurrection(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fp := makeCertCtx(t, "device-deleted-revoked")
	registerDevice(t, db, "device-deleted-revoked", fp)
	devID, _ := db.GetDeviceIDByFingerprint(context.Background(), fp)
	if _, err := db.DeleteDevice(context.Background(), devID); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}

	stream := &mockStream{ctx: ctx}
	if code := status.Code(gw.Connect(stream)); code != codes.NotFound {
		t.Errorf("got %v, want NotFound для отозванного серта", code)
	}
	// Воскрешения нет: устройство по этому серту в БД не появилось заново.
	if id, _ := db.GetDeviceIDByFingerprint(context.Background(), fp); id != "" {
		t.Errorf("воскрешение: устройство %q заведено заново по отозванному серту", id)
	}
}
