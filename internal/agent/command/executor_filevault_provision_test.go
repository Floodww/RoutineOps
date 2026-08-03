package command

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/Floodww/RoutineOps/proto"
)

type fakeProvisioner struct {
	calls  int
	gotReq string
	gotWhy string
	err    error
}

func (f *fakeProvisioner) Provision(_ context.Context, requestID, reason string) error {
	f.calls++
	f.gotReq, f.gotWhy = requestID, reason
	return f.err
}

// Happy-path: команда доходит до исполнителя вместе с поводом оператора, результат
// уходит успехом.
func TestHandle_FileVaultProvision_Success(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	p := &fakeProvisioner{}
	e.SetFileVaultProvisioner(p)

	e.Submit(&pb.Task{TaskId: "t-fv", FilevaultProvision: &pb.FileVaultProvisionCommand{
		RequestId: "req-1", Reason: "Завершите настройку шифрования",
	}})
	waitFor(t, "результат задачи", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	if p.calls != 1 {
		t.Fatalf("исполнитель вызван %d раз", p.calls)
	}
	if p.gotReq != "req-1" || p.gotWhy != "Завершите настройку шифрования" {
		t.Errorf("исполнителю пришло request_id=%q reason=%q", p.gotReq, p.gotWhy)
	}
	if st := fc.resultsCopy()[0].GetStatus(); st != pb.TaskStatus_TASK_STATUS_SUCCESS {
		t.Errorf("статус = %v, ожидался SUCCESS", st)
	}
}

// Отказ (в том числе отказ человека и таймаут диалога) обязан приезжать оператору
// ошибкой С ПРИЧИНОЙ: контракт команды прямо запрещает тихий Skip.
func TestHandle_FileVaultProvision_FailureReportsReason(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	e.SetFileVaultProvisioner(&fakeProvisioner{err: errors.New("сотрудник отменил диалог")})

	e.Submit(&pb.Task{TaskId: "t-fv-cancel", FilevaultProvision: &pb.FileVaultProvisionCommand{RequestId: "req-2"}})
	waitFor(t, "результат задачи", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	res := fc.resultsCopy()[0]
	if res.GetStatus() != pb.TaskStatus_TASK_STATUS_ERROR {
		t.Fatalf("статус = %v, ожидался ERROR", res.GetStatus())
	}
	if !strings.Contains(res.GetErrorLog(), "отменил") {
		t.Errorf("причина не доехала до оператора: %q", res.GetErrorLog())
	}
}

// Агент без поддержки FileVault (free-сборка, не macOS) обязан ответить ошибкой,
// а не проглотить команду: иначе панель покажет «выполнено» на машине, где
// подсистемы нет вовсе.
func TestHandle_FileVaultProvision_NoProvisioner(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	e.Submit(&pb.Task{TaskId: "t-fv-none", FilevaultProvision: &pb.FileVaultProvisionCommand{RequestId: "req-3"}})
	waitFor(t, "результат задачи", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	res := fc.resultsCopy()[0]
	if res.GetStatus() != pb.TaskStatus_TASK_STATUS_ERROR {
		t.Fatalf("статус = %v, ожидался ERROR", res.GetStatus())
	}
	if !strings.Contains(res.GetErrorLog(), "FileVault") {
		t.Errorf("в причине не сказано, чего именно нет: %q", res.GetErrorLog())
	}
}

// Пустой request_id — не повод молчать: подставляем task_id, иначе идемпотентность
// и аудит на сервере останутся без ключа.
func TestHandle_FileVaultProvision_EmptyRequestIDFallsBackToTaskID(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	p := &fakeProvisioner{}
	e.SetFileVaultProvisioner(p)

	e.Submit(&pb.Task{TaskId: "t-fv-noreq", FilevaultProvision: &pb.FileVaultProvisionCommand{}})
	waitFor(t, "результат задачи", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	if p.gotReq != "t-fv-noreq" {
		t.Errorf("request_id = %q, ожидался task_id", p.gotReq)
	}
}

// Задача provisioning НЕ должна занимать слот исполнителя скриптов: внутри неё
// диалог, ждущий человека до десяти минут, и слот всё это время был бы занят
// чужой работой. Проверяем через полностью занятый семафор.
func TestHandle_FileVaultProvision_NotGatedByScriptSemaphore(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	p := &fakeProvisioner{}
	e.SetFileVaultProvisioner(p)

	for range maxConcurrentTasks { // занимаем все слоты скриптов
		e.sem <- struct{}{}
	}
	defer func() {
		for range maxConcurrentTasks {
			<-e.sem
		}
	}()

	e.Submit(&pb.Task{TaskId: "t-fv-sem", FilevaultProvision: &pb.FileVaultProvisionCommand{RequestId: "req-4"}})
	waitFor(t, "результат задачи при занятом семафоре", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	if p.calls != 1 {
		t.Fatalf("исполнитель вызван %d раз — задача ждала слот скриптов", p.calls)
	}
}
