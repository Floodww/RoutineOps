package command

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

// fakeRebooter подменяет планировщик ОС: реальную перезагрузку в тесте не
// вызвать, поэтому проверяемой границей становится контракт executor↔планировщик.
type fakeRebooter struct {
	mu      sync.Mutex
	calls   int
	gotWant []time.Duration // запрошенные отсрочки
	gotWhy  []string
	ret     time.Duration // что вернуть как ФАКТИЧЕСКУЮ отсрочку
	err     error
}

func (f *fakeRebooter) Schedule(_ context.Context, delay time.Duration, reason string) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.gotWant = append(f.gotWant, delay)
	f.gotWhy = append(f.gotWhy, reason)
	if f.err != nil {
		return 0, f.err
	}
	return f.ret, nil
}

func (f *fakeRebooter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Happy-path: задача подтверждена, планировщик вызван с запрошенной отсрочкой и
// причиной, результат — SUCCESS.
func TestHandleReboot_SchedulesAndReportsSuccess(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	fr := &fakeRebooter{ret: 5 * time.Minute}
	e.SetRebooter(fr)

	e.Submit(&pb.Task{TaskId: "t-reboot", Reboot: &pb.RebootCommand{
		RequestId: "req-1", Reason: "Установка обновлений", DelaySeconds: 300,
	}})
	waitFor(t, "результат перезагрузки", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	if fr.callCount() != 1 {
		t.Fatalf("планировщик вызван %d раз, ожидали 1", fr.callCount())
	}
	if got := fr.gotWant[0]; got != 5*time.Minute {
		t.Errorf("запрошенная отсрочка = %v, ожидали 5m (из delay_seconds=300)", got)
	}
	if fr.gotWhy[0] != "Установка обновлений" {
		t.Errorf("причина не проброшена: %q", fr.gotWhy[0])
	}
	if ids := fc.ackedIDs(); len(ids) != 1 || ids[0] != "t-reboot" {
		t.Errorf("ack задачи = %v", ids)
	}
	res := fc.resultsCopy()[0]
	if res.GetStatus() != pb.TaskStatus_TASK_STATUS_SUCCESS {
		t.Errorf("статус = %v, ожидали SUCCESS", res.GetStatus())
	}
}

// Отчёт обязан нести ФАКТИЧЕСКУЮ отсрочку, а не запрошенную: на macOS/Linux она
// округляется вверх до минут, и если в аудит уедет запрошенное значение, оператор
// будет уверен во времени, которого планировщику никто не задавал.
func TestHandleReboot_ReportsActualDelayNotRequested(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	// Запросили 70 секунд, планировщик округлил до 2 минут.
	e.SetRebooter(&fakeRebooter{ret: 2 * time.Minute})

	e.Submit(&pb.Task{TaskId: "t-round", Reboot: &pb.RebootCommand{DelaySeconds: 70}})
	waitFor(t, "результат", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	out := fc.resultsCopy()[0].GetOutput()
	if !strings.Contains(out, "2m") {
		t.Errorf("в отчёте нет фактической отсрочки (2m): %q", out)
	}
	if strings.Contains(out, "1m10s") {
		t.Errorf("в отчёте запрошенная отсрочка вместо фактической: %q", out)
	}
}

// Отказ планировщика ОС (нет привилегии, уже запланирована другая перезагрузка) —
// это ERROR, а не SUCCESS: иначе панель показывала бы «выполнено» на машине,
// которая никуда не пошла.
func TestHandleReboot_SchedulerErrorIsReportedAsError(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	e.SetRebooter(&fakeRebooter{err: errors.New("shutdown: access denied")})

	e.Submit(&pb.Task{TaskId: "t-deny", Reboot: &pb.RebootCommand{DelaySeconds: 60}})
	waitFor(t, "результат", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	res := fc.resultsCopy()[0]
	if res.GetStatus() != pb.TaskStatus_TASK_STATUS_ERROR {
		t.Fatalf("статус = %v, ожидали ERROR", res.GetStatus())
	}
	if !strings.Contains(res.GetErrorLog(), "access denied") {
		t.Errorf("причина отказа не доехала до сервера: %q", res.GetErrorLog())
	}
}

// Планировщик не подключён (неподдерживаемая ОС/сборка) — отчитываемся ошибкой, а
// не молчим: молчание оставило бы задачу висеть в 'acked' до серверного sweep, и
// причина не появилась бы нигде.
func TestHandleReboot_NoRebooterIsReportedAsError(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	// SetRebooter не вызываем.

	e.Submit(&pb.Task{TaskId: "t-nobody", Reboot: &pb.RebootCommand{DelaySeconds: 60}})
	waitFor(t, "результат", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	res := fc.resultsCopy()[0]
	if res.GetStatus() != pb.TaskStatus_TASK_STATUS_ERROR {
		t.Fatalf("статус = %v, ожидали ERROR", res.GetStatus())
	}
	if res.GetErrorLog() == "" {
		t.Error("пустой error_log — оператор не узнает причину")
	}
}

// САМЫЙ ВАЖНЫЙ случай. Агент переживает перезагрузку, поэтому сервер может
// передоставить ту же задачу ПОСЛЕ загрузки (если отчёт не доехал до ухода машины
// вниз). Повторная доставка обязана быть подтверждена, но перезагрузку второй раз
// НЕ планировать — иначе устройство уйдёт в цикл перезагрузок, пока сервер не
// получит отчёт.
func TestHandleReboot_RedeliveryDoesNotRebootTwice(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	fr := &fakeRebooter{ret: time.Minute}
	e.SetRebooter(fr)

	task := &pb.Task{TaskId: "t-dup", Reboot: &pb.RebootCommand{RequestId: "req-dup", DelaySeconds: 60}}
	e.Submit(task)
	waitFor(t, "первая обработка", func() bool { return fr.callCount() == 1 })

	e.Submit(task) // передоставка того же task_id
	waitFor(t, "повторный ack", func() bool { return len(fc.ackedIDs()) == 2 })
	e.Shutdown()

	if got := fr.callCount(); got != 1 {
		t.Fatalf("планировщик вызван %d раз при передоставке — устройство ушло бы в цикл перезагрузок", got)
	}
}

// request_id пустой (сервер положил только task_id) — корреляция не должна
// теряться: падаем на task_id, как это делают lock и decommission.
func TestHandleReboot_EmptyRequestIDFallsBackToTaskID(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	e.SetRebooter(&fakeRebooter{ret: time.Minute})

	e.Submit(&pb.Task{TaskId: "t-noreq", Reboot: &pb.RebootCommand{DelaySeconds: 60}})
	waitFor(t, "результат", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	if id := fc.resultsCopy()[0].GetTaskId(); id != "t-noreq" {
		t.Fatalf("task_id в отчёте = %q", id)
	}
}

// Прямой отчёт не доставлен (сервер ответил Received=false — внутренняя ошибка):
// результат обязан уехать в durable-очередь, которая переживёт перезагрузку и
// доставит его после загрузки. Иначе факт выполненной перезагрузки теряется
// вместе с уходящей вниз машиной.
func TestHandleReboot_FallsBackToOutboxWhenDirectReportNotAcked(t *testing.T) {
	fc := &fakeClient{repNotReceived: true}
	var mu sync.Mutex
	var kinds []string
	enq := func(kind string, _ []byte) error {
		mu.Lock()
		defer mu.Unlock()
		kinds = append(kinds, kind)
		return nil
	}
	e := NewExecutor(nil, quietLog(), "", enq)
	e.connect = func() (pb.AgentServiceClient, func(), error) { return fc, func() {}, nil }
	e.SetRebooter(&fakeRebooter{ret: time.Minute})

	e.Submit(&pb.Task{TaskId: "t-outbox-reboot", Reboot: &pb.RebootCommand{DelaySeconds: 60}})
	waitFor(t, "запись в durable-очередь", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(kinds) == 1
	})
	e.Shutdown()

	if len(fc.resultsCopy()) != 1 {
		t.Errorf("прямая попытка отчёта не сделана: %d", len(fc.resultsCopy()))
	}
}
