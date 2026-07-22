package command

import (
	"errors"
	"sync"
	"testing"

	pb "github.com/Floodww/RoutineOps/proto"
)

// fakeLocker записывает применённые команды блокировки.
type fakeLocker struct {
	mu      sync.Mutex
	locks   []lockCall
	unlocks int
	err     error
}

type lockCall struct{ requestID, hash, reason string }

func (f *fakeLocker) Lock(requestID, hash, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.locks = append(f.locks, lockCall{requestID, hash, reason})
	return f.err
}

func (f *fakeLocker) Unlock() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unlocks++
	return f.err
}

func (f *fakeLocker) lockCalls() []lockCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]lockCall(nil), f.locks...)
}

// Команда блокировки (Task.lock) применяется через locker, отчёт LOCKED уходит,
// скрипт НЕ выполняется (результата задачи нет).
func TestHandle_LockTask_AppliesAndReports(t *testing.T) {
	fc := &fakeClient{}
	fl := &fakeLocker{}
	e, _ := newTestExecutor(t, fc)
	e.SetLocker(fl)

	e.Submit(&pb.Task{TaskId: "t-lock", Lock: &pb.LockCommand{
		RequestId: "req-1", PasswordHash: "$2a$hash", Reason: "Нарушение ИБ",
	}})
	e.Shutdown()

	calls := fl.lockCalls()
	if len(calls) != 1 || calls[0] != (lockCall{"req-1", "$2a$hash", "Нарушение ИБ"}) {
		t.Fatalf("ожидали один Lock с проброшенными полями, got %v", calls)
	}
	if fl.unlocks != 0 {
		t.Fatalf("Unlock не должен вызываться при блокировке: %d", fl.unlocks)
	}
	if res := fc.resultsCopy(); len(res) != 0 {
		t.Fatalf("команда блокировки не должна давать ReportTaskResult: %v", res)
	}
	rep := fc.lockReportsCopy()
	if len(rep) != 1 || rep[0].GetState() != pb.LockState_LOCK_STATE_LOCKED || rep[0].GetRequestId() != "req-1" {
		t.Fatalf("ожидали отчёт LOCKED по req-1, got %v", rep)
	}
}

// Команда разблокировки (Task.lock.unlock=true) → Unlock + отчёт UNLOCKED.
func TestHandle_UnlockTask_AppliesAndReports(t *testing.T) {
	fc := &fakeClient{}
	fl := &fakeLocker{}
	e, _ := newTestExecutor(t, fc)
	e.SetLocker(fl)

	e.Submit(&pb.Task{TaskId: "t-unlock", Lock: &pb.LockCommand{RequestId: "req-1", Unlock: true}})
	e.Shutdown()

	if fl.unlocks != 1 || len(fl.lockCalls()) != 0 {
		t.Fatalf("ожидали один Unlock и ноль Lock: unlocks=%d locks=%v", fl.unlocks, fl.lockCalls())
	}
	rep := fc.lockReportsCopy()
	if len(rep) != 1 || rep[0].GetState() != pb.LockState_LOCK_STATE_UNLOCKED {
		t.Fatalf("ожидали отчёт UNLOCKED, got %v", rep)
	}
}

// Без сконфигурированного locker команда блокировки не паникует и не отчитывается.
func TestHandle_LockTask_NoLocker(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc) // SetLocker не вызывали

	e.Submit(&pb.Task{TaskId: "t-lock", Lock: &pb.LockCommand{RequestId: "req-1"}})
	e.Shutdown()

	if acks := fc.ackedIDs(); len(acks) != 1 {
		t.Fatalf("ack должен уйти даже без locker: %v", acks)
	}
	if rep := fc.lockReportsCopy(); len(rep) != 0 {
		t.Fatalf("без locker отчёта быть не должно: %v", rep)
	}
}

// Если LockCommand.request_id пустой — используется task_id как фолбэк, чтобы
// идемпотентность lock.Manager и RequestId в ReportLockStatus совпали.
func TestHandle_LockTask_RequestIDFallback(t *testing.T) {
	fc := &fakeClient{}
	fl := &fakeLocker{}
	e, _ := newTestExecutor(t, fc)
	e.SetLocker(fl)

	e.Submit(&pb.Task{TaskId: "t-fallback", Lock: &pb.LockCommand{
		// RequestId намеренно пуст — должен использоваться TaskId.
		PasswordHash: "$2a$hash", Reason: "тест фолбэка",
	}})
	e.Shutdown()

	calls := fl.lockCalls()
	if len(calls) != 1 || calls[0].requestID != "t-fallback" {
		t.Fatalf("Lock должен использовать task_id как фолбэк, got requestID=%q", func() string {
			if len(calls) > 0 {
				return calls[0].requestID
			}
			return "(нет вызовов)"
		}())
	}
	rep := fc.lockReportsCopy()
	if len(rep) != 1 || rep[0].GetRequestId() != "t-fallback" {
		t.Fatalf("ReportLockStatus.request_id должен быть task_id-фолбэком, got %v", rep)
	}
}

// #1.2: Lock() отказал → handleLock НЕ репортит никакого состояния. LOCKED был бы
// ложью (панель показывает «заблокировано» при рабочей машине), а UNLOCKED стёр бы
// desired=locked на сервере (overlay-UNLOCKED → SetDeviceLockState ”) — транзиентный
// сбой навсегда разоружил бы kill-switch. desired держим целым; pull-реконсилятор
// доводит ретраем (Manager.Lock атомарен).
func TestHandle_LockTask_NoReportOnFailure(t *testing.T) {
	fc := &fakeClient{}
	fl := &fakeLocker{err: errors.New("невалидный password_hash")}
	e, _ := newTestExecutor(t, fc)
	e.SetLocker(fl)

	e.Submit(&pb.Task{TaskId: "t-lockfail", Lock: &pb.LockCommand{
		RequestId: "req-fail", PasswordHash: "",
	}})
	e.Shutdown()

	if reports := fc.lockReportsCopy(); len(reports) != 0 {
		t.Fatalf("при отказе Lock отправлено %d отчёт(ов) (State=%v) — desired на сервере мог быть стёрт (kill-switch)", len(reports), reports[0].GetState())
	}
}
