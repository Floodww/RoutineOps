package command

import (
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

// #14: скрипт-задача, вытесненная на семафоре при остановке агента (execCtx
// отменён до захвата слота), НЕ должна помечаться seen — иначе передоставка
// after-restart отсекла бы её, и результат не пришёл бы никогда. Семафор полон,
// поэтому send всегда блокируется, и после cancel select обязан выбрать
// execCtx.Done() (тест не зависит от тайминга).
func TestHandle_ScriptNotSeenIfCancelledWaitingOnSemaphore(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	for i := 0; i < maxConcurrentTasks; i++ {
		e.sem <- struct{}{} // забить все слоты
	}

	done := make(chan struct{})
	go func() {
		e.handle(&pb.Task{TaskId: "t-script", ScriptContent: "echo hi", Platform: "linux"})
		close(done)
	}()

	time.Sleep(50 * time.Millisecond) // дать горутине дойти до select на семафоре
	e.cancel()                        // как Shutdown по истечении грейса

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handle не вернулся после отмены execCtx")
	}

	if !e.seen.markIfNew("t-script") {
		t.Fatal("задача помечена seen, хотя не выполнялась — передоставка её отсечёт (#14)")
	}
	if len(fc.ackedIDs()) != 0 {
		t.Fatalf("задача заacked до захвата слота семафора: %v", fc.ackedIDs())
	}
}

// #14: lock/decommission (control-plane) НЕ гейтятся семафором — применяются
// сразу, даже когда все слоты заняты долгими скриптами.
func TestHandle_LockNotGatedBySemaphore(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	fl := &fakeLocker{}
	e.SetLocker(fl)
	for i := 0; i < maxConcurrentTasks; i++ {
		e.sem <- struct{}{} // все слоты заняты
	}

	done := make(chan struct{})
	go func() {
		e.handle(&pb.Task{
			TaskId: "t-lock",
			Lock:   &pb.LockCommand{RequestId: "r1", PasswordHash: "hash", Reason: "увольнение"},
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("lock-задача заблокирована семафором — control-plane не должен ждать за скриптами (#14)")
	}
	if len(fl.lockCalls()) != 1 {
		t.Fatalf("lock не применён при полном семафоре: %v", fl.lockCalls())
	}
}
