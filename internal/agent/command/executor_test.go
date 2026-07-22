package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeClient реализует pb.AgentServiceClient, перехватывая только Ack/Report.
// Остальные методы наследуются от nil-интерфейса и не должны вызываться.
type fakeClient struct {
	pb.AgentServiceClient
	mu          sync.Mutex
	acked       []string
	results     []*pb.TaskResult
	lockReports []*pb.ReportLockStatusRequest
	ackErr      error
	repErr      error
}

func (f *fakeClient) ReportLockStatus(_ context.Context, in *pb.ReportLockStatusRequest, _ ...grpc.CallOption) (*pb.ReportLockStatusResponse, error) {
	f.mu.Lock()
	f.lockReports = append(f.lockReports, in)
	f.mu.Unlock()
	return &pb.ReportLockStatusResponse{}, nil
}

func (f *fakeClient) lockReportsCopy() []*pb.ReportLockStatusRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pb.ReportLockStatusRequest(nil), f.lockReports...)
}

func (f *fakeClient) AckTaskReceived(_ context.Context, in *pb.TaskReceivedAck, _ ...grpc.CallOption) (*pb.TaskReceivedAckResponse, error) {
	f.mu.Lock()
	f.acked = append(f.acked, in.GetTaskId())
	f.mu.Unlock()
	return &pb.TaskReceivedAckResponse{}, f.ackErr
}

func (f *fakeClient) ReportTaskResult(_ context.Context, in *pb.TaskResult, _ ...grpc.CallOption) (*pb.TaskResultAck, error) {
	f.mu.Lock()
	f.results = append(f.results, in)
	f.mu.Unlock()
	return &pb.TaskResultAck{}, f.repErr
}

func (f *fakeClient) ackedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.acked...)
}

func (f *fakeClient) resultsCopy() []*pb.TaskResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pb.TaskResult(nil), f.results...)
}

// waitFor поллит условие до 5с: исполнитель асинхронный, а Shutdown с фиксом
// урезанного грейса НЕ пускает в работу задачи, не успевшие взять слот семафора,
// поэтому завершения задачи тесты ждут ЯВНО, до Shutdown.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}

// newTestExecutor собирает Executor с фейковым connect. statePath="" → дедуп в
// памяти, enqueue=nil → результат прямым unary (фолбэк-путь; durable-путь через
// outbox покрыт TestHandle_ResultEnqueuedToOutbox). Возвращает также счётчик
// вызовов connect.
func newTestExecutor(t *testing.T, fc *fakeClient) (*Executor, *int) {
	t.Helper()
	e := NewExecutor(nil, quietLog(), "", nil)
	var connectCalls int
	var mu sync.Mutex
	e.connect = func() (pb.AgentServiceClient, func(), error) {
		mu.Lock()
		connectCalls++
		mu.Unlock()
		return fc, func() {}, nil
	}
	return e, &connectCalls
}

// Задача без task_id отбрасывается без соединения.
func TestSubmit_EmptyTaskID_Skipped(t *testing.T) {
	fc := &fakeClient{}
	e, connectCalls := newTestExecutor(t, fc)
	e.connect = func() (pb.AgentServiceClient, func(), error) {
		t.Fatal("connect не должен вызываться для задачи без task_id")
		return nil, nil, nil
	}
	e.Submit(&pb.Task{})
	e.Shutdown()
	if *connectCalls != 0 {
		t.Errorf("connect вызван %d раз для пустого task_id", *connectCalls)
	}
}

// После Shutdown новые задачи отклоняются.
func TestSubmit_NotAccepting_Rejected(t *testing.T) {
	fc := &fakeClient{}
	e, connectCalls := newTestExecutor(t, fc)
	e.Shutdown() // accepting=false
	e.Submit(&pb.Task{TaskId: "t-after-shutdown", Platform: "macos", ScriptContent: "echo hi"})
	if *connectCalls != 0 {
		t.Errorf("задача принята после Shutdown (connect вызван %d раз)", *connectCalls)
	}
}

// Happy-path: новая задача подтверждается (ack) и результат уходит как SUCCESS.
func TestHandle_NewTask_AcksAndReportsSuccess(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	e.Submit(&pb.Task{TaskId: "t-ok", Platform: "macos", ScriptContent: "echo hi"})
	waitFor(t, "результат задачи", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	if acks := fc.ackedIDs(); len(acks) != 1 || acks[0] != "t-ok" {
		t.Fatalf("ожидался 1 ack 't-ok', получено %v", acks)
	}
	res := fc.resultsCopy()
	if len(res) != 1 {
		t.Fatalf("ожидался 1 результат, получено %d", len(res))
	}
	if res[0].GetStatus() != pb.TaskStatus_TASK_STATUS_SUCCESS {
		t.Errorf("статус = %v, ожидался SUCCESS", res[0].GetStatus())
	}
}

// Падающий скрипт → результат ERROR с заполненным error_log.
func TestHandle_ScriptError_ReportsError(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	e.Submit(&pb.Task{TaskId: "t-fail", Platform: "macos", ScriptContent: "exit 3"})
	waitFor(t, "результат задачи", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	res := fc.resultsCopy()
	if len(res) != 1 {
		t.Fatalf("ожидался 1 результат, получено %d", len(res))
	}
	if res[0].GetStatus() != pb.TaskStatus_TASK_STATUS_ERROR {
		t.Errorf("статус = %v, ожидался ERROR", res[0].GetStatus())
	}
	if res[0].GetErrorLog() == "" {
		t.Error("error_log пуст для упавшего скрипта")
	}
}

// Повторная доставка ПОСЛЕ завершения задачи: ack дважды (ack первой мог
// потеряться), но скрипт выполняется один раз (персистентный seen-дедуп).
func TestHandle_DuplicateTask_AcksButRunsOnce(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	task := &pb.Task{TaskId: "t-dup", Platform: "macos", ScriptContent: "echo hi"}
	e.Submit(task)
	waitFor(t, "результат первой доставки", func() bool { return len(fc.resultsCopy()) == 1 })
	// Ждать одного результата мало: он пишется ПОСРЕДИ handle, а inflight
	// чистится после его возврата — второй Submit в этот зазор попал бы в
	// inflight-дедуп (молчаливый drop без ack) вместо целевого seen-дедупа.
	waitFor(t, "очистка inflight", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		_, ok := e.inflight["t-dup"]
		return !ok
	})
	e.Submit(task) // in-flight уже нет — доставка доходит до seen-дедупа и ack'ается
	waitFor(t, "ack второй доставки", func() bool { return len(fc.ackedIDs()) == 2 })
	e.Shutdown()

	if res := fc.resultsCopy(); len(res) != 1 {
		t.Errorf("ожидался 1 результат (вторая доставка — дедуп), получено %d", len(res))
	}
}

// Повторная доставка, пока первая копия ещё ЖДЁТ слот семафора, отбрасывается
// молча (без ack и без второй горутины): сервер передоставляет pending-задачу
// каждую минуту, и без in-flight-дедупа горутины с телом скрипта копились бы
// линейно от времени ожидания слота.
func TestSubmit_DuplicateInflight_Dropped(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	for i := 0; i < maxConcurrentTasks; i++ {
		e.sem <- struct{}{} // забить все слоты: первая копия повиснет на семафоре
	}

	task := &pb.Task{TaskId: "t-inflight", Platform: "macos", ScriptContent: "echo hi"}
	e.Submit(task)
	waitFor(t, "первая копия в inflight", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		_, ok := e.inflight["t-inflight"]
		return ok
	})
	e.Submit(task) // копия передоставки — должна быть отброшена без ack

	// Освобождаем слоты — первая копия исполняется, вторая не существует.
	for i := 0; i < maxConcurrentTasks; i++ {
		<-e.sem
	}
	waitFor(t, "результат задачи", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	if acks := fc.ackedIDs(); len(acks) != 1 {
		t.Errorf("ожидался ровно 1 ack (копия отброшена до соединения), получено %v", acks)
	}
	if res := fc.resultsCopy(); len(res) != 1 {
		t.Errorf("ожидался 1 результат, получено %d", len(res))
	}
	// Задача завершилась — inflight очищен, слот семафора возвращён (без этого
	// 8 «застрявших» задач навсегда глушили бы скрипт-канал машины).
	e.mu.Lock()
	if _, ok := e.inflight["t-inflight"]; ok {
		t.Error("inflight не очищен после завершения задачи")
	}
	e.mu.Unlock()
	waitFor(t, "возврат слота семафора", func() bool { return len(e.sem) == 0 })
}

// Слоты семафора ВОЗВРАЩАЮТСЯ: волна задач больше ёмкости семафора полностью
// исполняется (утечка слота глушила бы всё после первых maxConcurrentTasks).
func TestHandle_SemaphoreSlotsRecycled(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	n := 2*maxConcurrentTasks + 1
	for i := 0; i < n; i++ {
		e.Submit(&pb.Task{TaskId: fmt.Sprintf("t-wave-%d", i), Platform: "macos", ScriptContent: "echo hi"})
	}
	waitFor(t, "результаты всей волны", func() bool { return len(fc.resultsCopy()) == n })
	waitFor(t, "возврат всех слотов", func() bool { return len(e.sem) == 0 })
	e.Shutdown()
}

// Задача, ждущая слот семафора в момент Shutdown, НЕ стартует посреди грейса
// (получила бы урезанное время и ложный ERROR при cancel): выходит сразу, seen
// не помечен, ack не отправлен — сервер передоставит после рестарта. Shutdown
// при этом возвращается быстро, не выжидая весь грейс.
func TestShutdown_QueuedTaskBailsWithoutStart(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	for i := 0; i < maxConcurrentTasks; i++ {
		e.sem <- struct{}{} // все слоты заняты «долгими скриптами»
	}

	e.Submit(&pb.Task{TaskId: "t-queued", Platform: "macos", ScriptContent: "echo hi"})
	waitFor(t, "задача в inflight", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		_, ok := e.inflight["t-queued"]
		return ok
	})

	done := make(chan struct{})
	go func() {
		e.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown не вернулся: ждущая слот задача не вышла по stopping")
	}

	if !e.seen.markIfNew("t-queued") {
		t.Fatal("задача помечена seen, хотя не выполнялась — передоставка её отсечёт")
	}
	if len(fc.ackedIDs()) != 0 {
		t.Fatalf("задача заacked, хотя скрипт не стартовал: %v", fc.ackedIDs())
	}
	if len(fc.resultsCopy()) != 0 {
		t.Fatalf("результат отправлен для незапущенной задачи: %v", fc.resultsCopy())
	}
}

// Конкурентные Submit, гонящиеся с Shutdown: проверяем синхронизацию accepting/wg
// (запускать с -race). Инвариант — никакой паники/гонки; число результатов не
// превышает числа ack, а ack — числа поданных задач.
func TestConcurrentSubmitDuringShutdown(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	const n = 40
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			e.Submit(&pb.Task{
				TaskId:        fmt.Sprintf("t-%d", i),
				Platform:      "macos",
				ScriptContent: "echo hi",
			})
		}(i)
	}
	// Останавливаем исполнитель, пока часть сабмитов ещё в полёте.
	go e.Shutdown()

	wg.Wait()
	e.Shutdown() // дренируем оставшиеся принятые задачи (идемпотентно)

	acks := len(fc.ackedIDs())
	res := len(fc.resultsCopy())
	if acks > n {
		t.Fatalf("ack больше числа поданных задач: acks=%d n=%d", acks, n)
	}
	if res > acks {
		t.Fatalf("результатов больше, чем ack: res=%d acks=%d", res, acks)
	}
}

// Результат уходит durable-путём: одна запись KindTask в очереди, прямой
// ReportTaskResult при живой очереди не вызывается, payload — валидный TaskResult.
func TestHandle_ResultEnqueuedToOutbox(t *testing.T) {
	fc := &fakeClient{}
	var mu sync.Mutex
	var kinds []string
	var payloads [][]byte
	enq := func(kind string, data []byte) error {
		mu.Lock()
		defer mu.Unlock()
		kinds = append(kinds, kind)
		payloads = append(payloads, data)
		return nil
	}
	e := NewExecutor(nil, quietLog(), "", enq)
	e.connect = func() (pb.AgentServiceClient, func(), error) { return fc, func() {}, nil }

	e.Submit(&pb.Task{TaskId: "t-outbox", Platform: "macos", ScriptContent: "echo durable-ok"})
	waitFor(t, "запись в outbox", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(kinds) == 1
	})
	e.Shutdown()

	if n := len(fc.resultsCopy()); n != 0 {
		t.Errorf("прямой ReportTaskResult не должен вызываться при живой очереди, вызовов %d", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(kinds) != 1 || kinds[0] != outbox.KindTask {
		t.Fatalf("ожидалась 1 запись вида %q, получено %v", outbox.KindTask, kinds)
	}
	var res pb.TaskResult
	if err := proto.Unmarshal(payloads[0], &res); err != nil {
		t.Fatalf("payload не распарсился как TaskResult: %v", err)
	}
	if res.GetTaskId() != "t-outbox" || res.GetStatus() != pb.TaskStatus_TASK_STATUS_SUCCESS {
		t.Errorf("TaskResult = {task_id:%q status:%v}, ожидался t-outbox/SUCCESS",
			res.GetTaskId(), res.GetStatus())
	}
	if !strings.Contains(res.GetOutput(), "durable-ok") {
		t.Errorf("output = %q, ожидали вывод скрипта", res.GetOutput())
	}
}

// Очередь недоступна (диск отказал) — результат не теряется молча: фолбэк на
// прямую отправку ReportTaskResult.
func TestHandle_EnqueueError_FallsBackToDirectReport(t *testing.T) {
	fc := &fakeClient{}
	enq := func(string, []byte) error { return errors.New("disk full") }
	e := NewExecutor(nil, quietLog(), "", enq)
	e.connect = func() (pb.AgentServiceClient, func(), error) { return fc, func() {}, nil }

	e.Submit(&pb.Task{TaskId: "t-fallback", Platform: "macos", ScriptContent: "echo hi"})
	waitFor(t, "прямой отчёт-фолбэк", func() bool { return len(fc.resultsCopy()) == 1 })
	e.Shutdown()

	res := fc.resultsCopy()
	if len(res) != 1 || res[0].GetTaskId() != "t-fallback" {
		t.Fatalf("ожидался 1 прямой ReportTaskResult (фолбэк), получено %v", res)
	}
	// Фолбэк — видимая авария: кумулятивный счётчик обязан тикнуть (уходит в
	// каждый лог фолбэка, чтобы сломанный outbox не был тихой деградацией).
	if got := e.fallbacks.Load(); got != 1 {
		t.Errorf("fallbacks = %d, want 1", got)
	}
}

// Команда decommission: агент ПОДТВЕРЖДАЕТ выполнение серверу (ReportTaskResult
// SUCCESS) и зовёт обработчик самоудаления — ровно один раз, с request_id.
func TestHandle_Decommission_ReportsThenInvokesHandler(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	var mu sync.Mutex
	var gotReq, gotReason string
	var calls int
	e.SetDecommissioner(func(reqID, reason string) {
		mu.Lock()
		calls++
		gotReq, gotReason = reqID, reason
		mu.Unlock()
	})

	e.Submit(&pb.Task{TaskId: "t-decom", Decommission: &pb.DecommissionCommand{RequestId: "req-9", Reason: "увольнение"}})
	e.Shutdown()

	res := fc.resultsCopy()
	if len(res) != 1 || res[0].GetTaskId() != "t-decom" || res[0].GetStatus() != pb.TaskStatus_TASK_STATUS_SUCCESS {
		t.Fatalf("ожидался 1 ReportTaskResult SUCCESS до сноса, получено %v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("обработчик самоудаления вызван %d раз, ожидался 1", calls)
	}
	if gotReq != "req-9" || gotReason != "увольнение" {
		t.Errorf("обработчик получил (%q,%q), ожидалось (req-9, увольнение)", gotReq, gotReason)
	}
}

// request_id пустой → падаем на task_id (идемпотентность/аудит всё равно сходятся).
func TestHandle_Decommission_EmptyRequestIDFallsBackToTaskID(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	var gotReq string
	e.SetDecommissioner(func(reqID, _ string) { gotReq = reqID })

	e.Submit(&pb.Task{TaskId: "t-noreq", Decommission: &pb.DecommissionCommand{}})
	e.Shutdown()

	if gotReq != "t-noreq" {
		t.Errorf("request_id = %q, ожидался фолбэк на task_id t-noreq", gotReq)
	}
}

// Обработчик не сконфигурирован → команда игнорируется, отчёт SUCCESS не шлётся
// (агент не сносится тихо).
func TestHandle_Decommission_NoHandler_Ignored(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)

	e.Submit(&pb.Task{TaskId: "t-nohandler", Decommission: &pb.DecommissionCommand{RequestId: "r"}})
	e.Shutdown()

	if len(fc.resultsCopy()) != 0 {
		t.Errorf("без обработчика decommission отчёт слаться не должен, получено %v", fc.resultsCopy())
	}
}

// Ошибки ack/report лишь логируются — handle не должен паниковать и доводит
// задачу до конца.
func TestHandle_AckAndReportErrors_AreLogged(t *testing.T) {
	fc := &fakeClient{ackErr: errors.New("ack rpc failed"), repErr: errors.New("report rpc failed")}
	e, _ := newTestExecutor(t, fc)

	e.Submit(&pb.Task{TaskId: "t-rpcerr", Platform: "macos", ScriptContent: "echo hi"})
	waitFor(t, "ack и report несмотря на ошибки RPC", func() bool {
		return len(fc.ackedIDs()) == 1 && len(fc.resultsCopy()) == 1
	})
	e.Shutdown()

	if len(fc.ackedIDs()) != 1 {
		t.Errorf("ack должен был быть вызван несмотря на ошибку, вызовов %d", len(fc.ackedIDs()))
	}
	if len(fc.resultsCopy()) != 1 {
		t.Errorf("report должен был быть вызван несмотря на ошибку, вызовов %d", len(fc.resultsCopy()))
	}
}

// Ошибка соединения: задача не выполняется, ack не шлётся, seen не помечается
// (сервер передоставит) — следующая доставка выполнит её. Зовём handle напрямую,
// чтобы не завершать исполнитель Shutdown'ом между попытками.
func TestHandle_ConnectError_NoAckNoSeen(t *testing.T) {
	fc := &fakeClient{}
	e := NewExecutor(nil, quietLog(), "", nil)
	fail := true
	e.connect = func() (pb.AgentServiceClient, func(), error) {
		if fail {
			return nil, nil, errors.New("dial failed")
		}
		return fc, func() {}, nil
	}

	task := &pb.Task{TaskId: "t-retry", Platform: "macos", ScriptContent: "echo hi"}
	e.handle(task) // connect падает
	if len(fc.ackedIDs()) != 0 {
		t.Fatal("ack отправлен несмотря на ошибку соединения")
	}

	// Связь восстановилась — повторная доставка должна выполниться (seen не помечен).
	fail = false
	e.handle(task)
	if res := fc.resultsCopy(); len(res) != 1 {
		t.Errorf("после восстановления связи задача должна выполниться один раз, результатов %d", len(res))
	}
}

// gatedLocker — Lock блокируется до close(release): имитация control-plane
// handle без потолка времени (FileVault RevokeAndShutdown с durable-retry).
type gatedLocker struct {
	release chan struct{}
	mu      sync.Mutex
	locks   int
}

func (g *gatedLocker) Lock(requestID, hash, reason string) error {
	g.mu.Lock()
	g.locks++
	g.mu.Unlock()
	<-g.release
	return nil
}

func (g *gatedLocker) Unlock() error { return nil }

func (g *gatedLocker) lockCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.locks
}

// №4.5: повторная доставка задачи, которая уже СТАРТОВАЛА (seen помечен), но
// всё ещё в полёте, обязана ПЕРЕПОДТВЕРЖДАТЬСЯ (ack) без выполнения — а не
// глотаться inflight-дедупом молча. Иначе при потерянном первом ack задача с
// висящим control-plane handle (lock/decommission семафором не гейтятся, их
// handle не ограничен) оставалась бы на сервере вечно 'pending', а все
// передоставки — механизм восстановления ack — отбрасывались бы.
func TestSubmit_DuplicateInflightSeen_Reacks(t *testing.T) {
	fc := &fakeClient{}
	e, _ := newTestExecutor(t, fc)
	release := make(chan struct{})
	gl := &gatedLocker{release: release}
	e.SetLocker(gl)

	task := &pb.Task{TaskId: "t-hung", Lock: &pb.LockCommand{
		RequestId: "req-hung", PasswordHash: "$2a$hash",
	}}
	e.Submit(task)
	// Первая копия: ack отправлен (после markIfNew), handleLock повис в Lock.
	waitFor(t, "ack первой доставки", func() bool { return len(fc.ackedIDs()) == 1 })
	waitFor(t, "handle повис в Lock", func() bool { return gl.lockCount() == 1 })

	e.Submit(task) // передоставка при живом inflight и помеченном seen
	waitFor(t, "переподтверждение ack", func() bool { return len(fc.ackedIDs()) == 2 })

	if got := gl.lockCount(); got != 1 {
		t.Errorf("копия не должна выполняться: Lock вызван %d раз", got)
	}
	close(release)
	e.Shutdown()
	if got := gl.lockCount(); got != 1 {
		t.Errorf("после завершения Lock вызван %d раз, ожидали 1", got)
	}
}
