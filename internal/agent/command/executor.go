// Package command реализует Command Listener агента: приём Task из Connect-стрима,
// подтверждение доставки (AckTaskReceived), выполнение скрипта и durable-доставку
// результата: TaskResult ставится в устойчивую очередь outbox (переживает обрыв
// связи и рестарт агента), прямой unary ReportTaskResult остаётся фолбэком на
// случай недоступной очереди.
//
// Идемпотентность: доставка Task — at-least-once (Asynq), агент обязан не
// выполнять одну задачу дважды. Дедуп по task_id персистентный (seenSet,
// файл tasks.seen) и фиксирует факт СТАРТА задачи, а не доставки результата:
// сдвиг фиксации на «после доставки» вернул бы двойной запуск скрипта после
// рестарта. Окно «агент упал посреди выполнения» закрывает серверный sweep
// зависших acked-задач (cmd/server, FailStaleAckedTasks).
package command

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/proto"
)

// callTimeout — потолок на unary-вызовы ack/report.
const callTimeout = 30 * time.Second

// maxRuntime — жёсткий потолок на выполнение одного скрипта задачи (захардкожен).
const maxRuntime = 5 * time.Minute

// maxConcurrentTasks — потолок ОДНОВРЕМЕННО исполняемых скриптов задач. Без него
// всплеск Task по стриму спавнил бы неограниченно интерпретаторов от root
// (форк-бомба/исчерпание PID и памяти). Control-plane команды (lock/decommission)
// этим потолком не гейтятся.
const maxConcurrentTasks = 8

// shutdownGrace — сколько ждать завершения текущих задач при остановке агента.
// Равен потолку выполнения: запущенная задача гарантированно успевает закончиться
// (она и так ограничена maxRuntime). Инвариант держится на том, что задачи,
// ждущие слот семафора, при Shutdown НЕ стартуют, а выходят сразу (см. stopping):
// иначе задача, взявшая слот посреди грейса, получила бы урезанное время и
// ложный ERROR при cancel.
const shutdownGrace = maxRuntime

// EnqueueFunc ставит отчёт в устойчивую очередь доставки (outbox.Queue.Enqueue).
// Тот же контракт, что у одноимённого типа в internal/agent/scripts.
type EnqueueFunc func(kind string, data []byte) error

// Executor выполняет задачи, пришедшие от сервера.
type Executor struct {
	dialer  *transport.Dialer
	log     *slog.Logger
	enqueue EnqueueFunc // durable-доставка результата через outbox; nil = только прямой unary

	// execCtx — контекст выполнения задач. НЕ сигнальный: при SIGTERM задачи
	// продолжаются до завершения (грейс), а не убиваются мгновенно. Отменяется
	// в Shutdown по истечении грейса.
	execCtx context.Context
	cancel  context.CancelFunc

	wg sync.WaitGroup // учёт задач «в полёте» для graceful shutdown

	mu        sync.Mutex // защищает accepting и inflight
	accepting bool       // принимаем ли новые задачи
	seen      *seenSet   // идемпотентность по task_id (персистентная)

	// inflight — task_id задач, уже принятых в обработку (включая ждущие слот
	// семафора). Пока задача ждёт слот, она НЕ ack'нута и на сервере остаётся
	// 'pending' — минутный реконсайлер (cmd/server) передоставляет её снова и
	// снова; без дедупа каждая копия спавнила бы горутину, висящую на семафоре
	// с *pb.Task (телом скрипта) в памяти — линейный рост от времени ожидания.
	inflight map[string]struct{}

	// stopping закрывается в начале Shutdown: задачи, ещё не взявшие слот
	// семафора, выходят немедленно (seen не помечен — передоставятся), вместо
	// того чтобы стартовать посреди грейса и получить урезанное время (<
	// maxRuntime) — ложный ERROR при cancel. Это и держит инвариант
	// shutdownGrace == maxRuntime: к началу ожидания остаются только УЖЕ
	// запущенные скрипты, каждый ограничен maxRuntime.
	stopping chan struct{}

	// fallbacks — сколько раз результат ушёл МИМО durable-очереди прямым unary
	// (outbox сломан/недоступен). Кумулятив уходит в каждый лог фолбэка:
	// постоянно сломанный outbox — видимая авария, а не тихая деградация
	// (снаружи «результаты доходят», а durability уже нет).
	fallbacks atomic.Uint64

	// connect возвращает gRPC-клиента и функцию закрытия соединения. Поле (а не
	// прямой dial), чтобы тесты подставляли фейкового клиента. По умолчанию —
	// dialAndClient на основе dialer.
	connect func() (pb.AgentServiceClient, func(), error)

	locker  LockApplier      // применяет команды блокировки устройства (nil = выключено)
	revoker FileVaultRevoker // деструктивный FileVault revoke-chaining (nil = недоступен на этой ОС/сборке)

	// sem ограничивает число одновременно исполняемых скриптов задач
	// (maxConcurrentTasks). Буферизированный канал = взвешенный семафор.
	sem chan struct{}

	// onDecommission сигналит рабочему циклу остановиться и снести агента (сам
	// teardown — service/tamper/файлы — живёт в cmd/agent, ему известны пути).
	// nil = команда decommission отклоняется (сборка/окружение без обвязки).
	onDecommission func(requestID, reason string)
}

// LockApplier применяет команды блокировки/разблокировки устройства (реализуется
// lock.Manager). Вынесен интерфейсом, чтобы executor не зависел от пакета lock и
// тестировался с фейком.
type LockApplier interface {
	Lock(requestID, hash, reason string) error
	Unlock() error
}

// FileVaultRevoker выполняет ДЕСТРУКТИВНУЮ dynamic-revoke-цепочку (G1/G2/G3)
// вместо обычного оверлей-лока — только
// когда LockCommand.lock_mode == LOCK_MODE_FILEVAULT (fail-safe: 0/unknown
// всегда трактуется как OVERLAY, см. proto LockMode doc). Реализуется
// filevault.Chain.RevokeAndShutdown (revoke → durable-доставленный отчёт →
// H3 forced shutdown, строго в этом порядке); вынесен интерфейсом по тому же
// паттерну, что LockApplier.
type FileVaultRevoker interface {
	RevokeAndShutdown(ctx context.Context, requestID string) (pb.LockState, error)
}

// SetLocker подключает применятель блокировок. Вызывать до старта приёма задач.
func (e *Executor) SetLocker(l LockApplier) { e.locker = l }

// SetFileVaultRevoker подключает FileVault revoke-chaining. nil (по умолчанию)
// означает, что lock_mode=FILEVAULT будет отклонён с ошибкой, а не тихо
// выполнен как overlay — см. handleLock.
func (e *Executor) SetFileVaultRevoker(r FileVaultRevoker) { e.revoker = r }

// SetDecommissioner подключает обработчик команды полного самоудаления. nil
// (по умолчанию) → команда decommission отклоняется, а не выполняется тихо.
// Вызывать до старта приёма задач.
func (e *Executor) SetDecommissioner(f func(requestID, reason string)) { e.onDecommission = f }

// NewExecutor creates an executor. statePath — файл для персистентной идемпотентности
// (""=только память). enqueue — durable-очередь доставки результатов (outbox);
// nil = результат уходит прямым unary-вызовом без гарантии доставки.
func NewExecutor(dialer *transport.Dialer, log *slog.Logger, statePath string, enqueue EnqueueFunc) *Executor {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Executor{
		dialer:    dialer,
		log:       log,
		enqueue:   enqueue,
		execCtx:   ctx,
		cancel:    cancel,
		accepting: true,
		seen:      loadSeenSet(statePath),
		inflight:  make(map[string]struct{}),
		stopping:  make(chan struct{}),
		sem:       make(chan struct{}, maxConcurrentTasks),
	}
	e.connect = e.dialAndClient
	return e
}

// dialAndClient — продакшн-реализация connect: dial + gRPC-клиент.
func (e *Executor) dialAndClient() (pb.AgentServiceClient, func(), error) {
	conn, err := e.dialer.Dial()
	if err != nil {
		return nil, nil, err
	}
	return pb.NewAgentServiceClient(conn), func() { conn.Close() }, nil
}

// Submit принимает Task из Connect-стрима и обрабатывает асинхронно, чтобы не
// блокировать heartbeat. Подходит как heartbeat.OnTask.
func (e *Executor) Submit(task *pb.Task) {
	id := task.GetTaskId()
	if id == "" {
		e.log.Warn("получена задача без task_id — пропуск")
		return
	}
	e.mu.Lock()
	if !e.accepting {
		e.mu.Unlock()
		e.log.Warn("агент останавливается — задача отклонена", slog.String("task_id", id))
		return
	}
	if _, dup := e.inflight[id]; dup {
		e.mu.Unlock()
		// Ожидаемый шум: пока задача ждёт слот, сервер передоставляет её каждую
		// минуту (она всё ещё 'pending'). Debug, не Warn — иначе лог зафлудит.
		e.log.Debug("задача уже в обработке — повторная доставка отброшена", slog.String("task_id", id))
		return
	}
	e.inflight[id] = struct{}{}
	e.wg.Add(1)
	e.mu.Unlock()

	go func() {
		defer e.wg.Done()
		defer func() {
			e.mu.Lock()
			delete(e.inflight, id)
			e.mu.Unlock()
		}()
		e.handle(task)
	}()
}

// Shutdown прекращает приём новых задач и ждёт завершения уже запущенных до
// shutdownGrace; по истечении грейса — прерывает их (cancel execCtx).
func (e *Executor) Shutdown() {
	e.mu.Lock()
	if e.accepting {
		e.accepting = false
		// Будим задачи, ждущие слот семафора: им нельзя стартовать посреди
		// грейса (получили бы урезанное время и ложный ERROR) — они выходят,
		// не пометив seen, и передоставятся после рестарта.
		close(e.stopping)
	}
	e.mu.Unlock()

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		e.cancel()
	case <-time.After(shutdownGrace):
		e.log.Warn("graceful shutdown: задачи не успели за грейс — прерываю",
			slog.Duration("grace", shutdownGrace))
		e.cancel()
		e.wg.Wait()
	}
}

func (e *Executor) handle(task *pb.Task) {
	id := task.GetTaskId()

	// Скрипт-задачи гейтим семафором ДО connect/ack/seen. Порядок критичен:
	//  (а) seen помечается ТОЛЬКО после захвата слота — иначе задача, вытесненная
	//      на семафоре при остановке агента (execCtx отменён), осталась бы seen,
	//      но не выполненной, и передоставка after-restart её бы отсекла (потеря);
	//  (б) connect тоже после слота — тысячи ждущих слот горутин иначе держали бы
	//      открытые gRPC-соединения (исчерпание FD/памяти при bulk-push).
	// lock/decommission (control-plane) семафором НЕ гейтим: не форк-бомба и не
	// должны ждать за скриптами.
	if task.GetLock() == nil && task.GetDecommission() == nil {
		select {
		case e.sem <- struct{}{}:
			defer func() { <-e.sem }()
		case <-e.stopping:
			e.log.Warn("task: агент останавливается — скрипт не запущен (seen НЕ помечен, передоставится)", slog.String("task_id", id))
			return
		case <-e.execCtx.Done():
			e.log.Warn("task: агент останавливается — скрипт не запущен (seen НЕ помечен, передоставится)", slog.String("task_id", id))
			return
		}
		// Слот и остановка могли быть готовы одновременно (select выбирает
		// случайно из готовых case) — перепроверяем: скрипт ещё не стартовал,
		// выйти сейчас безопасно, а стартовать в грейс — значит быть убитым
		// посреди выполнения по cancel (см. shutdownGrace).
		select {
		case <-e.stopping:
			e.log.Warn("task: агент останавливается — скрипт не запущен (seen НЕ помечен, передоставится)", slog.String("task_id", id))
			return
		default:
		}
	}

	client, closeConn, err := e.connect()
	if err != nil {
		// seen не помечаем — пусть сервер передоставит (at-least-once).
		e.log.Error("task: соединение", slog.String("task_id", id), slog.Any("error", err))
		return
	}
	defer closeConn()

	// Идемпотентность: повторную доставку подтверждаем (ack мог потеряться),
	// но скрипт второй раз не запускаем. Набор персистентный — переживает рестарт.
	newTask := e.seen.markIfNew(id)
	e.ack(client, id)
	if !newTask {
		e.log.Warn("повторная доставка задачи — выполнение пропущено", slog.String("task_id", id))
		return
	}

	// Команда блокировки устройства приезжает в Task.lock (а не как скрипт).
	if lc := task.GetLock(); lc != nil {
		e.handleLock(client, id, lc)
		return
	}

	// Команда полного самоудаления приезжает в Task.decommission.
	if dc := task.GetDecommission(); dc != nil {
		e.handleDecommission(client, id, dc)
		return
	}

	// Семафор скрипт-задачи уже захвачен в начале handle (см. коммент там).
	e.log.Info("выполняю задачу", slog.String("task_id", id), slog.String("platform", task.GetPlatform()))
	runCtx, cancel := context.WithTimeout(e.execCtx, maxRuntime)
	defer cancel()
	stdout, stderr, runErr := runScript(runCtx, task.GetPlatform(), task.GetScriptContent())

	result := &pb.TaskResult{TaskId: id, Output: stdout}
	if runErr != nil {
		result.Status = pb.TaskStatus_TASK_STATUS_ERROR
		result.ErrorLog = combineErr(stderr, runErr)
		e.log.Warn("задача завершилась ошибкой", slog.String("task_id", id), slog.Any("error", runErr))
	} else {
		result.Status = pb.TaskStatus_TASK_STATUS_SUCCESS
		e.log.Info("задача выполнена успешно", slog.String("task_id", id))
	}
	e.deliver(client, result)
}

// deliver отправляет результат задачи durable-путём: через outbox-очередь, которая
// переживает обрыв связи и рестарт агента (прежний прямой unary-вызов терял
// результат при любом сбое отправки, а строка задачи навсегда зависала в 'acked').
// Повторная/запоздалая доставка для сервера безопасна: CompleteTask скоупится по
// device_id, чужой/устаревший task_id — accept-and-drop (gateway.go).
//
// Прямой ReportTaskResult остаётся фолбэком, когда очередь недоступна (enqueue не
// сконфигурирован или диск отказал): best-effort попытка сейчас лучше
// гарантированной потери. Output/ErrorLog уже обрезаны и санитайзены на источнике
// (runScript → scriptenc), поэтому запись не встанет колом в голове FIFO
// ResourceExhausted'ом.
//
// Известный потолок (общий со scripts.Runner/KindScript, дизайн outbox): очередь
// одна FIFO на все виды отчётов, поэтому при переполнении OutboxMax результат
// может быть вытеснен drop-oldest'ом, а head-of-line блокировка может задержать
// его дольше серверного sweep (15 мин) → ложный 'failed', который затем
// перезапишется верным результатом при доставке. Это лучше прежнего поведения
// (гарантированная потеря при любом сбое отправки), а не хуже.
//
// Серверная сторона этого закрыта: CompleteTask поздний результат ПРИНИМАЕТ (гард
// `status='acked'` сохранял бы ложный 'failed' навсегда и возвращал бы агенту
// ErrTaskNotOwned — по контракту Report*-RPC это poison-pill), но исправление задним
// числом больше не молчаливое: переход failed→completed пишется в аудит как
// late_task_result. Корень же — общая FIFO на все виды отчётов; окончательно он
// лечится раздельными очередями по видам, и это уже агентская сторона.
func (e *Executor) deliver(client pb.AgentServiceClient, result *pb.TaskResult) {
	if e.enqueue == nil {
		e.report(client, result)
		return
	}
	data, err := proto.Marshal(result)
	if err != nil {
		// Не должно случаться (runScript гарантирует валидный UTF-8) — но потерять
		// результат молча нельзя, пробуем хотя бы напрямую.
		e.log.Error("task: сериализация результата — ФОЛБЭК на прямой unary, durability деградировала",
			slog.String("task_id", result.GetTaskId()),
			slog.Uint64("fallback_total", e.fallbacks.Add(1)),
			slog.Any("error", err))
		e.report(client, result)
		return
	}
	if err := e.enqueue(outbox.KindTask, data); err != nil {
		e.log.Error("task: outbox недоступен — ФОЛБЭК на прямой unary, durability деградировала",
			slog.String("task_id", result.GetTaskId()),
			slog.Uint64("fallback_total", e.fallbacks.Add(1)),
			slog.Any("error", err))
		e.report(client, result)
		return
	}
	e.log.Info("task: результат поставлен в очередь доставки", slog.String("task_id", result.GetTaskId()))
}

// handleLock применяет команду блокировки/разблокировки устройства и отчитывается
// серверу (ReportLockStatus) для аудита и UI. lock.Manager идемпотентен по
// request_id, поэтому повторная доставка безопасна.
//
// Корреляционный id: сервер шлёт его в LockCommand.request_id, но приравнивает к
// task_id. Если поле пустое (сервер положил только task_id) — падаем на taskID,
// чтобы идемпотентность и ReportLockStatus всё равно корректно сходились с задачей.
//
// lock_mode == LOCK_MODE_FILEVAULT (и НЕ unlock) — ветвится на e.revoker вместо
// обычного оверлея (proto LockMode doc: fail-safe, 0/unknown всегда OVERLAY, так
// что этот branch срабатывает ТОЛЬКО на явном значении 2). e.revoker == nil →
// ошибка вместо тихой деградации в overlay — сервер уже проверил escrow.Enabled
// перед постановкой такой задачи (handler.go lockDevice), поэтому nil здесь
// означает рассинхрон сборки агента, а не штатный случай.
func (e *Executor) handleLock(client pb.AgentServiceClient, taskID string, lc *pb.LockCommand) {
	reqID := lc.GetRequestId()
	if reqID == "" {
		reqID = taskID
	}
	var (
		err   error
		state pb.LockState
	)
	switch {
	case lc.GetUnlock():
		if e.locker == nil {
			e.log.Error("lock: команда разблокировки получена, но locker не сконфигурирован", slog.String("task_id", taskID))
			return
		}
		err = e.locker.Unlock()
		state = pb.LockState_LOCK_STATE_UNLOCKED
	case lc.GetLockMode() == pb.LockMode_LOCK_MODE_FILEVAULT:
		if e.revoker == nil {
			// Misbuild: revoker недоступен, RevokeAndShutdown не отработает — executor
			// сам репортит FAILED (сервер: actual-state + аудит + алерт IT), чтобы факт
			// не потерялся тихо. Падаем в общий report-блок ниже.
			err = fmt.Errorf("filevault revoker не сконфигурирован на этом агенте (сборка/ОС не поддерживает FileVault-лок)")
			state = pb.LockState_LOCK_STATE_FILEVAULT_REVOKE_FAILED
		} else {
			// RevokeAndShutdown durably репортит САМ и успех (FILEVAULT_REVOKED), и
			// провал (FILEVAULT_REVOKE_FAILED) — блокирующий retry, report.go. Executor
			// НЕ пере-репортит: иначе дубль аудита/алерта + гонка с shutdown -h now
			//. Ошибку только логируем — отчёт уже за revoker'ом.
			if _, rerr := e.revoker.RevokeAndShutdown(e.execCtx, reqID); rerr != nil {
				e.log.Error("lock: filevault RevokeAndShutdown", slog.String("request_id", reqID), slog.Any("error", rerr))
			}
			return
		}
	default:
		if e.locker == nil {
			e.log.Error("lock: команда блокировки получена, но locker не сконфигурирован", slog.String("task_id", taskID))
			return
		}
		err = e.locker.Lock(reqID, lc.GetPasswordHash(), lc.GetReason())
		state = pb.LockState_LOCK_STATE_LOCKED
	}

	details := "ok"
	if err != nil {
		details = err.Error()
		e.log.Error("lock: не удалось применить команду", slog.String("request_id", reqID), slog.Any("error", err))
	}
	ctx, cancel := context.WithTimeout(e.execCtx, callTimeout)
	defer cancel()
	if _, rerr := client.ReportLockStatus(ctx, &pb.ReportLockStatusRequest{
		RequestId:  reqID,
		State:      state,
		OccurredAt: time.Now().Unix(),
		Details:    details,
	}); rerr != nil {
		e.log.Error("lock: ReportLockStatus", slog.String("request_id", reqID), slog.Any("error", rerr))
	}
}

// handleDecommission обрабатывает команду вывода устройства из эксплуатации:
// ПОДТВЕРЖДАЕТ выполнение серверу (ReportTaskResult) и лишь затем сигналит
// рабочему циклу остановиться и снести агента.
//
// Порядок критичен (см. proto DecommissionCommand): отчёт уходит, ПОКА серт ещё
// на диске — сам снос (включая удаление серта) делает cmd/agent уже после
// graceful-остановки цикла. Отчёт шлём напрямую (не через outbox): outbox
// умер бы вместе с состоянием при сносе, а нам нужно подтверждение здесь и
// сейчас. Ошибка отчёта не отменяет снос: недоснесённый агент продолжал бы
// heartbeat'ом воскрешать списанную машину — прекратить heartbeat важнее, чем
// дождаться ack (серверная сторона всё равно отзывает серт по своей логике).
func (e *Executor) handleDecommission(client pb.AgentServiceClient, taskID string, dc *pb.DecommissionCommand) {
	reqID := dc.GetRequestId()
	if reqID == "" {
		reqID = taskID
	}
	if e.onDecommission == nil {
		e.log.Error("decommission: команда получена, но обработчик не сконфигурирован — игнорирую",
			slog.String("task_id", taskID))
		return
	}
	e.log.Warn("decommission: получена команда вывода устройства из эксплуатации",
		slog.String("task_id", taskID), slog.String("request_id", reqID), slog.String("reason", dc.GetReason()))

	// Подтверждаем ДО сноса — иначе отчитываться станет нечем (серт исчезнет).
	ctx, cancel := context.WithTimeout(e.execCtx, callTimeout)
	if _, err := client.ReportTaskResult(ctx, &pb.TaskResult{TaskId: taskID, Status: pb.TaskStatus_TASK_STATUS_SUCCESS}); err != nil {
		e.log.Error("decommission: подтверждение серверу не доставлено — сношусь всё равно (иначе воскрешу списанную машину)",
			slog.String("task_id", taskID), slog.Any("error", err))
	}
	cancel()

	// Сигналим рабочему циклу: остановиться и выполнить teardown (cmd/agent).
	e.onDecommission(reqID, dc.GetReason())
}

func (e *Executor) ack(client pb.AgentServiceClient, id string) {
	ctx, cancel := context.WithTimeout(e.execCtx, callTimeout)
	defer cancel()
	if _, err := client.AckTaskReceived(ctx, &pb.TaskReceivedAck{TaskId: id, ReceivedAt: time.Now().Unix()}); err != nil {
		e.log.Error("task: AckTaskReceived", slog.String("task_id", id), slog.Any("error", err))
	}
}

func (e *Executor) report(client pb.AgentServiceClient, result *pb.TaskResult) {
	ctx, cancel := context.WithTimeout(e.execCtx, callTimeout)
	defer cancel()
	if _, err := client.ReportTaskResult(ctx, result); err != nil {
		e.log.Error("task: ReportTaskResult", slog.String("task_id", result.GetTaskId()), slog.Any("error", err))
	}
}

func combineErr(stderr string, err error) string {
	if stderr == "" {
		return err.Error()
	}
	return stderr + "\n" + err.Error()
}
