package lock

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/proto"
)

const fetchTimeout = 30 * time.Second

// Reconciler периодически сверяет локальное состояние блокировки с ЖЕЛАЕМЫМ
// состоянием сервера (FetchLockStatus, pull). Нужен, потому что канал команды
// блокировки push-only: LockCommand едет РАЗ задачей по Connect-стриму, без
// повторной сверки. После рестарта агента (в т.ч. ребута машины) сервер мог
// сохранять lock_status=locked, пока локальный lock.json уже unlocked (или
// наоборот) — Reconciler сводит их так же, как admin.Manager сводит статус
// временных прав через FetchAdminStatus.
type Reconciler struct {
	mgr      *Manager
	interval time.Duration
	log      *slog.Logger
	fetch    func(context.Context) (*pb.FetchLockStatusResponse, error)
	report   func(context.Context, *pb.ReportLockStatusRequest) error
	revoker  FileVaultRevoker // деструктивный FileVault revoke-chaining (nil = недоступен на этой ОС/сборке)

	mu sync.Mutex
	// lastUnlockedHash — хеш лока, снятого ЛОКАЛЬНО (верный пароль на экране или
	// оффлайн-обнаружение), через OnLocalUnlock. Пока сервер не догнал этот отчёт
	// (durable, но не мгновенный — через outbox), его desired-состояние ещё
	// показывает locked с ЭТИМ ЖЕ хешем; без этой памяти реконсиляция заблокировала
	// бы устройство заново тут же после легитимного снятия.
	lastUnlockedHash string

	// durableReported — hash, для которого уже отправлен повторный UNLOCKED-отчёт
	// при skip'е по DURABLE-памяти (см. reconcileLocked, #7): отчёт идемпотентен и
	// достаточно одного на hash за жизнь процесса — доставку до сервера гарантирует
	// outbox, а слать дубликат каждые 30с при офлайне значит забивать очередь.
	durableReported string

	// applyFailReported/applyFailSet — дедуп ЛОГА о провале применения
	// desired=locked (пустой/битый hash от сервера #1.1, транзиентный отказ
	// persist). Тик крутит ретрай каждые 30с; без дедупа лог провала флудил бы
	// LevelError на каждом тике. Сбрасывается, когда лок применён или desired стал
	// unlocked. Серверу о провале НЕ отчитываемся: UNLOCKED стёр бы desired
	// (разоружил kill-switch), а actual-only канал требует нового proto-состояния.
	applyFailReported string
	applyFailSet      bool

	// fvInFlight/fvWG — одиночный фоновый воркер FileVault-revoke:
	// RevokeAndShutdown держит блокирующий durable ReportState
	// (backoff 1с→2мин до успеха или agent-lifetime ctx) — инлайн-вызов из tick
	// замораживал бы ВСЮ реконсиляцию (и lock, и unlock) на всё это время.
	fvInFlight atomic.Bool
	fvWG       sync.WaitGroup
}

// FileVaultRevoker — см. command.FileVaultRevoker (та же роль, отдельная
// копия интерфейса на стороне pull-реконсиляции — оба структурно
// удовлетворяются одним *filevault.Chain, см. cmd/agent/main.go).
type FileVaultRevoker interface {
	RevokeAndShutdown(ctx context.Context, requestID string) (pb.LockState, error)
}

// SetFileVaultRevoker подключает FileVault revoke-chaining к pull-пути
// (FetchLockStatus). nil (по умолчанию) — reconcileLocked отклонит
// lock_mode=FILEVAULT с логом ошибки вместо тихой деградации в overlay.
func (r *Reconciler) SetFileVaultRevoker(rv FileVaultRevoker) { r.revoker = rv }

// NewReconciler собирает Reconciler с боевыми зависимостями: FetchLockStatus —
// напрямую через dialer (при обрыве просто повторяется на следующем тике, как
// FetchAdminStatus); ReportLockStatus — durably через outbox (терять отчёт о
// снятии блокировки нельзя, иначе следующий тик пере-заблокирует устройство,
// которое сотрудник уже легитимно разблокировал — это и есть полевой баг).
func NewReconciler(mgr *Manager, dialer *transport.Dialer, enqueue func(kind string, data []byte) error,
	interval time.Duration, log *slog.Logger) *Reconciler {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Reconciler{
		mgr:      mgr,
		interval: interval,
		log:      log,
		fetch: func(ctx context.Context) (*pb.FetchLockStatusResponse, error) {
			conn, err := dialer.Dial()
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
			defer cancel()
			return pb.NewAgentServiceClient(conn).FetchLockStatus(ctx, &pb.FetchLockStatusRequest{})
		},
		report: func(_ context.Context, req *pb.ReportLockStatusRequest) error {
			data, err := proto.Marshal(req)
			if err != nil {
				return err
			}
			return enqueue(outbox.KindLock, data)
		},
	}
}

// OnLocalUnlock — колбэк для Manager.Run: вызывается, когда лок снят локально
// (верный пароль на экране лока или оффлайн-обнаружение внешнего изменения
// файла). Запоминает хеш снятого лока (см. lastUnlockedHash) и durably
// отчитывается серверу через outbox, заменяя прежний best-effort прямой вызов
// ReportLockStatus — потеря этого отчёта была первопричиной полевого re-lock-
// после-ребута бага (сервер оставался думать locked, реконсиляция пере-запирала).
func (r *Reconciler) OnLocalUnlock(requestID, hash string) {
	r.mu.Lock()
	r.lastUnlockedHash = hash
	r.mu.Unlock()

	if err := r.report(context.Background(), &pb.ReportLockStatusRequest{
		RequestId:  requestID,
		State:      pb.LockState_LOCK_STATE_UNLOCKED,
		OccurredAt: time.Now().Unix(),
		Details:    "offline unlock",
	}); err != nil {
		r.log.Error("lock: ReportLockStatus(UNLOCKED) в outbox", slog.Any("error", err))
	}
}

// Run крутит фоновую реконсиляцию до отмены ctx. Перед выходом дожидается
// фонового FileVault-воркера (тот завершается сам: ReportState выходит по
// ctx.Done) — горутина не переживает Run.
func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.fvWG.Wait()
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

func (r *Reconciler) tick(ctx context.Context) {
	resp, err := r.fetch(ctx)
	if err != nil {
		r.log.Error("lock: FetchLockStatus", slog.Any("error", err))
		return
	}

	if resp.GetLocked() {
		r.reconcileLocked(ctx, resp)
		return
	}
	r.reconcileUnlocked(ctx)
}

// reconcileLocked применяет желаемое состояние "locked", если локальное с ним
// расходится. Пропускает пере-блокировку, если это тот же лок, что был только
// что снят локально (сервер ещё не догнал отчёт о снятии, см. OnLocalUnlock).
//
// lock_mode=FILEVAULT ветвится ДО overlay-специфичной dedup-логики ниже
// (lastUnlockedHash/mgr.CurrentHash — понятия lock.Manager/lock.json, к
// FileVault-цепочке неприменимые): идемпотентность там своя, встроенная в
// filevault.Chain (enumerate-all ничего не находит на повторных тиках) — см.
// proto LockMode doc, fail-safe 0/unknown всегда OVERLAY.
func (r *Reconciler) reconcileLocked(ctx context.Context, resp *pb.FetchLockStatusResponse) {
	hash := resp.GetPasswordHash()

	if resp.GetLockMode() == pb.LockMode_LOCK_MODE_FILEVAULT {
		if r.revoker == nil {
			r.log.Error("lock: реконсиляция получила lock_mode=FILEVAULT, но revoker не сконфигурирован")
			return
		}
		// M4: в отдельной горутине — RevokeAndShutdown может блокироваться до
		// agent-lifetime ctx (durable ReportState при недоступном сервере), а
		// тик обязан жить дальше. Повторные тики при живом воркере — no-op:
		// Chain.mu и так сериализует вызовы, но копить на нём заблокированные
		// горутины (по одной на тик) незачем. ctx тика = ctx Run'а
		// (agent-lifetime) — ровно тот, что требует ReportState.
		if !r.fvInFlight.CompareAndSwap(false, true) {
			return
		}
		r.fvWG.Add(1)
		go func() {
			defer r.fvWG.Done()
			defer r.fvInFlight.Store(false)
			state, err := r.revoker.RevokeAndShutdown(ctx, hash)
			if err != nil {
				r.log.Error("lock: reconcile RevokeAndShutdown", slog.Any("error", err))
				return
			}
			r.log.Warn("lock: реконсиляция применила desired-состояние FILEVAULT", slog.String("state", state.String()))
		}()
		return
	}

	r.mu.Lock()
	skip := hash != "" && hash == r.lastUnlockedHash
	r.mu.Unlock()
	if skip {
		return
	}
	// Durable-память снятого лока (переживает ребут, #4): in-memory
	// lastUnlockedHash после рестарта пуст, но Manager хранит hash последнего
	// локального снятия в защищённом каталоге состояния — не даём пере-запереть
	// по устаревшему desired, пока сервер не догнал UNLOCKED-отчёт из outbox.
	//
	// Молчать при этом нельзя (#7): «desired=locked, а локально unlocked» —
	// расхождение, которое обязано быть видимым и самозавершающимся. Warn +
	// повторный идемпотентный UNLOCKED-отчёт (durable, через outbox; одного на
	// hash достаточно — доставку гарантирует сама очередь): либо сервер догонит
	// и очистит desired (skip кончится сам), либо оператор увидит правду в
	// логе и панели вместо вечного тихого return.
	if hash != "" && hash == r.mgr.LastUnlockedHash() {
		r.mu.Lock()
		already := r.durableReported == hash
		r.durableReported = hash
		r.mu.Unlock()
		if !already {
			r.log.Warn("lock: desired=locked подавлен durable-памятью локального снятия — повторяю UNLOCKED-отчёт серверу",
				slog.String("request_id", hash))
			if err := r.report(ctx, &pb.ReportLockStatusRequest{
				RequestId:  hash,
				State:      pb.LockState_LOCK_STATE_UNLOCKED,
				OccurredAt: time.Now().Unix(),
				Details:    "reconcile: desired=locked suppressed by durable local-unlock memory",
			}); err != nil {
				r.log.Error("lock: ReportLockStatus(UNLOCKED) в outbox", slog.Any("error", err))
				r.mu.Lock()
				if r.durableReported == hash {
					r.durableReported = "" // не встал даже в очередь — повторим на следующем тике
				}
				r.mu.Unlock()
			}
		}
		return
	}

	if r.mgr.Locked() && r.mgr.CurrentHash() == hash {
		return // уже применён этот же лок
	}

	if err := r.mgr.Lock(hash, hash, resp.GetReason()); err != nil {
		// Лок ФИЗИЧЕСКИ не поднят: пустой/битый password_hash от сервера (#1.1,
		// validateBcryptHash #13) или транзиентный отказ persist (ENOSPC/EIO/AV/
		// sharing-violation). Громко логируем (LevelError виден в проде) — прежний
		// молчок обнаруживался только чтением журнала конкретной машины.
		//
		// НЕ шлём серверу UNLOCKED: overlay-UNLOCKED на сервере идёт в
		// SetDeviceLockState('unlocked', '') и СТИРАЕТ desired=locked (gateway.go),
		// то есть транзиентный сбой навсегда разоружил бы kill-switch (adversarial-
		// ревью: critical). Держим desired нетронутым — Manager.Lock теперь
		// откатывает состояние при отказе, поэтому mgr.Locked()==false, и следующий
		// тик честно ретраит: транзиентный сбой самозаживает, как только диск
		// восстановится. Пустой хеш от сервера чинится на источнике (серверная
		// ветка FetchLockStatus); до тех пор тик крутит ретрай (дедуп лога — ниже).
		// Видимость в панели через actual-only канал (LOCK_STATE_LOCK_FAILED) —
		// отдельная задача: требует нового proto-состояния и серверного роутинга.
		r.mu.Lock()
		already := r.applyFailSet && r.applyFailReported == hash
		r.applyFailReported = hash
		r.applyFailSet = true
		r.mu.Unlock()
		if !already {
			r.log.Error("lock: reconcile Lock ОТКАЗАЛ — desired=locked не применён (ретраю, desired на сервере не трогаю)",
				slog.String("request_id", hash), slog.Any("error", err))
		}
		return
	}
	r.mu.Lock()
	r.applyFailSet = false // лок применён — дедуп лога провала сброшен
	r.mu.Unlock()
	r.log.Warn("lock: реконсиляция применила desired-состояние locked после рестарта/расхождения")
	if err := r.report(ctx, &pb.ReportLockStatusRequest{
		RequestId:  hash,
		State:      pb.LockState_LOCK_STATE_LOCKED,
		OccurredAt: time.Now().Unix(),
		Details:    "reconcile: server desired state is locked",
	}); err != nil {
		r.log.Error("lock: ReportLockStatus(LOCKED) в outbox", slog.Any("error", err))
	}
}

// reconcileUnlocked применяет желаемое состояние "unlocked", если локально
// устройство ещё считается заблокированным (сервер снял lock_status в обход
// обычного unlock-флоу — например, вручную из панели — либо агент потерял
// какое-то предыдущее unlock-намерение).
func (r *Reconciler) reconcileUnlocked(ctx context.Context) {
	// Сервер согласен: устройство unlocked — память о локальном снятии своё
	// отработала. Чистим ОБЕ копии: in-memory и durable в Manager (иначе
	// durable-копия жила бы до следующего Lock, а комментарий «память больше
	// не нужна» врал бы).
	r.mu.Lock()
	r.lastUnlockedHash = ""
	r.durableReported = ""
	r.applyFailSet = false // desired=unlocked — дедуп провала применения тоже сброшен
	r.mu.Unlock()
	r.mgr.ClearLastUnlocked()

	if !r.mgr.Locked() {
		return
	}
	reqID := r.mgr.CurrentRequestID()
	if err := r.mgr.Unlock(); err != nil {
		r.log.Error("lock: reconcile Unlock", slog.Any("error", err))
		return
	}
	r.log.Warn("lock: реконсиляция сняла блокировку — сервер desired-состояние unlocked",
		slog.String("request_id", reqID))
	if err := r.report(ctx, &pb.ReportLockStatusRequest{
		RequestId:  reqID,
		State:      pb.LockState_LOCK_STATE_UNLOCKED,
		OccurredAt: time.Now().Unix(),
		Details:    "reconcile: server desired state is unlocked",
	}); err != nil {
		r.log.Error("lock: ReportLockStatus(UNLOCKED) в outbox", slog.Any("error", err))
	}
}
