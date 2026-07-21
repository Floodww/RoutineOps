// Package outbox реализует устойчивую к обрывам связи доставку отчётов агента.
//
// Мотивация: в живом e2e мы видели, как при редеплоях сервера unary-вызовы
// (ReportSecurityEvent, ReportAdminAccess) падали и события терялись. Агент для
// удалённых сотрудников с нестабильной сетью обязан переживать обрывы: события,
// потеря которых недопустима (алерты ИБ, аудит прав администратора), пишутся в
// локальную очередь на диске и до-сылаются после восстановления связи.
//
// Не всё нужно буферизовать: периодическая инвентаризация — это полный снапшот
// состояния, он самовосстанавливается на следующем тике, поэтому через очередь
// НЕ идёт (буферизация промежуточных снапшотов бессмысленна).
//
// Хранилище — каталог, одна запись = один файл (атомарная запись через tmp+rename).
// Имя файла кодирует порядок (FIFO), поэтому очередь переживает перезапуск агента.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Виды отчётов в очереди. Диспетчер по виду решает, какой RPC вызвать.
const (
	KindSecurity = "security" // pb.SecurityEvent
	KindAdmin    = "admin"    // pb.ReportAdminAccessRequest
	KindScript   = "script"   // pb.ScriptResult
	KindLock     = "lock"     // pb.ReportLockStatusRequest
	KindTask     = "task"     // pb.TaskResult (результат ad-hoc задачи)
)

// Dispatcher доставляет одну запись серверу.
//
// Контракт по возвращаемому значению критичен для семантики очереди:
//   - error != nil  — ВРЕМЕННЫЙ сбой (нет связи и т.п.): запись остаётся в
//     очереди, доставка будет повторена. Слив очереди приостанавливается, чтобы
//     сохранить порядок (FIFO).
//   - error == nil  — запись успешно доставлена ИЛИ безнадёжно испорчена
//     (неизвестный вид, битый payload). В обоих случаях запись удаляется из
//     очереди. Диспетчер обязан сам залогировать «битый» случай — иначе
//     повреждённая запись навсегда заблокирует очередь (poison pill).
type Dispatcher func(ctx context.Context, kind string, data []byte) error

// entry — обёртка записи на диске.
type entry struct {
	Kind       string    `json:"kind"`
	Data       []byte    `json:"data"` // json кодирует []byte в base64
	EnqueuedAt time.Time `json:"enqueued_at"`
}

// Queue — устойчивая FIFO-очередь отчётов на диске.
type Queue struct {
	dir      string
	max      int           // максимум записей; при переполнении дропаем самые старые
	maxAge   time.Duration // потолок возраста записи; старше — дропаем (0 = без лимита)
	interval time.Duration
	log      *slog.Logger
	dispatch Dispatcher

	seq     uint64        // счётчик-тайбрейк для уникальности имён в пределах наносекунды
	trigger chan struct{} // сигнал «попробовать слить прямо сейчас» (после Enqueue)
	mu      sync.Mutex    // сериализует слив очереди
}

// New создаёт очередь в каталоге dir (создаётся при необходимости).
// max — потолок записей (<=0 → без ограничения), interval — период фоновых
// попыток до-доставки (страховка поверх немедленной попытки после Enqueue).
func New(dir string, max int, interval time.Duration, log *slog.Logger, dispatch Dispatcher) (*Queue, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("outbox: создание каталога %q: %w", dir, err)
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Queue{
		dir:      dir,
		max:      max,
		interval: interval,
		log:      log,
		dispatch: dispatch,
		trigger:  make(chan struct{}, 1),
	}, nil
}

// SetMaxAge задаёт возрастной потолок ретеншена: записи старше d удаляются
// фоновым проходом (см. enforceAge), даже если место по OutboxMax ещё есть.
// d<=0 — без ограничения по возрасту (поведение по умолчанию: храним loss-
// sensitive отчёты до доставки/вытеснения по числу). Безопасно вызвать один раз
// сразу после New, до старта Run.
func (q *Queue) SetMaxAge(d time.Duration) { q.maxAge = d }

// Enqueue ставит отчёт в очередь (durable: после успешного возврата запись на
// диске и будет доставлена). Сразу же будит фоновый слив (best-effort).
//
// Возврат ошибки означает, что запись НЕ durable — в том числе когда очередь
// забита более приоритетными (protected) видами и свежая evictable-запись не
// помещается (см. enforceLimit): вызывающий обязан уйти в свой фолбэк
// (executor — прямой unary, runner — лог потери), а не считать отчёт доставленным.
func (q *Queue) Enqueue(kind string, data []byte) error {
	e := entry{Kind: kind, Data: data, EnqueuedAt: time.Now()}
	buf, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("outbox: сериализация записи: %w", err)
	}

	name := q.newName(kind)
	tmp := filepath.Join(q.dir, name+".tmp")
	final := filepath.Join(q.dir, name)
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("outbox: запись %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("outbox: фиксация %q: %w", final, err)
	}

	if err := q.enforceLimit(name); err != nil {
		return err
	}
	q.wake()
	return nil
}

// newName формирует лексикографически возрастающее имя: <unixnano>-<seq>-<kind>.json.
// unixnano даёт порядок и переживает перезапуск (старые файлы — раньше по времени),
// seq разрешает коллизии в пределах одной наносекунды.
func (q *Queue) newName(kind string) string {
	n := atomic.AddUint64(&q.seq, 1)
	return fmt.Sprintf("%019d-%012d-%s.json", time.Now().UnixNano(), n, sanitize(kind))
}

func sanitize(s string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ".", "_", "-", "_").Replace(s)
}

// Run крутит фоновый слив: по тику interval и по сигналу после Enqueue, пока ctx жив.
func (q *Queue) Run(ctx context.Context) {
	ticker := time.NewTicker(q.interval)
	defer ticker.Stop()
	q.flush(ctx) // попытка слить накопленное за прошлые запуски сразу на старте
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.flush(ctx)
		case <-q.trigger:
			q.flush(ctx)
		}
	}
}

// FlushOnce синхронно пытается слить очередь один раз. Полезно для graceful-
// shutdown (до-доставить накопленное перед выходом) и для детерминированных тестов.
func (q *Queue) FlushOnce(ctx context.Context) { q.flush(ctx) }

// flush сливает очередь в FIFO-порядке. На первом временном сбое останавливается,
// сохраняя порядок: остаток уйдёт на следующей попытке.
func (q *Queue) flush(ctx context.Context) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Ретеншен по возрасту — до попытки доставки: цикл ниже выходит на первом
	// сбое связи, а устаревший backlog надо подрезать на каждом тике независимо.
	q.enforceAge()

	files, err := q.list()
	if err != nil {
		q.log.Error("outbox: чтение очереди", slog.Any("error", err))
		return
	}
	var sent int
	for _, f := range files {
		if ctx.Err() != nil {
			return
		}
		path := filepath.Join(q.dir, f)
		e, err := readEntry(path)
		if err != nil {
			// Битый файл: удаляем, чтобы не заблокировать очередь.
			q.log.Error("outbox: повреждённая запись удалена", slog.String("file", f), slog.Any("error", err))
			os.Remove(path)
			continue
		}
		if err := q.dispatch(ctx, e.Kind, e.Data); err != nil {
			// Временный сбой: прекращаем слив, сохраняем порядок, повторим позже.
			q.log.Warn("outbox: доставка отложена",
				slog.String("kind", e.Kind), slog.Int("pending", len(files)-sent), slog.Any("error", err))
			return
		}
		os.Remove(path)
		sent++
	}
	if sent > 0 {
		q.log.Info("outbox: доставлено отложенных отчётов", slog.Int("count", sent))
	}
}

// list возвращает имена записей (без .tmp) в FIFO-порядке (лексикографически).
func (q *Queue) list() ([]string, error) {
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, ".tmp") || !strings.HasSuffix(n, ".json") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// isEvictableFirst — виды, которые при переполнении вытесняются ПЕРВЫМИ:
// script/task — операционные данные (у task есть серверная компенсация
// late_task_result, script менее loss-sensitive). security/admin/lock —
// ИБ-алерты, аудит прав, статусы лока — серверной компенсации не имеют, их
// вытесняем в последнюю очередь.
func isEvictableFirst(kind string) bool {
	return kind == KindScript || kind == KindTask
}

// fileKind извлекает вид из имени файла (<unixnano>-<seq>-<kind>.json). Вид при
// постановке проходит sanitize (замена /\.- на _), но реальные Kind* этих
// символов не содержат, поэтому доезжают неизменными. "" если имя не разобрать.
func fileKind(name string) string {
	parts := strings.SplitN(strings.TrimSuffix(name, ".json"), "-", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// enforceLimit вытесняет записи при переполнении q.max, но НЕ слепо по возрасту:
// прежний drop-oldest молча терял единственный ИБ-алерт под флудом
// самовосстанавливающихся script-результатов (оффлайн-ноут + частый cron).
// Очерёдность жертв: старые evictable (script/task, FIFO) → сама свежая запись
// newName, если она evictable → старые protected (security/admin/lock, FIFO).
// Потеря loss-sensitive отчёта всегда логируется (не может быть немой).
//
// newName — только что записанный файл этого же Enqueue. Свежая evictable-запись
// НЕ вытесняет protected-отчёты (класс выше), поэтому при очереди, забитой
// protected-видами, жертвой становится она сама — тогда enforceLimit удаляет её
// и возвращает ошибку, чтобы Enqueue не отрапортовал durable-успех (прежний код
// молча удалял свежезаписанный файл и возвращал nil — вызывающий не уходил в
// фолбэк, и результат не существовал нигде). Свежая protected-запись, наоборот,
// вытесняет старейшую protected и остаётся — для неё ошибка невозможна.
func (q *Queue) enforceLimit(newName string) error {
	if q.max <= 0 {
		return nil
	}
	files, err := q.list()
	if err != nil || len(files) <= q.max {
		return nil
	}
	drop := len(files) - q.max

	// files уже в FIFO-порядке; разложение сохраняет его внутри каждого класса.
	var evictable, protected []string
	for _, f := range files {
		if f == newName {
			continue // свежая запись — кандидат особого порядка, см. ниже
		}
		if isEvictableFirst(fileKind(f)) {
			evictable = append(evictable, f)
		} else {
			protected = append(protected, f)
		}
	}
	victims := evictable
	newSacrificed := false
	if len(victims) < drop && isEvictableFirst(fileKind(newName)) {
		victims = append(victims, newName)
		newSacrificed = true
	}
	if len(victims) < drop {
		victims = append(victims, protected...)
	}
	if len(victims) > drop {
		victims = victims[:drop]
	}

	droppedProtected := 0
	for _, f := range victims {
		os.Remove(filepath.Join(q.dir, f))
		if kind := fileKind(f); !isEvictableFirst(kind) {
			droppedProtected++
			q.log.Error("outbox: ПЕРЕПОЛНЕНИЕ вытеснило loss-sensitive отчёт — серверной компенсации нет",
				slog.String("kind", kind), slog.String("file", f))
		}
	}
	q.log.Warn("outbox: очередь переполнена, записи вытеснены",
		slog.Int("dropped", len(victims)), slog.Int("dropped_protected", droppedProtected), slog.Int("max", q.max))

	if newSacrificed {
		return fmt.Errorf("outbox: очередь забита loss-sensitive отчётами (max %d) — запись вида %q не помещается",
			q.max, fileKind(newName))
	}
	return nil
}

// enforceAge удаляет записи старше maxAge. Возраст берётся из префикса имени
// файла (<unixnano>-...), поэтому проход не читает содержимое и дёшев. Вызывается
// под q.mu из flush; нераспознанные имена не трогаем (консервативно).
func (q *Queue) enforceAge() {
	if q.maxAge <= 0 {
		return
	}
	files, err := q.list()
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-q.maxAge)
	var dropped int
	for _, f := range files {
		ts, ok := fileTime(f)
		if !ok || !ts.Before(cutoff) {
			continue
		}
		os.Remove(filepath.Join(q.dir, f))
		dropped++
	}
	if dropped > 0 {
		q.log.Warn("outbox: ретеншен по возрасту удалил устаревшие записи",
			slog.Int("dropped", dropped), slog.Duration("max_age", q.maxAge))
	}
}

// fileTime извлекает время постановки в очередь из имени файла
// (<unixnano>-<seq>-<kind>.json). ok=false, если префикс не разобрать.
func fileTime(name string) (time.Time, bool) {
	i := strings.IndexByte(name, '-')
	if i <= 0 {
		return time.Time{}, false
	}
	nano, err := strconv.ParseInt(name[:i], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, nano), true
}

// Len — число записей в очереди (для тестов/диагностики).
func (q *Queue) Len() int {
	files, _ := q.list()
	return len(files)
}

func (q *Queue) wake() {
	select {
	case q.trigger <- struct{}{}:
	default: // сигнал уже стоит — повторно не нужно
	}
}

func readEntry(path string) (entry, error) {
	var e entry
	buf, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(buf, &e); err != nil {
		return e, err
	}
	if e.Kind == "" {
		return e, fmt.Errorf("пустой kind")
	}
	return e, nil
}
