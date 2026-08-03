package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// Окно улик сессии админ-прав: что накопилось на устройстве с момента выдачи прав.
//
// Окна КУМУЛЯТИВНЫ от базовой линии t0 и базовая линия за сессию не
// перебазируется. Это не деталь реализации, а несущее решение: при схеме «дельта
// от предыдущего окна» потеря одного отчёта превращается в невидимую дыру, поверх
// которой финальное окно рисует уверенный полный список. Для фичи подотчётности
// уверенное враньё — худший возможный исход, поэтому потеря промежуточного окна
// обязана самоизлечиваться следующим.
//
// Здесь только сборка окна и решение «пора ли». Отправка — отдельно и под флагом
// сервера (см. sendWindow в Manager).

const (
	// DefaultWindowInterval — период промежуточных окон, пока сессия жива.
	DefaultWindowInterval = 30 * time.Minute

	// MinWindowInterval — нижний кламп на значение, пришедшее с сервера. Снимок
	// служб и ПО обходит реестр/каталоги целиком; разрешить серверу поставить
	// «раз в 10 секунд» значит дать одной настройкой положить парк.
	MinWindowInterval = 5 * time.Minute

	// MaxWindowChanges — потолок строк в одном окне. Сервер отвергает окно
	// длиннее как InvalidArgument (терминальный код у reportErr), поэтому агент
	// обязан урезать сам: иначе сессия с массовой переустановкой ПО отдала бы
	// окно, которое сервер выбросит целиком, и улик не осталось бы вовсе.
	MaxWindowChanges = 1000

	// staleFinalThreshold — насколько финальный срез может отстать от реального
	// конца сессии, оставаясь честным «финалом». Больше — окно помечается
	// stale_final: так выглядит машина, выключенная на неделю с активной
	// сессией, где дельта заведомо шире самой сессии.
	staleFinalThreshold = 10 * time.Minute
)

// Полнота улик. Пустая дельта при complete читается как «изменений не было»;
// при любом другом значении — как «мы не знаем». Отсутствие улик обязано быть
// событием, а не тишиной.
const (
	CompletenessComplete   = "complete"
	CompletenessNoBaseline = "no_baseline"
	CompletenessPartial    = "partial"
	CompletenessTruncated  = "truncated"
	CompletenessStaleFinal = "stale_final"
)

// Inventory — срез инвентаря в момент времени.
type Inventory struct {
	Software       []SoftFP
	SoftwareHealth string
	Services       []SvcFP
	ServicesHealth string
	At             time.Time

	// BootTime — время загрузки на момент среза. Расхождение с записанным в
	// базовой линии означает ребут внутри сессии: часть изменений могла приехать
	// с обновлениями, применёнными при перезагрузке, и оператор обязан это видеть.
	BootTime int64
}

// Window — одно окно улик, готовое к отправке. Поля повторяют
// ReportAdminSessionChangesRequest из контракта, но без зависимости от proto:
// сборка и её тесты не ждут кодогенерации.
type Window struct {
	RequestID      string
	Seq            int32
	WindowStart    time.Time // t0 базовой линии — у всех окон сессии одинаковый
	WindowEnd      time.Time
	SnapshotAt     time.Time // ≠ WindowEnd только при stale_final
	Changes        []Change
	Final          bool
	Truncated      bool
	TotalChanges   int32 // сколько изменений было ДО урезания
	Rebooted       bool
	BaselineLost   bool
	SoftwareHealth string
	ServicesHealth string
	Completeness   string
}

// WindowInput — то, что знает вызывающий, но не знает состояние сессии.
type WindowInput struct {
	Seq   int32
	Final bool
	Now   time.Time

	// SessionEnd — момент, когда права реально кончились (для финального окна).
	// Нулевое = «прямо сейчас». Отличается от Now, когда агент поднял с диска
	// сессию, пережившую выключение машины: дельта тогда шире самой сессии, и
	// это обязано быть видно (stale_final), а не выдаваться за точный финал.
	SessionEnd time.Time

	// BaselineLost — базовой линии нет: устойчивое состояние выключено, файл
	// не прочитался или сессия восстановлена без него.
	BaselineLost bool
}

// BuildWindow собирает окно из базовой линии и текущего среза.
//
// Чистая функция: ни ввода-вывода, ни часов — всё приходит параметрами, поэтому
// каждое решение (полнота, урезание, деградация) проверяется таблицей на любой
// машине без прав администратора.
func BuildWindow(st *SessionState, cur Inventory, in WindowInput) Window {
	now := in.Now
	w := Window{
		Seq:          in.Seq,
		Final:        in.Final,
		WindowEnd:    now,
		SnapshotAt:   now,
		BaselineLost: in.BaselineLost || st == nil,
		Rebooted:     st.Rebooted(cur.BootTime),
	}
	if !cur.At.IsZero() {
		w.SnapshotAt = cur.At
	}
	if st != nil {
		w.RequestID = st.RequestID
		w.WindowStart = st.GrantedAt
	}

	// Финальное окно датируется концом сессии, а не моментом сборки: иначе окно
	// заявки, отлежавшей неделю в выключенной машине, выглядело бы как свежий
	// точный срез на момент снятия прав.
	stale := false
	if in.Final && !in.SessionEnd.IsZero() {
		w.WindowEnd = in.SessionEnd
		stale = now.Sub(in.SessionEnd) > staleFinalThreshold
	}

	// Здоровье — ХУДШЕЕ из базовой линии и текущего среза. Дельта, снятая от
	// неполной базовой линии, недостоверна ровно так же, как снятая неполным
	// текущим срезом: «мы не видели половину машины в момент выдачи прав» и «не
	// видим её сейчас» дают одинаково недостоверный список.
	var baseSoft, baseSvc string
	var beforeSoft []SoftFP
	var beforeSvc []SvcFP
	if st != nil {
		baseSoft, baseSvc = st.SoftwareHealth, st.ServicesHealth
		beforeSoft, beforeSvc = st.Software, st.Services
	}
	w.SoftwareHealth = worseHealth(baseSoft, cur.SoftwareHealth)
	w.ServicesHealth = worseHealth(baseSvc, cur.ServicesHealth)

	// БЕЗ ГОДНОЙ БАЗОВОЙ ЛИНИИ ДЕЛЬТА НЕ СЧИТАЕТСЯ ВОВСЕ — по источникам раздельно.
	//
	// Это не перестраховка. Пустая базовая линия (устойчивое состояние выключено,
	// файл не прочитался, сбор в момент выдачи прав отказал) при обычном diff даёт
	// не «мы не знаем», а список ВСЕГО установленного на машине с пометкой
	// «появилось за сессию» — то есть готовое обвинение сотрудника в установке
	// двух тысяч пакетов, включая те, что приехали с образом. Уверенное враньё в
	// подотчётности хуже честного молчания, поэтому здесь окно уходит пустым, а
	// полнота говорит, почему (no_baseline / partial).
	// Здоровье берём УЖЕ СВЕДЁННОЕ (худшее из t0 и текущего): отказ текущего среза
	// так же фатален, как отказ базовой линии, только зеркально — пустой текущий
	// список превращает дельту в «сотрудник удалил всё, что было на машине».
	// Отсюда же требование непустоты обоих срезов: ни один реальный сценарий не
	// даёт машину с нулём пакетов или нулём служб, а вот отказ источника даёт.
	softUsable := st != nil && !w.BaselineLost && healthUsable(w.SoftwareHealth) &&
		len(beforeSoft) > 0 && len(cur.Software) > 0
	svcUsable := st != nil && !w.BaselineLost && healthUsable(w.ServicesHealth) &&
		len(beforeSvc) > 0 && len(cur.Services) > 0

	var changes []Change
	if softUsable {
		changes = append(changes, DiffSoftware(beforeSoft, cur.Software, now)...)
	}
	if svcUsable {
		changes = append(changes, DiffServices(beforeSvc, cur.Services, now)...)
	}
	// Обе дельты отсортированы по отдельности — после склейки порядок общий, а не
	// «сначала весь софт, потом все службы».
	sortChanges(changes)
	changes = Degrade(changes, w.SoftwareHealth, w.ServicesHealth, w.BaselineLost)

	w.TotalChanges = int32(len(changes))
	w.Changes, w.Truncated = truncateChanges(changes, MaxWindowChanges)
	w.Completeness = completenessOf(w, stale, !softUsable || !svcUsable)
	return w
}

// truncateChanges урезает окно до потолка, сохраняя САМОЕ ЗНАЧИМОЕ.
//
// Резать по канонической сортировке (то есть по алфавиту) значит выбросить
// именно то, ради чего фича сделана: при переполнении первыми улетели бы записи
// с атрибуцией на человека, если их имена оказались в хвосте алфавита. Поэтому
// приоритет: human_likely → unknown → background_likely; шум ОС вытесняется
// первым. Внутри отобранного восстанавливаем канонический порядок, чтобы два
// одинаковых окна ехали на сервер побайтово одинаково.
func truncateChanges(in []Change, max int) ([]Change, bool) {
	if max <= 0 || len(in) <= max {
		return in, false
	}
	idx := make([]int, len(in))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return attrRank(in[idx[a]].Attribution) < attrRank(in[idx[b]].Attribution)
	})
	out := make([]Change, 0, max)
	for _, i := range idx[:max] {
		out = append(out, in[i])
	}
	sortChanges(out)
	return out, true
}

func attrRank(a string) int {
	switch a {
	case AttrHumanLikely:
		return 0
	case AttrUnknown:
		return 1
	case AttrBackgroundLikely:
		return 2
	default:
		return 1 // незнакомое значение прячем не раньше, чем явную неизвестность
	}
}

// completenessOf — одно значение полноты на окно, от самого тяжёлого к лёгкому.
//
// Порядок именно такой: «не от чего считать» строго хуже «часть источника не
// прочиталась», а та строго хуже «список полон, но датирован не концом сессии».
// Truncated стоит последним из проблемных: там total_changes честно показывает
// объём, то есть оператор знает и что было урезано, и сколько.
// Аргумент skipped обязателен: источник может оказаться непригодным для дельты
// при формально здоровом статусе (пустой срез). Без него такое окно уехало бы
// пустым и «полным» — то есть прочиталось бы как «за сессию ничего не менялось».
func completenessOf(w Window, stale, skipped bool) string {
	switch {
	case w.BaselineLost:
		return CompletenessNoBaseline
	case skipped || !healthOK(w.SoftwareHealth) || !healthOK(w.ServicesHealth):
		return CompletenessPartial
	case stale:
		return CompletenessStaleFinal
	case w.Truncated:
		return CompletenessTruncated
	default:
		return CompletenessComplete
	}
}

// healthOK — пустое значение считаем здоровым: так же его трактует Degrade
// (состояния сессии, записанные до появления поля, не должны задним числом
// становиться «неполными»).
func healthOK(h string) bool {
	return h == "" || h == string(collector.HealthOK)
}

// healthUsable — можно ли на таком здоровье вообще считать дельту.
//
// partial пропускаем осознанно: «часть каталога не прочиталась» обычно означает
// одну и ту же недоступную часть и в t0, и сейчас — она просто отсутствует в
// обоих срезах и ложной дельты не даёт. Запретить partial значило бы выключить
// фичу на любой машине с одним недоступным каталогом. Атрибуция в таком окне всё
// равно снижена до unknown (Degrade), а полнота честно говорит partial.
// failed и unsupported не пропускаем: там источника нет вовсе.
func healthUsable(h string) bool {
	switch h {
	case "", string(collector.HealthOK), string(collector.HealthPartial):
		return true
	default:
		return false
	}
}

func worseHealth(a, b string) string {
	if healthRank(a) >= healthRank(b) {
		return a
	}
	return b
}

func healthRank(h string) int {
	switch h {
	case string(collector.HealthFailed):
		return 3
	case string(collector.HealthPartial):
		return 2
	case string(collector.HealthUnsupported):
		return 1
	default:
		return 0 // ok и пустое
	}
}

// windowDigest — отпечаток того, что окно сообщает серверу.
//
// В него входит не только список изменений, но и всё, что меняет прочтение этого
// списка: полнота, признак урезания, здоровье источников, ребут. Иначе окно, где
// список тот же, но сбор деградировал до partial, посчиталось бы «тем же самым» и
// не уехало бы — то есть оператор не узнал бы, что данным больше нельзя верить.
func windowDigest(w Window) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%t|%s|%t|%s|%s\n", w.TotalChanges, w.Truncated, w.Completeness,
		w.Rebooted, w.SoftwareHealth, w.ServicesHealth)
	for _, c := range w.Changes {
		fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s\n", c.Kind, c.IdentityKey, c.Subject,
			c.OldValue, c.NewValue, c.Attribution)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ClampWindowInterval — период промежуточных окон по значению с сервера.
// 0 (в том числе старый сервер, не знающий поля) = дефолт агента; всё, что
// меньше нижней границы, поднимается до неё, а не отвергается: сервер не должен
// уметь ни задушить сбор, ни устроить снимок каждые несколько секунд.
func ClampWindowInterval(sec int32) time.Duration {
	if sec <= 0 {
		return DefaultWindowInterval
	}
	d := time.Duration(sec) * time.Second
	if d < MinWindowInterval {
		return MinWindowInterval
	}
	return d
}
