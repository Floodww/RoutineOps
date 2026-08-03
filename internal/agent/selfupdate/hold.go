package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Гейт самообновления на время работы, которую нельзя прерывать заменой бинаря
// (docs/remote-desktop-contract.md §9.1).
//
// Повод конкретный. На Windows замена бинаря начинается с
// `taskkill /F /IM <exe> /FI "PID ne <self>"` — он бьёт ВСЕ прочие процессы того же
// бинаря, а захватчик экрана запускается тем же exe, значит попадает под него
// гарантированно. `/F` — это TerminateProcess: ни финализации записи сеанса, ни события,
// ни строки в аудите. На macOS зеркальная беда: rename поверх exe оставляет worker на
// старом inode, и посреди сеанса получается протокольный разъезд версий.
//
// Правильный ответ — не «исключить worker из taskkill» (это лечит симптом на одной ОС), а
// не начинать обновление, пока сеанс идёт.

// ErrDeferred — обновление не применено НАМЕРЕННО.
//
// Отдельная ошибка, потому что в логе это Info, а не Error: «отложили из-за сеанса» и
// «не смогли обновиться» — разные события, и склеивать их значит либо приучить смотрящего
// игнорировать ошибки обновления, либо пугать его штатной работой гейта.
var ErrDeferred = errors.New("selfupdate: применение отложено")

// Потолки гейта по умолчанию.
const (
	// DefaultHoldCap — сколько ОДНА работа вправе задерживать обновление.
	//
	// Полчаса при потолке сеанса в час: обновление не должно висеть вечно, но и рвать
	// сеанс поддержки на середине разговора с сотрудником из-за релиза тоже нельзя.
	DefaultHoldCap = 30 * time.Minute

	// DefaultHoldGrace — сколько ждём штатного завершения после просьбы освободить.
	//
	// Штатное завершение сеанса — это финализация записи и durable-событие, а не
	// мгновенный выход; полминуты хватает с запасом, и это всё равно на порядки лучше
	// TerminateProcess.
	DefaultHoldGrace = 30 * time.Second

	// defaultHoldPoll — как часто переспрашиваем после просьбы освободить.
	defaultHoldPoll = time.Second
)

// Hold — источник, который вправе отложить замену бинаря.
type Hold struct {
	// Active сообщает, идёт ли сейчас работа, посреди которой заменять бинарь нельзя, и
	// что это за работа.
	//
	// Описание ОБЯЗАНО идентифицировать конкретную работу (например, включать id
	// сеанса), а не быть родовым «идёт сеанс». По смене описания гейт понимает, что
	// работа сменилась, и обнуляет счётчик отсрочки. Иначе два разных сеанса, попавшие
	// на две соседние проверки, выглядят как одна непрерывная задержка — и второй сеанс
	// закроют за грехи первого, хотя он начался минуту назад.
	Active func() (holding bool, what string)

	// Release просит завершить работу ШТАТНО — с причиной AGENT_UPDATE, финализацией
	// записи и событием, а не TerminateProcess. Зовётся один раз на одну работу, когда
	// потолок отсрочки исчерпан.
	Release func()

	// Cap — потолок отсрочки для одной работы. 0 = DefaultHoldCap.
	Cap time.Duration
	// Grace — сколько ждём штатного завершения после Release. 0 = DefaultHoldGrace.
	Grace time.Duration
	// Poll — как часто переспрашиваем Active в течение Grace. 0 = defaultHoldPoll.
	Poll time.Duration
}

// clock — текущее время гейта. Сейм нужен ради тестов на потолок отсрочки: иначе тест
// на «полчаса» шёл бы полчаса.
func (u *Updater) clock() time.Time {
	if u.nowFn != nil {
		return u.nowFn()
	}
	return time.Now()
}

// SetHold подключает гейт. До вызова обновление применяется как раньше.
func (u *Updater) SetHold(h Hold) {
	if h.Cap <= 0 {
		h.Cap = DefaultHoldCap
	}
	if h.Grace <= 0 {
		h.Grace = DefaultHoldGrace
	}
	if h.Poll <= 0 {
		h.Poll = defaultHoldPoll
	}
	u.hold = &h
}

// applyAllowed решает, можно ли сейчас заменять бинарь.
//
// Зовётся ДО скачивания, а не перед самой заменой, и это не оптимизация: тянуть 20 МБ по
// тому же каналу, по которому идёт сеанс, — верный способ превратить «поддержка смотрит
// экран» в «поддержка смотрит слайд-шоу».
func (u *Updater) applyAllowed(ctx context.Context) error {
	if u.hold == nil {
		return nil
	}
	holding, what := u.hold.Active()
	if !holding {
		u.holdSince, u.holdWhat, u.holdReleased = time.Time{}, "", false
		return nil
	}

	now := u.clock()
	if what != u.holdWhat {
		// Работа сменилась — счётчик отсрочки начинается заново.
		u.holdSince, u.holdWhat, u.holdReleased = now, what, false
	}
	if u.holdSince.IsZero() {
		u.holdSince = now
	}

	if waited := now.Sub(u.holdSince); waited < u.hold.Cap {
		u.log.Info("selfupdate: обновление отложено",
			slog.String("причина", what), slog.Duration("ждём", waited), slog.Duration("потолок", u.hold.Cap))
		return fmt.Errorf("%w: %s", ErrDeferred, what)
	}

	// Потолок исчерпан. Просим завершить штатно — один раз на одну работу, иначе при
	// каждой проверке будем слать повторные просьбы уже закрывающемуся сеансу.
	if !u.holdReleased {
		u.holdReleased = true
		u.log.Warn("selfupdate: потолок отсрочки исчерпан — просим завершить штатно",
			slog.String("причина", what), slog.Duration("потолок", u.hold.Cap))
		if u.hold.Release != nil {
			u.hold.Release()
		}
	}

	// Ждём освобождения. Не бесконечно: если работа не завершилась и за grace, обновление
	// откладывается до следующей проверки — но НЕ применяется силой. Убить процесс,
	// который пишет запись сеанса, хуже, чем поставить релиз на несколько часов позже.
	//
	// Цикл СЧЁТНЫЙ, а не по дедлайну от u.clock(): часы здесь подменяемы ради тестов на
	// потолок отсрочки, и сверка «сколько уже прождали» с ними превращает ожидание в
	// вечное — время-то стоит. Поймано первым же прогоном теста: он завис.
	steps := int(u.hold.Grace / u.hold.Poll)
	if steps < 1 {
		steps = 1
	}
	for i := 0; i < steps; i++ {
		if !waitOrDone(ctx, u.hold.Poll) {
			return ctx.Err()
		}
		if holding, _ = u.hold.Active(); !holding {
			u.log.Info("selfupdate: работа завершена штатно — применяем обновление", slog.String("была", what))
			u.holdSince, u.holdWhat, u.holdReleased = time.Time{}, "", false
			return nil
		}
	}
	u.log.Warn("selfupdate: работа не завершилась за отведённое время — обновление ждёт следующей проверки",
		slog.String("причина", what), slog.Duration("ждали", u.hold.Grace))
	return fmt.Errorf("%w: %s не завершилось за %v", ErrDeferred, what, u.hold.Grace)
}
