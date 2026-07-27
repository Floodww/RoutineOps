package lock

import (
	"os"
	"strings"
	"testing"
	"time"
)

type tamperCall struct {
	kind      TamperKind
	markerLen int
}

// tamperSpy собирает вызовы TamperReporter. Вызывается из detectOfflineUnlock
// уже БЕЗ удержания Manager.mu, поэтому своя синхронизация не нужна: в этих
// тестах сторож дёргается синхронно, из одной горутины.
type tamperSpy struct {
	calls []tamperCall
	fail  bool // true = имитируем провал постановки в очередь
}

func (s *tamperSpy) report(kind TamperKind, markerLen int) bool {
	s.calls = append(s.calls, tamperCall{kind, markerLen})
	return !s.fail
}

// newMgrTamper — Manager с подключённым spy-репортером и коротким кулдауном
// (иначе тест ждал бы 15 минут реального tamperReportInterval).
func newMgrTamper(t *testing.T, cooldown time.Duration) (*Manager, *fakeLocker, *tamperSpy) {
	t.Helper()
	fl := &fakeLocker{}
	m, _ := newMgrDurable(t, fl)
	spy := &tamperSpy{}
	m.SetTamperReporter(spy.report)
	m.tamperCooldown = cooldown
	return m, fl, spy
}

func lockForTamper(t *testing.T, m *Manager) string {
	t.Helper()
	hash := bcryptHash(t, "pw")
	if err := m.Lock("r1", hash, "увольнение"); err != nil {
		t.Fatal(err)
	}
	return hash
}

// Базовый контракт: первая подделка уходит в ИБ сразу и несёт КЛАССИФИКАЦИЮ,
// а не содержимое подделанного файла.
func TestTamperReport_FirstForgeReportsImmediately(t *testing.T) {
	m, _, spy := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)

	forgeUnlocked(t, m.path, "произвольный-маркер")
	m.detectOfflineUnlock()

	if len(spy.calls) != 1 {
		t.Fatalf("ожидали ровно одно событие ИБ, got %d", len(spy.calls))
	}
	if spy.calls[0].kind != TamperMarkerOther {
		t.Fatalf("kind = %q, ожидали TamperMarkerOther", spy.calls[0].kind)
	}
	if spy.calls[0].markerLen != len("произвольный-маркер") {
		t.Fatalf("markerLen = %d, ожидали %d", spy.calls[0].markerLen, len("произвольный-маркер"))
	}
}

// Классификация обязана различать три вектора: пустой маркер, скопированный из
// соседнего поля hash активного лока (ровно то, что пропускала прежняя проверка)
// и произвольное значение.
func TestTamperReport_MarkerClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		mark func(activeHash string) string
		want TamperKind
	}{
		{"пустой", func(string) string { return "" }, TamperMarkerEmpty},
		{"скопированный hash", func(h string) string { return h }, TamperMarkerCopiedHash},
		{"произвольный", func(string) string { return "qqq" }, TamperMarkerOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, spy := newMgrTamper(t, time.Hour)
			hash := lockForTamper(t, m)

			forgeUnlocked(t, m.path, tc.mark(hash))
			m.detectOfflineUnlock()

			if len(spy.calls) != 1 {
				t.Fatalf("ожидали одно событие, got %d", len(spy.calls))
			}
			if spy.calls[0].kind != tc.want {
				t.Fatalf("kind = %q, ожидали %q", spy.calls[0].kind, tc.want)
			}
		})
	}
}

// РЕГРЕССИЯ (ревью, high): содержимое подделанного файла пишет ровно тот
// непривилегированный пользователь, против которого событие. Пусти его байты в
// Details — и он глушит алерт о себе: набивка на мегабайты разносит
// SecurityEvent за серверный MaxRecvMsgSize (4 МиБ), сервер отвечает
// ResourceExhausted, outbox считает код терминальным и ДРОПАЕТ запись. Наружу
// обязаны уходить только словарь и число.
func TestTamperReport_HugeMarkerDoesNotInflateEvent(t *testing.T) {
	m, _, spy := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)

	huge := strings.Repeat("A", 5<<20) // 5 МБ набивки
	forgeUnlocked(t, m.path, huge)
	m.detectOfflineUnlock()

	if len(spy.calls) != 1 {
		t.Fatalf("ожидали одно событие, got %d", len(spy.calls))
	}
	if got := len(string(spy.calls[0].kind)); got > 256 {
		t.Fatalf("наружу ушла строка длиной %d — в событие попал маркер целиком", got)
	}
	if spy.calls[0].markerLen != len(huge) {
		t.Fatalf("markerLen = %d, ожидали %d (длина полезна для триажа, в отличие от самих байт)",
			spy.calls[0].markerLen, len(huge))
	}
}

// РЕГРЕССИЯ (ревью, high): маркер с HTML-разметкой не должен доезжать до
// Telegram (сервер шлёт Details с parse_mode=HTML). Наружу уходит словарь, а он
// разметки не содержит ни при каком вводе.
func TestTamperReport_MarkupInMarkerNeverEscapes(t *testing.T) {
	m, _, spy := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)

	forgeUnlocked(t, m.path, `</code><a href="https://evil/">Инструкция IT</a>`)
	m.detectOfflineUnlock()

	if len(spy.calls) != 1 {
		t.Fatalf("ожидали одно событие, got %d", len(spy.calls))
	}
	for _, bad := range []string{"<", ">", "href", "evil"} {
		if strings.Contains(string(spy.calls[0].kind), bad) {
			t.Fatalf("в событие просочилась разметка из подделанного файла: %q", spy.calls[0].kind)
		}
	}
}

// РЕГРЕССИЯ, ради которой дедуп и заведён: сторож тикает раз в секунду, а
// KindSecurity в outbox вытесняет старейшую protected-запись (enforceLimit).
// Событие на каждый тик за ~17 минут выдавило бы из очереди loss-sensitive
// отчёты. Внутри окна повтор обязан молчать.
func TestTamperReport_RepeatWithinCooldownIsDeduped(t *testing.T) {
	m, _, spy := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)

	for range 10 {
		forgeUnlocked(t, m.path, "x")
		m.detectOfflineUnlock()
	}

	if len(spy.calls) != 1 {
		t.Fatalf("10 тиков подделки дали %d событий, ожидали 1 (дедуп)", len(spy.calls))
	}
}

// Кулдаун истёк, а атака продолжается — IT обязан увидеть повтор: это сигнал о
// чужом активном действии, а не дребезг собственного ретрая.
func TestTamperReport_RepeatAfterCooldown(t *testing.T) {
	m, _, spy := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)

	forgeUnlocked(t, m.path, "x")
	m.detectOfflineUnlock()

	// Отматываем границу окна в прошлое — единственное, что снимает дедуп.
	m.mu.Lock()
	m.tamperNextReportAt = time.Now().Add(-time.Second)
	m.mu.Unlock()

	forgeUnlocked(t, m.path, "x")
	m.detectOfflineUnlock()

	if len(spy.calls) != 2 {
		t.Fatalf("после истечения окна ожидали 2 события, got %d", len(spy.calls))
	}
}

// РЕГРЕССИЯ (ревью, medium): провал постановки в очередь не должен дарить
// подделывателю полное окно тишины. Неудача укорачивает окно до
// tamperRetryInterval, а не до нуля (иначе вернулся бы флуд).
func TestTamperReport_FailedEnqueueShortensWindow(t *testing.T) {
	m, _, spy := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)
	spy.fail = true

	forgeUnlocked(t, m.path, "x")
	m.detectOfflineUnlock()

	m.mu.Lock()
	wait := time.Until(m.tamperNextReportAt)
	m.mu.Unlock()

	if wait > tamperRetryInterval+time.Second {
		t.Fatalf("после провала Enqueue окно = %v, ожидали не больше %v", wait, tamperRetryInterval)
	}
	if wait <= 0 {
		t.Fatalf("после провала Enqueue окно не выставлено (%v) — вернулся бы флуд на каждый тик", wait)
	}
	if len(spy.calls) != 1 {
		t.Fatalf("ожидали одну попытку, got %d", len(spy.calls))
	}
}

// Успешная постановка списывает ПОЛНОЕ окно.
func TestTamperReport_SuccessfulEnqueueSpendsFullWindow(t *testing.T) {
	m, _, _ := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)

	forgeUnlocked(t, m.path, "x")
	m.detectOfflineUnlock()

	m.mu.Lock()
	wait := time.Until(m.tamperNextReportAt)
	m.mu.Unlock()

	if wait < time.Hour-time.Minute {
		t.Fatalf("после успешной постановки окно = %v, ожидали ~1ч", wait)
	}
}

// ГЛАВНАЯ РЕГРЕССИЯ дедупа. Демон пере-утверждает файл на КАЖДОМ тике, поэтому
// «файл согласован» — это норма МЕЖДУ записями атакующего, а не конец атаки.
// Сброс дедупа по согласованному тику вернул бы флуд.
func TestTamperReport_ForgeAfterConsistentTickStillDeduped(t *testing.T) {
	m, _, spy := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)

	for range 10 {
		forgeUnlocked(t, m.path, "x")
		m.detectOfflineUnlock() // подделка
		m.detectOfflineUnlock() // файл уже пере-утверждён — согласованный тик
		m.detectOfflineUnlock() // и ещё один
	}

	if len(spy.calls) != 1 {
		t.Fatalf("подделка вперемешку с согласованными тиками дала %d событий, ожидали 1", len(spy.calls))
	}
}

// Штатное снятие и новая блокировка тоже НЕ обнуляют потолок частоты: иначе
// сервер, гоняющий lock/unlock, стал бы обходным путём для флуда.
func TestTamperReport_RelockDoesNotResetCooldown(t *testing.T) {
	m, _, spy := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)

	forgeUnlocked(t, m.path, "x")
	m.detectOfflineUnlock()

	if err := m.Unlock(); err != nil {
		t.Fatal(err)
	}
	m.detectOfflineUnlock()

	lockForTamper(t, m)
	forgeUnlocked(t, m.path, "z")
	m.detectOfflineUnlock()

	if len(spy.calls) != 1 {
		t.Fatalf("перезапирание обнулило дедуп: %d событий, ожидали 1", len(spy.calls))
	}
}

// Файл недоступен (удалён) — судить о подделке не по чему: события нет и потолок
// частоты не трогается.
func TestTamperReport_UnreadableStateIsSilent(t *testing.T) {
	m, _, spy := newMgrTamper(t, time.Hour)
	lockForTamper(t, m)

	if err := os.Remove(m.path); err != nil {
		t.Fatal(err)
	}
	m.detectOfflineUnlock()

	if len(spy.calls) != 0 {
		t.Fatalf("недоступный файл состояния дал %d событий, ожидали 0", len(spy.calls))
	}
}

// Репортер не подключён (nil по умолчанию) — tamper-путь обязан отработать
// полностью: лок пере-утверждён, оверлей поднят, паники нет.
func TestTamperReport_NilReporterStillReasserts(t *testing.T) {
	fl := &fakeLocker{}
	m, durable := newMgrDurable(t, fl)
	hash := lockForTamper(t, m)

	forgeUnlocked(t, m.path, "")
	m.detectOfflineUnlock()

	assertTamperReasserted(t, m, m.path, durable, hash)
	if fl.reasserts() == 0 {
		t.Fatal("оверлей не поднят принудительно при отключённом репортере")
	}
}

// Лог тоже не должен принимать мегабайты от непривилегированного пользователя
// раз в секунду.
func TestTruncateMarker(t *testing.T) {
	if got := truncateMarker("короткий"); got != "короткий" {
		t.Fatalf("короткое значение изменено: %q", got)
	}
	long := strings.Repeat("A", 5<<20)
	got := truncateMarker(long)
	if len(got) > maxLoggedMarker+64 {
		t.Fatalf("обрезка не сработала: длина %d", len(got))
	}
	if !strings.Contains(got, "обрезано") {
		t.Fatalf("факт обрезки не помечен: %q", got)
	}
}
