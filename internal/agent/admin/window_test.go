package admin

import (
	"fmt"
	"testing"
	"time"
)

// Сборка окна улик. Главные проверки здесь не про «дельта посчиталась», а про то,
// что окно НИКОГДА не выдаёт отказ сбора за факт: ни за «сотрудник поставил всё,
// что есть на машине», ни за «сотрудник удалил всё», ни за «изменений не было».

func winBaseline(soft []SoftFP, svc []SvcFP) *SessionState {
	return &SessionState{
		RequestID: "req-1", User: "ivan", GrantedAt: t0,
		SoftwareHealth: "ok", ServicesHealth: "ok",
		Software: soft, Services: svc,
	}
}

func winInv(soft []SoftFP, svc []SvcFP) Inventory {
	return Inventory{Software: soft, SoftwareHealth: "ok", Services: svc, ServicesHealth: "ok"}
}

func TestBuildWindowDelta(t *testing.T) {
	st := winBaseline(
		[]SoftFP{{Key: "browser", Name: "Браузер", Version: "141"}},
		[]SvcFP{{Key: "svc-a", DefHash: "h1", OSOwned: true}},
	)
	cur := winInv(
		[]SoftFP{
			{Key: "browser", Name: "Браузер", Version: "142"},
			{Key: "tool", Name: "Утилита", Version: "1.0"},
		},
		[]SvcFP{
			{Key: "svc-a", DefHash: "h1", OSOwned: true},
			{Key: "svc-new", DefHash: "h2", ImagePath: "/opt/x", Kind: "service"},
		},
	)

	w := BuildWindow(st, cur, WindowInput{Seq: 1, Now: t0.Add(time.Hour)})

	if w.Completeness != CompletenessComplete {
		t.Fatalf("полнота: got %q, want %q", w.Completeness, CompletenessComplete)
	}
	if w.RequestID != "req-1" || !w.WindowStart.Equal(t0) {
		t.Fatalf("окно не привязано к заявке: %+v", w)
	}
	if len(w.Changes) != 3 {
		t.Fatalf("изменений: got %d, want 3: %+v", len(w.Changes), w.Changes)
	}
	kinds := map[string]int{}
	for _, c := range w.Changes {
		kinds[c.Kind]++
	}
	if kinds[ChangeSoftwareUpdated] != 1 || kinds[ChangeSoftwareInstalled] != 1 || kinds[ChangeServiceInstalled] != 1 {
		t.Fatalf("состав дельты: %+v", kinds)
	}
}

// Потерянная базовая линия НЕ ПРЕВРАЩАЕТСЯ в обвинение. Это главный тест файла:
// обычный diff от пустой базовой линии выдал бы весь инвентарь машины как
// «появилось за сессию» — готовое обвинение сотрудника в установке всего, что на
// машине есть, включая приехавшее с образом.
func TestBuildWindowNoBaselineDoesNotFabricateInstalls(t *testing.T) {
	cur := winInv(
		[]SoftFP{{Key: "a", Name: "A"}, {Key: "b", Name: "B"}, {Key: "c", Name: "C"}},
		[]SvcFP{{Key: "s1"}, {Key: "s2"}},
	)

	for _, tc := range []struct {
		name string
		st   *SessionState
		in   WindowInput
	}{
		{"состояния нет вовсе", nil, WindowInput{Seq: 1, Now: t0}},
		{"пустая базовая линия", winBaseline(nil, nil), WindowInput{Seq: 1, Now: t0, BaselineLost: true}},
		// Признак потери обязан перевешивать даже НЕПУСТУЮ базовую линию: если
		// состояние прочиталось, но помечено недостоверным, дельта от него —
		// такое же выдуманное обвинение, как дельта от пустоты.
		{"непустая базовая линия, помеченная потерянной",
			winBaseline([]SoftFP{{Key: "old", Name: "Старое"}}, []SvcFP{{Key: "s0"}}),
			WindowInput{Seq: 1, Now: t0, BaselineLost: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := BuildWindow(tc.st, cur, tc.in)
			if len(w.Changes) != 0 || w.TotalChanges != 0 {
				t.Fatalf("без базовой линии дельта обязана быть пустой, got %d: %+v", len(w.Changes), w.Changes)
			}
			if w.Completeness != CompletenessNoBaseline {
				t.Fatalf("полнота: got %q, want %q", w.Completeness, CompletenessNoBaseline)
			}
		})
	}
}

// Отказ сбора В МОМЕНТ ВЫДАЧИ прав не должен читаться как «машина была пустой».
func TestBuildWindowFailedBaselineSourceIsNotEmptyMachine(t *testing.T) {
	st := winBaseline(nil, []SvcFP{{Key: "s1"}})
	st.SoftwareHealth = "failed" // инвентарь ПО в момент выдачи прав не снялся
	cur := winInv([]SoftFP{{Key: "a", Name: "A"}, {Key: "b", Name: "B"}}, []SvcFP{{Key: "s1"}})

	w := BuildWindow(st, cur, WindowInput{Seq: 1, Now: t0})

	for _, c := range w.Changes {
		if c.Kind == ChangeSoftwareInstalled {
			t.Fatalf("отказ сбора выдан за установку: %+v", c)
		}
	}
	if w.Completeness != CompletenessPartial {
		t.Fatalf("полнота: got %q, want %q", w.Completeness, CompletenessPartial)
	}
	if w.SoftwareHealth != "failed" {
		t.Fatalf("здоровье базовой линии потеряно: %q", w.SoftwareHealth)
	}
}

// Зеркальный случай: отказ ТЕКУЩЕГО среза не должен читаться как «сотрудник всё снёс».
func TestBuildWindowFailedCurrentSourceIsNotMassRemoval(t *testing.T) {
	st := winBaseline([]SoftFP{{Key: "a", Name: "A"}, {Key: "b", Name: "B"}}, []SvcFP{{Key: "s1"}})
	cur := Inventory{Software: nil, SoftwareHealth: "failed", Services: []SvcFP{{Key: "s1"}}, ServicesHealth: "ok"}

	w := BuildWindow(st, cur, WindowInput{Seq: 1, Now: t0})

	for _, c := range w.Changes {
		if c.Kind == ChangeSoftwareRemoved {
			t.Fatalf("отказ сбора выдан за удаление: %+v", c)
		}
	}
	if w.Completeness != CompletenessPartial {
		t.Fatalf("полнота: got %q, want %q", w.Completeness, CompletenessPartial)
	}
}

// Негодное здоровье блокирует дельту само по себе — даже когда оба среза
// непустые и обычный diff отработал бы «успешно». Без этого гейт держался бы
// только на проверке непустоты, а она ловит лишь полный отказ источника.
func TestBuildWindowBadHealthBlocksDiffEvenWithData(t *testing.T) {
	for _, health := range []string{"failed", "unsupported", "какая-то новая беда"} {
		t.Run(health, func(t *testing.T) {
			st := winBaseline([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
			st.SoftwareHealth = health
			cur := winInv([]SoftFP{{Key: "a", Name: "A"}, {Key: "b", Name: "B"}}, []SvcFP{{Key: "s1"}})

			w := BuildWindow(st, cur, WindowInput{Seq: 1, Now: t0})

			if len(w.Changes) != 0 {
				t.Fatalf("дельта посчитана на здоровье %q: %+v", health, w.Changes)
			}
			if w.Completeness != CompletenessPartial {
				t.Fatalf("полнота: got %q, want %q", w.Completeness, CompletenessPartial)
			}
		})
	}
}

// Пустой источник при формально здоровом статусе тоже не «изменений не было».
func TestBuildWindowEmptySourceIsNeverComplete(t *testing.T) {
	full := func() (*SessionState, Inventory) {
		return winBaseline([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}}),
			winInv([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
	}
	// Каждый из четырёх срезов проверяется отдельно: гейт на одном источнике
	// не должен прикрывать дыру на другом.
	for _, tc := range []struct {
		name string
		mut  func(*SessionState, *Inventory)
	}{
		{"пуст инвентарь ПО в базовой линии", func(st *SessionState, _ *Inventory) { st.Software = nil }},
		{"пуст текущий инвентарь ПО", func(_ *SessionState, cur *Inventory) { cur.Software = nil }},
		{"пусты службы в базовой линии", func(st *SessionState, _ *Inventory) { st.Services = nil }},
		{"пусты текущие службы", func(_ *SessionState, cur *Inventory) { cur.Services = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, cur := full()
			tc.mut(st, &cur)

			w := BuildWindow(st, cur, WindowInput{Seq: 1, Now: t0})

			if w.Completeness != CompletenessPartial {
				t.Fatalf("пустой источник прочитался как полное окно: %q", w.Completeness)
			}
		})
	}
}

// partial пропускаем к дельте (иначе одна недоступная папка выключает фичу), но
// атрибуция обязана упасть до unknown, а полнота — сказать partial.
func TestBuildWindowPartialHealthDiffsButDegrades(t *testing.T) {
	st := winBaseline([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
	st.ServicesHealth = "partial"
	cur := winInv([]SoftFP{{Key: "a", Name: "A"}, {Key: "new", Name: "Новое"}}, []SvcFP{{Key: "s1"}})

	w := BuildWindow(st, cur, WindowInput{Seq: 1, Now: t0})

	if len(w.Changes) != 1 {
		t.Fatalf("дельта при partial обязана считаться: %+v", w.Changes)
	}
	if w.Changes[0].Attribution != AttrUnknown || w.Changes[0].AttributionReason != ReasonDegradedBaseline {
		t.Fatalf("атрибуция не снижена: %+v", w.Changes[0])
	}
	if w.Completeness != CompletenessPartial {
		t.Fatalf("полнота: got %q", w.Completeness)
	}
}

// unsupported (платформа не умеет смотреть службы) к дельте не пропускается.
func TestBuildWindowUnsupportedSourceSkipped(t *testing.T) {
	st := winBaseline([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
	st.ServicesHealth = "unsupported"
	cur := Inventory{
		Software: []SoftFP{{Key: "a", Name: "A"}}, SoftwareHealth: "ok",
		Services: []SvcFP{{Key: "s1"}, {Key: "s2"}}, ServicesHealth: "unsupported",
	}

	w := BuildWindow(st, cur, WindowInput{Seq: 1, Now: t0})

	for _, c := range w.Changes {
		if c.Kind == ChangeServiceInstalled {
			t.Fatalf("дельта служб посчитана на неподдержанной платформе: %+v", c)
		}
	}
	if w.Completeness != CompletenessPartial {
		t.Fatalf("полнота: got %q", w.Completeness)
	}
}

// Урезание сохраняет улики, а не алфавит: при переполнении первым вытесняется шум ОС.
//
// Фон здесь намеренно взят такой, чтобы в КАНОНИЧЕСКОМ порядке он шёл ПЕРЕД
// уликами (service_definition_changed сортируется раньше software_installed).
// Иначе тест проходил бы сам собой: наивное «взять первые N» сохранило бы улики
// случайно, потому что они оказались в начале списка.
func TestBuildWindowTruncationKeepsHumanLikely(t *testing.T) {
	var beforeSvc, afterSvc []SvcFP
	for i := 0; i < MaxWindowChanges; i++ {
		key := fmt.Sprintf("svc-%04d", i)
		beforeSvc = append(beforeSvc, SvcFP{Key: key, DefHash: "h1", OSOwned: true, Kind: "service"})
		afterSvc = append(afterSvc, SvcFP{Key: key, DefHash: "h2", OSOwned: true, Kind: "service"})
	}
	const humanCount = 50
	before := []SoftFP{{Key: "base", Name: "Base"}}
	after := []SoftFP{{Key: "base", Name: "Base"}}
	for i := 0; i < humanCount; i++ {
		key := fmt.Sprintf("zzz-human-%04d", i)
		after = append(after, SoftFP{Key: key, Name: key, Version: "1"})
	}

	w := BuildWindow(winBaseline(before, beforeSvc), winInv(after, afterSvc), WindowInput{Seq: 1, Now: t0})

	if !w.Truncated {
		t.Fatalf("окно обязано быть помечено урезанным")
	}
	if got, want := int(w.TotalChanges), MaxWindowChanges+humanCount; got != want {
		t.Fatalf("total_changes: got %d, want %d", got, want)
	}
	if len(w.Changes) != MaxWindowChanges {
		t.Fatalf("длина окна: got %d, want %d", len(w.Changes), MaxWindowChanges)
	}
	human := 0
	for _, c := range w.Changes {
		if c.Attribution == AttrHumanLikely {
			human++
		}
	}
	if human != humanCount {
		t.Fatalf("улики вытеснены фоном: human_likely в окне %d, было %d", human, humanCount)
	}
	if w.Completeness != CompletenessTruncated {
		t.Fatalf("полнота: got %q, want %q", w.Completeness, CompletenessTruncated)
	}
}

// Финал, снятый заметно позже реального конца сессии, не выдаётся за точный срез.
func TestBuildWindowStaleFinal(t *testing.T) {
	st := winBaseline([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
	cur := winInv([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
	end := t0.Add(time.Hour)
	now := end.Add(48 * time.Hour) // машина сутки лежала выключенной

	w := BuildWindow(st, cur, WindowInput{Seq: 4, Final: true, Now: now, SessionEnd: end})

	if w.Completeness != CompletenessStaleFinal {
		t.Fatalf("полнота: got %q, want %q", w.Completeness, CompletenessStaleFinal)
	}
	if !w.WindowEnd.Equal(end) {
		t.Fatalf("окно датировано не концом сессии: %v", w.WindowEnd)
	}
	if !w.SnapshotAt.After(w.WindowEnd) {
		t.Fatalf("snapshot_at обязан отличаться от window_end при stale_final: %v vs %v", w.SnapshotAt, w.WindowEnd)
	}
}

func TestBuildWindowFreshFinalIsComplete(t *testing.T) {
	st := winBaseline([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
	cur := winInv([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
	now := t0.Add(time.Hour)

	w := BuildWindow(st, cur, WindowInput{Seq: 4, Final: true, Now: now, SessionEnd: now})

	if w.Completeness != CompletenessComplete {
		t.Fatalf("полнота: got %q, want %q", w.Completeness, CompletenessComplete)
	}
	if len(w.Changes) != 0 {
		t.Fatalf("изменений быть не должно: %+v", w.Changes)
	}
}

// Полнота идёт от тяжёлого к лёгкому: «не от чего считать» перебивает «урезано».
func TestCompletenessPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		w      Window
		stale  bool
		skip   bool
		expect string
	}{
		{"нет базовой линии перебивает всё", Window{BaselineLost: true, Truncated: true, SoftwareHealth: "failed"}, true, true, CompletenessNoBaseline},
		{"деградация перебивает stale", Window{SoftwareHealth: "partial"}, true, false, CompletenessPartial},
		{"пропущенный источник = partial", Window{SoftwareHealth: "ok", ServicesHealth: "ok"}, false, true, CompletenessPartial},
		{"stale перебивает урезание", Window{Truncated: true}, true, false, CompletenessStaleFinal},
		{"урезание", Window{Truncated: true}, false, false, CompletenessTruncated},
		{"всё хорошо", Window{}, false, false, CompletenessComplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := completenessOf(tc.w, tc.stale, tc.skip); got != tc.expect {
				t.Fatalf("got %q, want %q", got, tc.expect)
			}
		})
	}
}

func TestBuildWindowRebootFlag(t *testing.T) {
	st := winBaseline([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
	st.BootTime = 1000
	cur := winInv([]SoftFP{{Key: "a", Name: "A"}}, []SvcFP{{Key: "s1"}})
	cur.BootTime = 2000

	if w := BuildWindow(st, cur, WindowInput{Seq: 1, Now: t0}); !w.Rebooted {
		t.Fatalf("ребут внутри сессии не отмечен")
	}
	cur.BootTime = 1000
	if w := BuildWindow(st, cur, WindowInput{Seq: 1, Now: t0}); w.Rebooted {
		t.Fatalf("ребут отмечен без ребута")
	}
}

func TestClampWindowInterval(t *testing.T) {
	for _, tc := range []struct {
		sec  int32
		want time.Duration
	}{
		{0, DefaultWindowInterval},  // старый сервер, поля нет
		{-1, DefaultWindowInterval}, // мусор
		{10, MinWindowInterval},     // попытка задушить парк снимками
		{300, MinWindowInterval},    // ровно граница
		{3600, time.Hour},           // штатное значение
		{86400, 24 * time.Hour},     // верхней границы нет намеренно
	} {
		if got := ClampWindowInterval(tc.sec); got != tc.want {
			t.Fatalf("ClampWindowInterval(%d): got %v, want %v", tc.sec, got, tc.want)
		}
	}
}

// Отпечаток окна обязан реагировать не только на список изменений, но и на то,
// как этот список следует читать.
func TestWindowDigestCoversReadability(t *testing.T) {
	base := Window{
		Changes:      []Change{{Kind: ChangeSoftwareInstalled, IdentityKey: "a", Subject: "A", Attribution: AttrHumanLikely}},
		TotalChanges: 1, Completeness: CompletenessComplete, SoftwareHealth: "ok", ServicesHealth: "ok",
	}
	same := base
	same.Changes = []Change{{Kind: ChangeSoftwareInstalled, IdentityKey: "a", Subject: "A", Attribution: AttrHumanLikely}}
	if windowDigest(base) != windowDigest(same) {
		t.Fatalf("одинаковые окна дали разные отпечатки")
	}

	for _, tc := range []struct {
		name string
		mut  func(w *Window)
	}{
		{"деградация сбора", func(w *Window) { w.SoftwareHealth = "partial"; w.Completeness = CompletenessPartial }},
		{"ребут", func(w *Window) { w.Rebooted = true }},
		{"урезание", func(w *Window) { w.Truncated = true; w.TotalChanges = 5000 }},
		{"другая атрибуция", func(w *Window) { w.Changes[0].Attribution = AttrBackgroundLikely }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			mutated.Changes = append([]Change(nil), base.Changes...)
			tc.mut(&mutated)
			if windowDigest(base) == windowDigest(mutated) {
				t.Fatalf("изменение %q не поменяло отпечаток", tc.name)
			}
		})
	}
}
