package uninstall

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
	pb "github.com/Floodww/RoutineOps/proto"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeExec подменяет платформенного исполнителя: реальный msiexec/pacman в тесте
// не запустить, поэтому проверяемой границей становится контракт
// Manager↔исполнитель.
type fakeExec struct {
	calls  []collector.Software
	out    string
	err    error
	onCall func()
}

func (f *fakeExec) run(_ context.Context, target collector.Software, _ *slog.Logger) (string, error) {
	f.calls = append(f.calls, target)
	if f.onCall != nil {
		f.onCall()
	}
	return f.out, f.err
}

// newTestManager собирает Manager со снимками, которые отдаются ПО ОЧЕРЕДИ:
// первый вызов — состояние до снятия, второй — после. Именно эта
// последовательность и проверяет, что вывод об успехе делается по повторному
// снимку, а не по коду возврата деинсталлятора.
func newTestManager(snapshots [][]collector.Software, ex *fakeExec) *Manager {
	i := 0
	return &Manager{
		scan: func() []collector.Software {
			s := snapshots[min(i, len(snapshots)-1)]
			i++
			return s
		},
		exec: ex.run,
		self: testSelf(),
		log:  quietLog(),
	}
}

func chrome() collector.Software {
	return collector.Software{
		Name: "Google Chrome", Version: "120.0.1", Vendor: "Google LLC",
		InstallLocation: "/Applications/Google Chrome.app",
		UninstallMethod: collector.UninstallMacAppBundle, Scope: collector.ScopeMachine,
	}
}

func TestRun_Removed(t *testing.T) {
	ex := &fakeExec{out: "удалён бандл"}
	m := newTestManager([][]collector.Software{{chrome()}, {}}, ex)

	res := m.Run(context.Background(), Request{Name: "Google Chrome", Version: "120.0.1"})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_REMOVED {
		t.Fatalf("исход = %v (%s), ожидали REMOVED", res.Outcome, res.Detail)
	}
	if len(ex.calls) != 1 {
		t.Fatalf("исполнитель вызван %d раз, ожидали 1", len(ex.calls))
	}
	if ex.calls[0].UninstallMethod != collector.UninstallMacAppBundle {
		t.Errorf("исполнителю передан метод %q — он обязан приходить из СВЕЖЕГО снимка", ex.calls[0].UninstallMethod)
	}
}

// Ядро контракта: успешный код возврата деинсталлятора ничего не доказывает.
// msiexec отдаёт 0 на снос, отложенный до перезагрузки; pkgutil --forget только
// чистит квитанцию. Отчитаться «снято» по коду возврата означало бы соврать
// оператору про работающую программу.
func TestRun_ExecSucceededButSoftwareStillThere(t *testing.T) {
	ex := &fakeExec{out: "ok"}
	m := newTestManager([][]collector.Software{{chrome()}, {chrome()}}, ex)

	res := m.Run(context.Background(), Request{Name: "Google Chrome", Version: "120.0.1"})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_STILL_PRESENT {
		t.Fatalf("исход = %v (%s), ожидали STILL_PRESENT", res.Outcome, res.Detail)
	}
}

// «На машине такого нет» — намерение оператора выполнено, спорить не о чем.
// Исполнителя при этом не трогаем вовсе.
func TestRun_AlreadyAbsent(t *testing.T) {
	ex := &fakeExec{}
	m := newTestManager([][]collector.Software{{}}, ex)

	res := m.Run(context.Background(), Request{Name: "Google Chrome"})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_ALREADY_ABSENT {
		t.Fatalf("исход = %v (%s), ожидали ALREADY_ABSENT", res.Outcome, res.Detail)
	}
	if len(ex.calls) != 0 {
		t.Fatal("исполнитель не должен вызываться, когда удалять нечего")
	}
}

// А вот «имя есть, но запись разъехалась» — принципиально ДРУГОЙ исход:
// между снимком инвентаря и командой ПО обновили, и снос по одному имени снял бы
// не ту версию. Схлопывание с ALREADY_ABSENT означало бы либо ложное «удалено»,
// либо ложную тревогу.
func TestRun_TargetChanged(t *testing.T) {
	updated := chrome()
	updated.Version = "121.0.0"
	ex := &fakeExec{}
	m := newTestManager([][]collector.Software{{updated}}, ex)

	res := m.Run(context.Background(), Request{Name: "Google Chrome", Version: "120.0.1"})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED {
		t.Fatalf("исход = %v (%s), ожидали TARGET_CHANGED", res.Outcome, res.Detail)
	}
	if len(ex.calls) != 0 {
		t.Fatal("исполнитель не должен вызываться при разъехавшейся цели")
	}
	// Оператору нужно видеть, что именно на машине вместо ожидаемого.
	if !strings.Contains(res.Detail, "121.0.0") {
		t.Errorf("в причине нет фактической версии: %q", res.Detail)
	}
}

func TestRun_SelectorFieldsAreCheckedIndividually(t *testing.T) {
	base := chrome()
	cases := []struct {
		name string
		req  Request
		want pb.UninstallOutcome
	}{
		{"версия разошлась", Request{Name: base.Name, Version: "999"}, pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED},
		{"ключ разошёлся", Request{Name: base.Name, UninstallID: "другой"}, pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED},
		{"путь разошёлся", Request{Name: base.Name, InstallLocation: "/Applications/Other.app"}, pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED},
		{"scope разошёлся", Request{Name: base.Name, Scope: collector.ScopeUser}, pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED},
		{"метод разошёлся", Request{Name: base.Name, Method: collector.UninstallMSI}, pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED},
		// Пустые поля означают «сервер этого не знает» и сверке не подлежат.
		{"только имя", Request{Name: base.Name}, pb.UninstallOutcome_UNINSTALL_OUTCOME_REMOVED},
		{"путь совпал с точностью до разделителя", Request{Name: base.Name, InstallLocation: "/Applications/Google Chrome.app/"}, pb.UninstallOutcome_UNINSTALL_OUTCOME_REMOVED},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ex := &fakeExec{}
			m := newTestManager([][]collector.Software{{base}, {}}, ex)
			if got := m.Run(context.Background(), c.req); got.Outcome != c.want {
				t.Fatalf("исход = %v (%s), ожидали %v", got.Outcome, got.Detail, c.want)
			}
		})
	}
}

// Две записи, неразличимые по всему, что знает сервер. Выбрать «какую-нибудь»
// означало бы снести произвольную из них.
func TestRun_AmbiguousSelectorRefuses(t *testing.T) {
	a, b := chrome(), chrome()
	b.InstallLocation = "/Users/ivan/Applications/Google Chrome.app"
	ex := &fakeExec{}
	m := newTestManager([][]collector.Software{{a, b}}, ex)

	res := m.Run(context.Background(), Request{Name: "Google Chrome", Version: "120.0.1"})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_AMBIGUOUS {
		t.Fatalf("исход = %v (%s), ожидали AMBIGUOUS", res.Outcome, res.Detail)
	}
	if len(ex.calls) != 0 {
		t.Fatal("при неоднозначной цели исполнитель вызываться не должен")
	}
}

// Метод берётся из СВЕЖЕГО снимка. Пустой метод = коллектор не нашёл тихого
// деинсталлятора; исполнять тут нечего, и врать оператору нельзя.
func TestRun_NotRemovable(t *testing.T) {
	sw := chrome()
	sw.UninstallMethod = collector.UninstallNone
	ex := &fakeExec{}
	m := newTestManager([][]collector.Software{{sw}}, ex)

	res := m.Run(context.Background(), Request{Name: sw.Name, Method: collector.UninstallMacAppBundle})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_NOT_REMOVABLE {
		t.Fatalf("исход = %v (%s), ожидали NOT_REMOVABLE", res.Outcome, res.Detail)
	}
	if len(ex.calls) != 0 {
		t.Fatal("исполнитель не должен вызываться, когда снимать нечем")
	}
}

// Самозащита на уровне Run: до сканирования и до исполнителя дело не доходит.
func TestRun_SelfProtected_BySelector(t *testing.T) {
	scanned := false
	ex := &fakeExec{}
	m := &Manager{
		scan: func() []collector.Software { scanned = true; return nil },
		exec: ex.run,
		self: testSelf(),
		log:  quietLog(),
	}

	res := m.Run(context.Background(), Request{Name: "RoutineOps Agent"})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_SELF_PROTECTED {
		t.Fatalf("исход = %v (%s), ожидали SELF_PROTECTED", res.Outcome, res.Detail)
	}
	if scanned {
		t.Error("команда на себя не должна доходить даже до снятия инвентаря")
	}
	if len(ex.calls) != 0 {
		t.Fatal("исполнитель вызван на команде против самого агента")
	}
}

// Второй рубеж: селектор безобидный, а найденная запись — агент (сервер знал
// только имя, а путь ведёт в каталог агента). Один guard по селектору такой
// случай пропустил бы.
func TestRun_SelfProtected_ByResolvedRecord(t *testing.T) {
	disguised := collector.Software{
		Name: "Системный компонент", Version: "1.0",
		InstallLocation: "/opt/RoutineOps",
		UninstallMethod: collector.UninstallDpkg, Scope: collector.ScopeMachine,
	}
	ex := &fakeExec{}
	m := newTestManager([][]collector.Software{{disguised}}, ex)

	res := m.Run(context.Background(), Request{Name: "Системный компонент"})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_SELF_PROTECTED {
		t.Fatalf("исход = %v (%s), ожидали SELF_PROTECTED", res.Outcome, res.Detail)
	}
	if len(ex.calls) != 0 {
		t.Fatal("исполнитель вызван на записи самого агента")
	}
}

func TestRun_ExecFailureIsReportedWithReason(t *testing.T) {
	ex := &fakeExec{out: "msiexec: 1603", err: errors.New("msiexec.exe завершился с кодом 1603")}
	m := newTestManager([][]collector.Software{{chrome()}, {chrome()}}, ex)

	res := m.Run(context.Background(), Request{Name: "Google Chrome"})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_FAILED {
		t.Fatalf("исход = %v, ожидали FAILED", res.Outcome)
	}
	if !strings.Contains(res.Detail, "1603") {
		t.Errorf("причина отказа не доехала до оператора: %q", res.Detail)
	}
}

// Вывод деинсталлятора уезжает в proto3 string, который ОБЯЗАН быть валидным
// UTF-8. На русской Windows он приезжает в OEM-кодировке — без санации
// Marshal отчёта упал бы, и результат потерялся бы целиком.
func TestRun_OutputIsSanitizedForProto(t *testing.T) {
	ex := &fakeExec{out: "снято \xff\xfe кодировка"}
	m := newTestManager([][]collector.Software{{chrome()}, {}}, ex)

	res := m.Run(context.Background(), Request{Name: "Google Chrome"})

	if !utf8.ValidString(res.Detail) {
		t.Fatalf("Detail не валидный UTF-8: %q", res.Detail)
	}
}

func TestRun_EmptyNameRefused(t *testing.T) {
	ex := &fakeExec{}
	m := newTestManager([][]collector.Software{{chrome()}}, ex)
	for _, name := range []string{"", "   "} {
		res := m.Run(context.Background(), Request{Name: name})
		if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED {
			t.Fatalf("имя %q: исход = %v, ожидали отказ", name, res.Outcome)
		}
		if len(ex.calls) != 0 {
			t.Fatal("исполнитель вызван по пустому селектору")
		}
	}
}

// Повторный снимок сверяет запись по ВСЕМ машинным признакам. Иначе
// переустановленный сразу же другой версией продукт (или одноимённый чужой)
// выглядел бы как «не снялось».
func TestRun_ReinstalledOtherVersionCountsAsRemoved(t *testing.T) {
	after := chrome()
	after.Version = "121.0.0"
	ex := &fakeExec{}
	m := newTestManager([][]collector.Software{{chrome()}, {after}}, ex)

	res := m.Run(context.Background(), Request{Name: "Google Chrome", Version: "120.0.1"})

	if res.Outcome != pb.UninstallOutcome_UNINSTALL_OUTCOME_REMOVED {
		t.Fatalf("исход = %v (%s), ожидали REMOVED: целевая запись из снимка исчезла", res.Outcome, res.Detail)
	}
}
