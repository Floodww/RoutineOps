package uninstall

import (
	"path/filepath"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// testSelf — идентичность агента с фиксированными путями, чтобы тесты не зависели
// от того, где лежит бинарь самого теста.
func testSelf() selfID {
	exe := filepath.Join(string(filepath.Separator), "opt", "RoutineOps", "RoutineOps-agent")
	return selfID{exePath: exe, exeDir: filepath.Dir(exe)}
}

// Главный тест пакета: НИ ОДИН из способов адресовать агента не должен пройти.
// Каждый признак проверяется в одиночку — они независимы, и достаточно одного,
// потому что в поле любой из них может отсутствовать (переименованный
// дистрибутив, пустой InstallLocation, установка мимо пакетного менеджера).
func TestSelfGuard_BlocksEverySelfSignal(t *testing.T) {
	self := testSelf()
	cases := []struct {
		name string
		sw   collector.Software
	}{
		{"по имени продукта", collector.Software{Name: "RoutineOps Agent"}},
		{"по имени в другом регистре", collector.Software{Name: "routineops agent"}},
		{"по имени с пробелами по краям", collector.Software{Name: "  RoutineOps-Agent  "}},
		{"по историческому имени до ребрендинга", collector.Software{Name: "mdm-agent"}},
		{"по имени пакета в машинном ключе", collector.Software{Name: "Что-то", UninstallID: "routineops-agent"}},
		{"по издателю", collector.Software{Name: "Что-то", Vendor: "RoutineOps"}},
		{"по каталогу установки", collector.Software{Name: "Что-то", InstallLocation: "/opt/RoutineOps"}},
		{"по каталогу с хвостовым разделителем", collector.Software{Name: "Что-то", InstallLocation: "/opt/RoutineOps/"}},
		{"по пути самого бинаря", collector.Software{Name: "Что-то", InstallLocation: "/opt/RoutineOps/RoutineOps-agent"}},
		{"по каталогу в другом регистре", collector.Software{Name: "Что-то", InstallLocation: "/OPT/routineops"}},
		{"по каталогу с лишними сегментами", collector.Software{Name: "Что-то", InstallLocation: "/opt/./RoutineOps"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if why := self.matchesSoftware(c.sw); why == "" {
				t.Fatalf("guard пропустил самого агента: %+v", c.sw)
			}
		})
	}
}

// Обратная сторона: guard не должен превращаться в запрет на удаление чего угодно.
func TestSelfGuard_AllowsThirdPartySoftware(t *testing.T) {
	self := testSelf()
	cases := []collector.Software{
		{Name: "Google Chrome", Vendor: "Google LLC", InstallLocation: "/Applications/Google Chrome.app"},
		{Name: "7-Zip", Vendor: "Igor Pavlov", InstallLocation: `C:\Program Files\7-Zip`},
		{Name: "routineops-monitor", Vendor: "Другая контора", UninstallID: "routineops-monitor"},
		// Соседний каталог с общим префиксом — не наш: без проверки разделителя
		// guard съел бы и его.
		{Name: "Пакет", InstallLocation: "/opt/RoutineOps-data"},
		{Name: "Пакет", InstallLocation: "/opt/RoutineOpsExtra"},
	}
	for _, sw := range cases {
		t.Run(sw.Name+" "+sw.InstallLocation, func(t *testing.T) {
			if why := self.matchesSoftware(sw); why != "" {
				t.Fatalf("guard заблокировал чужое ПО (%s): %+v", why, sw)
			}
		})
	}
}

// Guard обязан срабатывать и на СЕЛЕКТОРЕ, до какого-либо сканирования: команда,
// нацеленная на агента, не должна доходить даже до снятия инвентаря.
func TestSelfGuard_BlocksRequestBeforeAnyWork(t *testing.T) {
	self := testSelf()
	if why := self.matchesRequest(Request{Name: "RoutineOps Agent"}); why == "" {
		t.Fatal("селектор с именем агента должен блокироваться")
	}
	if why := self.matchesRequest(Request{Name: "Chrome", InstallLocation: "/opt/RoutineOps"}); why == "" {
		t.Fatal("селектор с путём агента должен блокироваться")
	}
	if why := self.matchesRequest(Request{Name: "Chrome", InstallLocation: "/Applications/Chrome.app"}); why != "" {
		t.Fatalf("чужой селектор заблокирован: %s", why)
	}
}

// Пустые поля не должны считаться совпадением: иначе запись без пути и издателя
// (обычное дело для скудных источников) выглядела бы как агент, и удалить нельзя
// было бы ничего.
func TestSelfGuard_EmptyFieldsAreNotAMatch(t *testing.T) {
	self := testSelf()
	if why := self.matchesSoftware(collector.Software{Name: "Пакет"}); why != "" {
		t.Fatalf("запись без признаков не должна считаться агентом: %s", why)
	}
	if why := self.matchesSoftware(collector.Software{Name: "Пакет", UninstallID: "", Vendor: "", InstallLocation: ""}); why != "" {
		t.Fatalf("пустые поля дали совпадение: %s", why)
	}
}

func TestPathCovers(t *testing.T) {
	sep := string(filepath.Separator)
	cases := []struct {
		parent, child string
		want          bool
	}{
		{"/opt/RoutineOps", "/opt/RoutineOps/RoutineOps-agent", true},
		{"/opt/RoutineOps", "/opt/RoutineOps", true},
		{"/opt/RoutineOps", "/opt/RoutineOps-data/bin", false},
		{"/opt/RoutineOps", "/opt", false},
		{"", "/opt/RoutineOps", false},
		{"/opt/RoutineOps", "", false},
		// Windows-пути приезжают в инвентаре с обратными слэшами и в любом регистре.
		{`C:\Program Files\RoutineOps`, `C:/program files/routineops/RoutineOps-agent.exe`, true},
		{`C:\Program Files\RoutineOps`, `C:\Program Files\RoutineOpsX`, false},
	}
	for _, c := range cases {
		if got := pathCovers(c.parent, c.child); got != c.want {
			t.Errorf("pathCovers(%q, %q) = %v, ожидали %v (разделитель %q)", c.parent, c.child, got, c.want, sep)
		}
	}
}

// resolveSelf работает на реальном процессе: если он падает, фича отключается
// целиком, поэтому проверяем, что на штатной машине он всё-таки отдаёт пути.
func TestResolveSelf_ReturnsAbsolutePaths(t *testing.T) {
	self, err := resolveSelf()
	if err != nil {
		t.Fatalf("resolveSelf: %v", err)
	}
	if !filepath.IsAbs(self.exePath) {
		t.Errorf("exePath не абсолютный: %q", self.exePath)
	}
	if self.exeDir == "" || self.exeDir == self.exePath {
		t.Errorf("exeDir = %q при exePath = %q", self.exeDir, self.exePath)
	}
}
