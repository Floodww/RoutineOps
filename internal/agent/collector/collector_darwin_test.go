//go:build darwin

package collector

import (
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

func TestParseFileVaultStatus(t *testing.T) {
	cases := []struct{ in, want string }{
		{"FileVault is On.\n", "enabled"},
		{"FileVault is Off.\n", "disabled"},
		{"FileVault is Off, but Deferred enablement appears to be active.\n", "disabled"},
		{"fdesetup: unknown error\n", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := parseFileVaultStatus(c.in); got != c.want {
			t.Errorf("parseFileVaultStatus(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseInstallHistory(t *testing.T) {
	data := []byte(`{"SPInstallHistoryDataType":[
		{"_name":"Chrome","install_date":"2026-07-15T10:00:00Z","package_source":"package_source_other"},
		{"_name":"XProtectPlistConfigData","install_date":"2026-06-05T17:59:24Z","package_source":"package_source_apple"},
		{"_name":"macOS 26.2","install_date":"2026-06-20 10:00:00 +0000","package_source":"package_source_apple"},
		{"_name":"macOS 26.1","install_date":"2026-05-01T09:00:00Z","package_source":"package_source_apple"},
		{"_name":"битая запись","install_date":"вчера","package_source":"package_source_apple"}
	]}`)
	// Сторонний Chrome от 15.07 НЕ считается обновлением ОС — берётся максимум
	// только по package_source_apple; запись от 20.06 в запасном формате
	// с пробелом (installDateLayouts) участвует в максимуме наравне с RFC3339.
	if got := parseInstallHistory(data); got != "2026-06-20" {
		t.Errorf("parseInstallHistory = %q, want 2026-06-20", got)
	}
	if got := parseInstallHistory([]byte("не json")); got != "" {
		t.Errorf("parseInstallHistory(мусор) = %q, want пусто", got)
	}
	if got := parseInstallHistory([]byte(`{"SPInstallHistoryDataType":[]}`)); got != "" {
		t.Errorf("parseInstallHistory(пусто) = %q, want пусто", got)
	}
}

func TestParseBootTime(t *testing.T) {
	if got := parseBootTime("{ sec = 1752834000, usec = 123456 } Thu Jul 17 12:00:00 2026\n"); got != 1752834000 {
		t.Errorf("parseBootTime = %d, want 1752834000", got)
	}
	if got := parseBootTime("мусор без sec"); got != 0 {
		t.Errorf("parseBootTime(мусор) = %d, want 0", got)
	}
}

// liveApplicationsFragment — реальный фрагмент `system_profiler -json
// SPApplicationsDataType` с живого мака (macOS 26.3), обезличенный: домашний
// каталог заменён на /Users/testuser, персональное имя в Developer ID —
// на организацию. Набор записей подобран так, чтобы покрыть все встреченные
// живьём каналы подписи (Software Signing / Developer ID / Mac App Store /
// подписи нет) и все классы путей.
const liveApplicationsFragment = `{"SPApplicationsDataType":[
	{"_name":"Google Chrome","arch_kind":"arch_arm_i64","lastModified":"2026-06-16T06:20:06Z",
	 "obtained_from":"identified_developer","path":"/Applications/Google Chrome.app","version":"150.0.7871.182",
	 "signed_by":["Developer ID Application: Google LLC (EQHXZ8M8AV)","Developer ID Certification Authority","Apple Root CA"]},
	{"_name":"Почта","arch_kind":"arch_arm_i64","lastModified":"2026-06-25T02:29:03Z",
	 "obtained_from":"apple","path":"/System/Applications/Mail.app","version":"16.0",
	 "signed_by":["Software Signing","Apple Code Signing Certification Authority","Apple Root CA"]},
	{"_name":"Keynote","arch_kind":"arch_arm_i64","lastModified":"2026-03-02T19:46:11Z",
	 "obtained_from":"mac_app_store","path":"/Applications/Keynote.app","version":"14.4",
	 "signed_by":["Apple Mac OS Application Signing","Apple Worldwide Developer Relations Certification Authority","Apple Root CA"]},
	{"_name":"iTerm","arch_kind":"arch_arm","lastModified":"2026-06-02T10:16:06Z",
	 "obtained_from":"identified_developer","path":"/Users/testuser/Applications/iTerm.app","version":"3.6.11",
	 "signed_by":["Developer ID Application: Example Tools LLC (H7V7XYVQ7D)","Developer ID Certification Authority","Apple Root CA"]},
	{"_name":"GoogleUpdater","arch_kind":"arch_i64","lastModified":"2026-07-01T12:00:00Z",
	 "obtained_from":"identified_developer","path":"/Users/testuser/Library/Application Support/Google/GoogleUpdater/152.0.7933.0/GoogleUpdater.app","version":"152.0.7933.0",
	 "signed_by":["Developer ID Application: Google LLC (EQHXZ8M8AV)","Developer ID Certification Authority","Apple Root CA"]},
	{"_name":"XProtect","arch_kind":"arch_arm_i64","lastModified":"2026-06-25T02:29:03Z",
	 "obtained_from":"apple","path":"/Library/Apple/System/Library/CoreServices/XProtect.app","version":"157",
	 "signed_by":["Software Signing","Apple Code Signing Certification Authority","Apple Root CA"]},
	{"_name":"YouTube","arch_kind":"arch_web","lastModified":"2026-05-01T00:00:00Z",
	 "obtained_from":"safari","path":"/Users/testuser/Applications/YouTube.app"},
	{"_name":"Throne","arch_kind":"arch_i64","lastModified":"2026-04-01T00:00:00Z",
	 "obtained_from":"unknown","path":"/Users/testuser/Downloads/Throne/Throne.app","version":"1.0"},
	{"_name":"","arch_kind":"arch_other","obtained_from":"unknown","path":"/Users/testuser/Library/HTTPStorages/com.apple.ctcategories.service"}
]}`

// TestParseApplications проверяет разбор реальной выдачи целиком: и заполнение
// новых полей, и fail-safe решения (кому НЕ ставится метод снятия).
func TestParseApplications(t *testing.T) {
	got := parseApplications([]byte(liveApplicationsFragment))
	// Запись без _name отбрасывается (последний элемент фрагмента).
	want := []Software{
		{Name: "Google Chrome", Version: "150.0.7871.182", Vendor: "Google LLC",
			InstallLocation: "/Applications/Google Chrome.app", Arch: "universal",
			UninstallMethod: UninstallMacAppBundle, Scope: ScopeMachine},
		// Бинарь ОС: подпись Apple опознана, но /System под SIP — снимать нечем.
		{Name: "Почта", Version: "16.0", Vendor: "Apple Inc.",
			InstallLocation: "/System/Applications/Mail.app", Arch: "universal",
			UninstallMethod: UninstallNone, Scope: ScopeMachine},
		// Mac App Store: leaf — подпись Apple, настоящего вендора в выдаче нет → "".
		{Name: "Keynote", Version: "14.4", Vendor: "",
			InstallLocation: "/Applications/Keynote.app", Arch: "universal",
			UninstallMethod: UninstallMacAppBundle, Scope: ScopeMachine},
		// ~/Applications: снять можем (агент под root), но scope честно user.
		{Name: "iTerm", Version: "3.6.11", Vendor: "Example Tools LLC",
			InstallLocation: "/Users/testuser/Applications/iTerm.app", Arch: "arm64",
			UninstallMethod: UninstallMacAppBundle, Scope: ScopeUser},
		// Вложенный бандл апдейтера — часть чужой установки, не цель удаления.
		{Name: "GoogleUpdater", Version: "152.0.7933.0", Vendor: "Google LLC",
			InstallLocation: "/Users/testuser/Library/Application Support/Google/GoogleUpdater/152.0.7933.0/GoogleUpdater.app",
			Arch:            "x86_64", UninstallMethod: UninstallNone, Scope: ScopeUser},
		{Name: "XProtect", Version: "157", Vendor: "Apple Inc.",
			InstallLocation: "/Library/Apple/System/Library/CoreServices/XProtect.app", Arch: "universal",
			UninstallMethod: UninstallNone, Scope: ScopeMachine},
		// Веб-приложение Safari: подписи нет, arch_web — не архитектура.
		{Name: "YouTube", Version: "", Vendor: "",
			InstallLocation: "/Users/testuser/Applications/YouTube.app", Arch: "",
			UninstallMethod: UninstallMacAppBundle, Scope: ScopeUser},
		// Скачанный архив в ~/Downloads — не установка, удалять нечего.
		{Name: "Throne", Version: "1.0", Vendor: "",
			InstallLocation: "/Users/testuser/Downloads/Throne/Throne.app", Arch: "x86_64",
			UninstallMethod: UninstallNone, Scope: ScopeUser},
	}
	if len(got) != len(want) {
		t.Fatalf("parseApplications вернул %d записей, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("запись %d (%s):\n got  %+v\n want %+v", i, w.Name, got[i], w)
		}
	}

	if sw := parseApplications([]byte("не json")); sw != nil {
		t.Errorf("parseApplications(мусор) = %+v, want nil", sw)
	}
	if sw := parseApplications([]byte(`{"SPApplicationsDataType":[]}`)); len(sw) != 0 {
		t.Errorf("parseApplications(пусто) = %+v, want пусто", sw)
	}
}

func TestMacVendor(t *testing.T) {
	cases := []struct {
		name     string
		signedBy []string
		want     string
	}{
		{"developer id", []string{"Developer ID Application: Anthropic PBC (Q6L2SF6YDW)", "Developer ID Certification Authority"}, "Anthropic PBC"},
		{"developer id с запятой в имени", []string{"Developer ID Application: Docker Inc (9BNSXJN65R)"}, "Docker Inc"},
		{"бинарь ОС", []string{"Software Signing", "Apple Code Signing Certification Authority"}, "Apple Inc."},
		// Mac App Store перевыпускает подпись — вендора не знаем, Apple не подставляем.
		{"mac app store", []string{"Apple Mac OS Application Signing"}, ""},
		{"подписи нет", nil, ""},
		{"пустой leaf", []string{""}, ""},
		// Разбирается только leaf: УЦ выше по цепочке одинаков у всех вендоров.
		{"developer id не в leaf", []string{"Apple Mac OS Application Signing", "Developer ID Application: Google LLC (EQHXZ8M8AV)"}, ""},
		// Персональный сертификат разработчика — не издатель продукта.
		{"apple development", []string{"Apple Development: Ivan Ivanov (ABCDE12345)"}, ""},
		{"team id не 10 символов", []string{"Developer ID Application: Fake LLC (SHORT)"}, ""},
	}
	for _, c := range cases {
		if got := macVendor(c.signedBy); got != c.want {
			t.Errorf("%s: macVendor(%v) = %q, want %q", c.name, c.signedBy, got, c.want)
		}
	}
}

func TestMacArchByKind(t *testing.T) {
	cases := []struct{ kind, want string }{
		{"arch_arm_i64", "universal"},
		{"arch_arm", "arm64"},
		{"arch_i64", "x86_64"},
		{"arch_i32", "i386"},
		// Тип бандла, а не архитектура → "" («неизвестно»), а не догадка.
		{"arch_web", ""},
		{"arch_ios", ""},
		{"arch_other", ""},
		{"", ""},
		{"arch_будущее", ""},
	}
	for _, c := range cases {
		if got := macArchByKind[c.kind]; got != c.want {
			t.Errorf("macArchByKind[%q] = %q, want %q", c.kind, got, c.want)
		}
	}
}

// TestMacUninstallMethodAndScope — граница fail-safe: где агент реально снимет ПО
// и чей это профиль.
func TestMacUninstallMethodAndScope(t *testing.T) {
	cases := []struct {
		path       string
		wantMethod UninstallMethod
		wantScope  string
	}{
		{"/Applications/Karing.app", UninstallMacAppBundle, ScopeMachine},
		{"/Applications/Mail+ for Gmail.app", UninstallMacAppBundle, ScopeMachine},
		{"/Users/testuser/Applications/iTerm.app", UninstallMacAppBundle, ScopeUser},
		// Ровно один уровень вложенности: пакет с подбандлами снимается целиком.
		{"/Applications/Suite/Helper.app", UninstallNone, ScopeMachine},
		{"/Users/testuser/Applications/Sub/Helper.app", UninstallNone, ScopeUser},
		// SIP: rm вернёт EPERM даже root'у.
		{"/System/Applications/Mail.app", UninstallNone, ScopeMachine},
		{"/System/Library/CoreServices/Finder.app", UninstallNone, ScopeMachine},
		{"/Library/Apple/System/Library/CoreServices/MRT.app", UninstallNone, ScopeMachine},
		{"/usr/local/opt/Tool.app", UninstallNone, ScopeMachine},
		// Часть чужой установки, а не самостоятельный продукт.
		{"/Library/Application Support/WorkspaceONE/Deem/deem/LegacyDeem.app", UninstallNone, ScopeMachine},
		{"/Users/testuser/Downloads/Throne/Throne.app", UninstallNone, ScopeUser},
		// Не бандл вовсе.
		{"/Users/testuser/Library/HTTPStorages/com.apple.ctcategories.service", UninstallNone, ScopeUser},
		{"/Applications/.app", UninstallNone, ScopeMachine},
		{"/Applications", UninstallNone, ScopeMachine},
		{"Relative.app", UninstallNone, ScopeMachine},
		{"", UninstallNone, ScopeMachine},
		// Пустой сегмент пользователя (/Users//Applications) — не профиль.
		{"/Users//Applications/X.app", UninstallNone, ScopeUser},
	}
	for _, c := range cases {
		if got := macUninstallMethod(c.path); got != c.wantMethod {
			t.Errorf("macUninstallMethod(%q) = %q, want %q", c.path, got, c.wantMethod)
		}
		if got := macScope(c.path); got != c.wantScope {
			t.Errorf("macScope(%q) = %q, want %q", c.path, got, c.wantScope)
		}
	}
}

// Живые пробники: на маке разработчика должны как минимум не падать и давать
// значения из контракта ("enabled"/"disabled"/"" и т.п.).
func TestLiveProbesContract(t *testing.T) {
	if v := diskEncryption(); v != "enabled" && v != "disabled" && v != "" {
		t.Errorf("diskEncryption = %q — вне контракта enabled/disabled/пусто", v)
	}
	if v := domainJoined(); v != "false" {
		t.Errorf("domainJoined = %q, want заведомое false на macOS", v)
	}
	if bootTime() <= 0 {
		t.Error("bootTime на живой системе должен быть > 0")
	}
	if diskFree() == "" {
		t.Error("diskFree на живой системе не должен быть пустым")
	}
	// Живой контракт формата install_date: если system_profiler отдаёт хоть одну
	// датированную apple-запись, parseInstallHistory обязан извлечь дату. Пустота
	// при непустой истории значит, что формат живой macOS разошёлся со ВСЕМИ
	// installDateLayouts (каждый item ушёл в continue) — именно так os_patch_date
	// молча обнулился бы на всём мак-парке. Проверка «непустой результат — валидная
	// дата» бессмысленна: он по построению выходит из Format("2006-01-02").
	if out, err := exec.Command("system_profiler", "-json", "SPInstallHistoryDataType").Output(); err == nil {
		var hist struct {
			Items []struct {
				InstallDate string `json:"install_date"`
				Source      string `json:"package_source"`
			} `json:"SPInstallHistoryDataType"`
		}
		dated := 0
		if json.Unmarshal(out, &hist) == nil {
			for _, it := range hist.Items {
				if it.Source == "package_source_apple" && it.InstallDate != "" {
					dated++
				}
			}
		}
		if v := parseInstallHistory(out); dated > 0 && v == "" {
			t.Errorf("parseInstallHistory = \"\" при %d датированных apple-записях — формат install_date разошёлся с installDateLayouts", dated)
		}
	}
}

// TestLiveSoftwareStability — страж инварианта стабильности на ЖИВОЙ выдаче: два
// снимка подряд обязаны дать побитово одинаковые записи. Волатильное поле (mtime,
// размер, счётчик) не роняет ни сборку, ни линтер — оно молча возвращает отправку
// инвентаря каждые 5 минут по всему мак-парку, потому что SoftwareItem целиком
// входит в inventory.hashReport. Сравнение по ключу (имя, версия) намеренно
// терпимо к появлению/исчезновению записей между вызовами (обновление в фоне,
// временный каталог установщика) — ловим именно изменение полей у той же записи.
//
// 🔴 Ключ (имя, версия) НЕ ИДЕНТИФИЦИРУЕТ запись, и это не редкость: приложение и его
// вспомогательный агент — разные бандлы с одинаковыми CFBundleName и версией.
// Живой пример: «NTFS for Mac» 17.0.488 существует одновременно как
// /Applications/NTFS for Mac.app и как .../com.paragon-software.ntfs.notification-agent.app.
// Прежняя редакция клала в map по одному представителю на ключ и сравнивала первого из
// одного снимка со вторым из другого — вердикт зависел от порядка выдачи
// system_profiler, то есть тест требовал от системы гарантии, которой она не даёт, и
// падал на исправном сборщике.
//
// Поэтому сравниваются МНОЖЕСТВА записей под ключом целиком: любое изменение любого
// поля любой записи по-прежнему валит тест (инвариант сохранён полностью), а
// перестановка одинаковых по составу записей — нет.
func TestLiveSoftwareStability(t *testing.T) {
	first := installedSoftware()
	if len(first) == 0 {
		t.Skip("system_profiler не вернул приложений — нечего сравнивать")
	}
	byKey := func(list []Software) map[string][]Software {
		m := make(map[string][]Software, len(list))
		for _, s := range list {
			k := s.Name + "\x00" + s.Version
			m[k] = append(m[k], s)
		}
		for k := range m {
			// Порядок выдачи system_profiler не является частью контракта — сравниваем
			// как множества, а не как последовательности.
			sort.Slice(m[k], func(i, j int) bool { return m[k][i].InstallLocation < m[k][j].InstallLocation })
		}
		return m
	}

	a, b := byKey(first), byKey(installedSoftware())
	for k, want := range a {
		got, ok := b[k]
		// Разное число записей под ключом — это появление/исчезновение, которое тест
		// терпит намеренно (фоновое обновление, временный каталог установщика).
		if !ok || len(got) != len(want) {
			continue
		}
		for i := range want {
			if want[i] != got[i] {
				t.Errorf("запись %q нестабильна между снимками:\n первый %+v\n второй %+v",
					want[i].Name, want[i], got[i])
			}
		}
	}
}

// TestLiveSoftwareContract — живые значения новых полей не выходят за контракт, и
// метод снятия действительно кому-то достаётся: если Apple переедет из
// /Applications или изменит формат path, whitelist перестанет совпадать, кнопка
// «удалить» тихо исчезнет со всех записей — без единой ошибки в логах.
func TestLiveSoftwareContract(t *testing.T) {
	sw := installedSoftware()
	if len(sw) == 0 {
		t.Skip("system_profiler не вернул приложений")
	}
	allowedArch := map[string]bool{"": true, "universal": true, "arm64": true, "x86_64": true, "i386": true}
	removable, inApplications, noPath := 0, 0, 0
	for _, s := range sw {
		if strings.HasPrefix(s.InstallLocation, "/Applications/") {
			inApplications++
		}
		if !allowedArch[s.Arch] {
			t.Errorf("%q: arch = %q вне контракта", s.Name, s.Arch)
		}
		if s.Scope != ScopeMachine && s.Scope != ScopeUser {
			t.Errorf("%q: scope = %q вне контракта", s.Name, s.Scope)
		}
		switch s.UninstallMethod {
		case UninstallNone:
		case UninstallMacAppBundle:
			removable++
			// Метод обязан подразумевать реально сносимый бандл.
			if !isRemovableAppBundle(s.InstallLocation) {
				t.Errorf("%q: метод %q при пути %q", s.Name, s.UninstallMethod, s.InstallLocation)
			}
		default:
			t.Errorf("%q: метод %q не применим на macOS", s.Name, s.UninstallMethod)
		}
		if s.InstallLocation == "" {
			noPath++
		}
	}
	// Границу отказа держим на РЕАЛЬНОЙ поломке — переименованном поле JSON (тогда
	// пусто у всех), а не на одной нетипичной записи: живьём path заполнен у 100%,
	// но ручаться за это на каждой версии macOS нельзя, и падение из-за одного
	// приложения было бы ложной тревогой.
	if noPath == len(sw) {
		t.Errorf("путь пуст у ВСЕХ %d записей — поле path в выдаче system_profiler переименовано", len(sw))
	}
	// Про метод снятия то же: ругаемся, только если кандидаты в /Applications ЕСТЬ,
	// а метод не достался никому (значит whitelist разошёлся с живыми путями). На
	// машине без сторонних приложений (чистая тест-VM) проверять нечего.
	if removable == 0 && inApplications > 0 {
		t.Errorf("в /Applications %d записей, но ни одной с методом снятия — whitelist каталогов разошёлся с живыми путями", inApplications)
	}
}
