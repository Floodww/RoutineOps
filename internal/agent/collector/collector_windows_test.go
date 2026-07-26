//go:build windows

package collector

import "testing"

func TestParseBool3(t *testing.T) {
	cases := []struct{ in, want string }{
		{"True\r\n", "true"},
		{"False", "false"},
		{" true ", "true"},
		{"", ""},
		{"Access denied", ""}, // текст ошибки — «не знаю», не выдуманный false
	}
	for _, c := range cases {
		if got := parseBool3(c.in); got != c.want {
			t.Errorf("parseBool3(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Живой реестр в тестах не трогаем: проверяются чистые решения над УЖЕ
// прочитанными значениями ключа (их и надо защитить от регрессий).

func TestSkipEntry(t *testing.T) {
	cases := []struct {
		name  string
		entry uninstallEntry
		want  bool
	}{
		{"обычный продукт", uninstallEntry{displayName: "7-Zip 23.01"}, false},
		{"без DisplayName", uninstallEntry{keyName: "{orphan}"}, true},
		{"системный компонент", uninstallEntry{displayName: "VC++ Runtime", systemComponent: 1}, true},
		// SystemComponent=0 пишут явно — это не признак служебности.
		{"SystemComponent=0", uninstallEntry{displayName: "Notepad++", systemComponent: 0}, false},
		{"обновление продукта", uninstallEntry{displayName: "Обновление для Office", parentKeyName: "Office16"}, true},
		{"продукт с тихим удалением остаётся", uninstallEntry{displayName: "Zoom", quietUninstallString: `"C:\z.exe" /uninstall /silent`}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := skipEntry(c.entry); got != c.want {
				t.Errorf("skipEntry(%+v) = %v, want %v", c.entry, got, c.want)
			}
		})
	}
}

func TestUninstallMethodFor(t *testing.T) {
	const productCode = "{23170F69-40C1-2702-2301-000001000000}"
	cases := []struct {
		name  string
		entry uninstallEntry
		want  UninstallMethod
	}{
		{
			"MSI по флагу WindowsInstaller",
			uninstallEntry{keyName: productCode, scope: ScopeMachine, windowsInstaller: 1},
			UninstallMSI,
		},
		{
			"MSI по msiexec в UninstallString",
			uninstallEntry{keyName: productCode, scope: ScopeMachine, uninstallString: `MsiExec.exe /X` + productCode},
			UninstallMSI,
		},
		{
			// InstallShield/Wise тоже занимают {GUID}-ключи, но msiexec /x на них
			// вернёт 1605 — метод давать нельзя.
			"GUID-ключ без признаков MSI",
			uninstallEntry{keyName: productCode, scope: ScopeMachine, uninstallString: `C:\Program Files\App\uninst.exe`},
			UninstallNone,
		},
		{
			// Помечено как MSI, но адресовать msiexec нечем — падаем в фолбэк.
			"WindowsInstaller=1 без ProductCode в имени ключа",
			uninstallEntry{keyName: "SomeApp", scope: ScopeMachine, windowsInstaller: 1},
			UninstallNone,
		},
		{
			"WindowsInstaller=1 без ProductCode, но с тихой строкой",
			uninstallEntry{keyName: "SomeApp", scope: ScopeMachine, windowsInstaller: 1, quietUninstallString: `"C:\a.exe" /S`},
			UninstallWindowsQuiet,
		},
		{
			"тихая строка от вендора",
			uninstallEntry{keyName: "Notepad++", scope: ScopeMachine, quietUninstallString: `"C:\np++\uninstall.exe" /S`},
			UninstallWindowsQuiet,
		},
		{
			// Главный fail-safe: интерактивный визард в session 0 повиснет невидимо.
			"только интерактивный UninstallString",
			uninstallEntry{keyName: "LegacyApp", scope: ScopeMachine, uninstallString: `C:\legacy\setup.exe -remove`},
			UninstallNone,
		},
		{
			"вообще нет команды удаления",
			uninstallEntry{keyName: "Ghost", scope: ScopeMachine},
			UninstallNone,
		},
		{
			// Из-под LocalSystem чужую per-user установку не снять — метода нет
			// даже у MSI и даже при объявленном тихом режиме.
			"per-user MSI",
			uninstallEntry{keyName: productCode, scope: ScopeUser, windowsInstaller: 1},
			UninstallNone,
		},
		{
			"per-user с тихой строкой",
			uninstallEntry{keyName: "Chrome", scope: ScopeUser, quietUninstallString: `"C:\Users\u\chrome\setup.exe" --uninstall --force-uninstall`},
			UninstallNone,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := uninstallMethodFor(c.entry); got != c.want {
				t.Errorf("uninstallMethodFor(%+v) = %q, want %q", c.entry, got, c.want)
			}
		})
	}
}

func TestIsProductCode(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"{23170F69-40C1-2702-2301-000001000000}", true},
		{"{23170f69-40c1-2702-2301-000001000000}", true}, // нижний регистр легален
		{"", false},
		{"7-Zip", false},
		{"23170F69-40C1-2702-2301-000001000000", false},    // без скобок msiexec не примет
		{"{23170F69-40C1-2702-2301-00000100000}", false},   // короче на символ
		{"{23170F69-40C1-2702-2301-0000010000000}", false}, // длиннее на символ
		{"{23170F69+40C1-2702-2301-000001000000}", false},  // дефис не на месте
		{"{23170G69-40C1-2702-2301-000001000000}", false},  // не hex
		{"{Microsoft Visual Studio Community 2022 - ru}", false},
	}
	for _, c := range cases {
		if got := isProductCode(c.in); got != c.want {
			t.Errorf("isProductCode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestArchForBranch(t *testing.T) {
	cases := []struct {
		name   string
		wow    bool
		goarch string
		want   string
	}{
		{"x64: родная ветка", false, "amd64", "x86_64"},
		{"x64: Wow6432Node", true, "amd64", "i386"},
		// ARM-Windows: родная ветка мешает arm64 и эмулируемый x64, WOW — x86 и
		// ARM32; "" честнее уверенно-неверного значения.
		{"arm64: родная ветка", false, "arm64", ""},
		{"arm64: Wow6432Node", true, "arm64", ""},
		{"32-битный агент: ветка не признак из-за WOW-редиректа", false, "386", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := archForBranch(c.wow, c.goarch); got != c.want {
				t.Errorf("archForBranch(%v, %q) = %q, want %q", c.wow, c.goarch, got, c.want)
			}
		})
	}
}

func TestFilterUserHives(t *testing.T) {
	in := []string{
		"S-1-5-21-1-1-1-1002_Classes",
		".DEFAULT",
		"S-1-5-21-1-1-1-1002",
		"S-1-5-18",
		"S-1-5-19_Classes",
	}
	want := []string{"S-1-5-18", "S-1-5-21-1-1-1-1002"} // отсортировано, без служебных
	got := filterUserHives(in)
	if len(got) != len(want) {
		t.Fatalf("filterUserHives(%v) = %v, want %v", in, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("filterUserHives(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestSoftwareFromEntry(t *testing.T) {
	const productCode = "{23170F69-40C1-2702-2301-000001000000}"
	cases := []struct {
		name   string
		entry  uninstallEntry
		wow    bool
		goarch string
		want   Software
	}{
		{
			name: "машинный MSI из 64-битной ветки",
			entry: uninstallEntry{
				keyName:          productCode,
				displayName:      "7-Zip 23.01 (x64)",
				displayVersion:   "23.01",
				publisher:        "Igor Pavlov",
				installLocation:  `C:\Program Files\7-Zip\`,
				uninstallString:  `MsiExec.exe /X` + productCode,
				windowsInstaller: 1,
				scope:            ScopeMachine,
			},
			goarch: "amd64",
			want: Software{
				Name:            "7-Zip 23.01 (x64)",
				Version:         "23.01",
				Vendor:          "Igor Pavlov",
				InstallLocation: `C:\Program Files\7-Zip\`,
				Arch:            "x86_64",
				UninstallID:     productCode,
				UninstallMethod: UninstallMSI,
				Scope:           ScopeMachine,
			},
		},
		{
			name: "per-user установка из профиля: видна, но снять нечем",
			entry: uninstallEntry{
				keyName:              "Google Chrome",
				displayName:          "Google Chrome",
				displayVersion:       "126.0.6478.127",
				publisher:            "Google LLC",
				installLocation:      `C:\Users\ivan\AppData\Local\Google\Chrome\Application`,
				quietUninstallString: `"C:\Users\ivan\...\setup.exe" --uninstall --force-uninstall`,
				scope:                ScopeUser,
			},
			wow:    true,
			goarch: "amd64",
			want: Software{
				Name:            "Google Chrome",
				Version:         "126.0.6478.127",
				Vendor:          "Google LLC",
				InstallLocation: `C:\Users\ivan\AppData\Local\Google\Chrome\Application`,
				Arch:            "i386",
				UninstallID:     "Google Chrome",
				UninstallMethod: UninstallNone,
				Scope:           ScopeUser,
			},
		},
		{
			name: "пустые значения остаются пустыми, а не выдуманными",
			entry: uninstallEntry{
				keyName:     "MinimalApp",
				displayName: "MinimalApp",
				scope:       ScopeMachine,
			},
			goarch: "arm64",
			want: Software{
				Name:            "MinimalApp",
				UninstallID:     "MinimalApp",
				UninstallMethod: UninstallNone,
				Scope:           ScopeMachine,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := softwareFromEntry(c.entry, c.wow, c.goarch); got != c.want {
				t.Errorf("softwareFromEntry() = %+v, want %+v", got, c.want)
			}
		})
	}
}
