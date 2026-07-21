//go:build darwin

package collector

import (
	"encoding/json"
	"os/exec"
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
