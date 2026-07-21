//go:build darwin

package collector

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func osVersion() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func cpuModel() string {
	out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func ramMegabytes() int64 {
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return 0
	}
	b, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0
	}
	return b / (1024 * 1024)
}

func diskTotal() string {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return ""
	}
	return humanBytes(st.Blocks * uint64(st.Bsize))
}

func serialNumber() string {
	out, err := exec.Command("ioreg", "-l").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformSerialNumber") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				s := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				if isPlaceholderSerial(s) {
					return ""
				}
				return s
			}
		}
	}
	return ""
}

// diskEncryption — статус FileVault системного тома. Только read-only `fdesetup
// status`: пробник живёт во Free-сборке и НЕ имеет отношения к enterprise-пакету
// internal/agent/filevault (secure token / recovery-операции) — не импортирует
// его и не тянет ни одной secret-операции.
func diskEncryption() string {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return ""
	}
	return parseFileVaultStatus(string(out))
}

// parseFileVaultStatus нормализует вывод fdesetup status. «Off, but Deferred
// enablement…» содержит "FileVault is Off" и честно даёт "disabled": шифрование
// сейчас не действует, что бы ни было запланировано.
func parseFileVaultStatus(out string) string {
	s := strings.ToLower(out)
	switch {
	case strings.Contains(s, "filevault is on"):
		return "enabled"
	case strings.Contains(s, "filevault is off"):
		return "disabled"
	}
	return ""
}

// osPatchDate — дата последнего установленного Apple-обновления: максимум
// install_date по записям истории установок с package_source_apple. Сюда
// попадают и большие апдейты macOS, и security-контент (XProtect/MRT) — вместе
// они отвечают на вопрос «когда машина последний раз получала обновления Apple».
// Сторонние пакеты (package_source_other) не считаются обновлением ОС.
func osPatchDate() string {
	out, err := exec.Command("system_profiler", "-json", "SPInstallHistoryDataType").Output()
	if err != nil {
		return ""
	}
	return parseInstallHistory(out)
}

func parseInstallHistory(data []byte) string {
	var hist struct {
		Items []struct {
			InstallDate string `json:"install_date"`
			Source      string `json:"package_source"`
		} `json:"SPInstallHistoryDataType"`
	}
	if err := json.Unmarshal(data, &hist); err != nil {
		return ""
	}
	var latest time.Time
	for _, it := range hist.Items {
		if it.Source != "package_source_apple" {
			continue
		}
		t, err := parseInstallDate(it.InstallDate)
		if err != nil {
			continue
		}
		if t.After(latest) {
			latest = t
		}
	}
	if latest.IsZero() {
		return ""
	}
	return latest.UTC().Format("2006-01-02")
}

// installDateLayouts — форматы install_date у system_profiler: актуальная macOS
// отдаёт строгий RFC3339 ("2026-03-02T19:42:00Z", проверено живьём на 26.3);
// запасной вариант с пробелом ("2026-06-05 17:59:24 +0000") — формат дат plist
// на случай старых версий. Без запасного layout смена формата молча обнулила бы
// os_patch_date на всём мак-парке: каждый item уходил бы в continue.
var installDateLayouts = []string{time.RFC3339, "2006-01-02 15:04:05 -0700"}

func parseInstallDate(s string) (time.Time, error) {
	var err error
	for _, layout := range installDateLayouts {
		var t time.Time
		if t, err = time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, err
}

var bootSecRe = regexp.MustCompile(`sec = (\d+)`)

// bootTime: `sysctl -n kern.boottime` → "{ sec = 1752834000, usec = … } …".
// Абсолютное время загрузки стабильно между снимками (в отличие от uptime).
func bootTime() int64 {
	out, err := exec.Command("sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return 0
	}
	return parseBootTime(string(out))
}

func parseBootTime(out string) int64 {
	m := bootSecRe.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	sec, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0
	}
	return sec
}

func diskFree() string {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return ""
	}
	return humanBytesBucketed(st.Bavail * uint64(st.Bsize))
}

// domainJoined — заведомое "false": в нашей модели мак в AD-домен не вводится
// (контракт хендоффа); TPM/SecureBoot — Windows-специфика, не собираются.
func domainJoined() string      { return "false" }
func tpmPresent() string        { return "" }
func secureBootEnabled() string { return "" }

// installedSoftware читает список приложений через system_profiler (один процесс,
// структурированный JSON). Может занять пару секунд — инвентаризация редкая.
func installedSoftware() []Software {
	out, err := exec.Command("system_profiler", "-json", "SPApplicationsDataType").Output()
	if err != nil {
		return nil
	}
	var data struct {
		Apps []struct {
			Name    string `json:"_name"`
			Version string `json:"version"`
		} `json:"SPApplicationsDataType"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil
	}
	sw := make([]Software, 0, len(data.Apps))
	for _, a := range data.Apps {
		if a.Name == "" {
			continue
		}
		sw = append(sw, Software{Name: a.Name, Version: a.Version})
	}
	return sw
}
