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
	return parseApplications(out)
}

// spApplication — подмножество полей записи SPApplicationsDataType, которое мы
// действительно используем. Живьём (macOS 26.3, 342 записи) непусты: path и
// arch_kind — 100%, version — 99%, signed_by — 97%, obtained_from — 100%.
//
// СОЗНАТЕЛЬНО НЕ БЕРЁМ lastModified (тоже 100%): это mtime бандла, он меняется от
// любого touch'а внутри пакета и в паре с ежечасным самообновлением апдейтеров
// вернул бы отправку инвентаря по всему мак-парку — SoftwareItem целиком входит в
// хэш снимка (inventory.hashReport), см. инвариант стабильности у типа Software.
// obtained_from (apple / mac_app_store / identified_developer / unknown) — это
// КАНАЛ доставки, а не издатель, поэтому в Vendor он не годится.
type spApplication struct {
	Name     string   `json:"_name"`
	Version  string   `json:"version"`
	Path     string   `json:"path"`
	ArchKind string   `json:"arch_kind"`
	SignedBy []string `json:"signed_by"`
}

// parseApplications — чистый разбор выдачи `system_profiler -json
// SPApplicationsDataType`, вынесен из installedSoftware, чтобы решения о вендоре,
// архитектуре, способе снятия и scope проверялись табличными тестами на реальном
// фрагменте выдачи, а не живым опросом ОС.
func parseApplications(data []byte) []Software {
	var payload struct {
		Apps []spApplication `json:"SPApplicationsDataType"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	sw := make([]Software, 0, len(payload.Apps))
	for _, a := range payload.Apps {
		if a.Name == "" {
			continue
		}
		sw = append(sw, Software{
			Name:            a.Name,
			Version:         a.Version,
			Vendor:          macVendor(a.SignedBy),
			InstallLocation: a.Path,
			Arch:            macArchByKind[a.ArchKind],
			// UninstallID (bundle identifier) system_profiler не отдаёт вовсе, а
			// добывать его отдельно — это `defaults read`/`mdls` на каждую запись,
			// то есть сотни процессов на снимок при 342 приложениях. Оставляем
			// пустым: цель снятия на macOS однозначно задаётся InstallLocation.
			UninstallMethod: macUninstallMethod(a.Path),
			Scope:           macScope(a.Path),
		})
	}
	return sw
}

// developerIDRe вытаскивает издателя из leaf-сертификата подписи: "Developer ID
// Application: Google LLC (EQHXZ8M8AV)" → "Google LLC". Team ID в скобках в
// вендора не тащим — он не нужен ни для CPE/purl, ни для UI, а различал бы
// формально одного и того же вендора.
var developerIDRe = regexp.MustCompile(`^Developer ID Application:\s*(.+?)\s*\([0-9A-Z]{10}\)$`)

// appleSoftwareSigningLeaf — leaf-сертификат, которым Apple подписывает бинарники
// самой ОС (299 из 342 записей живьём). Он выдаётся только Apple, поэтому
// отображение в издателя однозначно.
const appleSoftwareSigningLeaf = "Software Signing"

// macVendor определяет издателя по цепочке подписи: она берётся из самого бандла
// и стабильна, пока приложение не переподписано (в отличие от чего-либо
// вычисляемого на лету). Разбирается ТОЛЬКО leaf (signed_by[0]) — выше по цепочке
// всегда стоят УЦ Apple, и они одинаковы у всех вендоров.
//
// Для приложений из Mac App Store leaf — "Apple Mac OS Application Signing"
// (Apple перевыпускает подпись при выдаче), и настоящего разработчика в выдаче
// нет. Возвращаем "" вместо соблазнительного "Apple": подставить Apple вендором
// чужому продукту означает и неверную карточку в UI, и промах CPE при
// CVE-сканировании. Пустое поле честно значит «источник не сказал».
func macVendor(signedBy []string) string {
	if len(signedBy) == 0 {
		return ""
	}
	leaf := strings.TrimSpace(signedBy[0])
	if m := developerIDRe.FindStringSubmatch(leaf); m != nil {
		return m[1]
	}
	if leaf == appleSoftwareSigningLeaf {
		return "Apple Inc."
	}
	return ""
}

// macArchByKind — arch_kind из system_profiler в значения поля Software.Arch.
// Заполняем только то, что означает конкретный набор машинного кода;
// arch_arm_i64 (универсальный бандл, 322 из 342 записей живьём) — это ОБА
// среза сразу, поэтому отдельное "universal", а не произвольный выбор одного из
// них: подставить arm64 значило бы отдавать разный Arch для одного и того же
// пакета на Apple Silicon и на Intel.
//
// Остальные виды (arch_other, arch_web у веб-приложений Safari, arch_ios у
// iOS/Catalyst-бандлов) остаются "" = «неизвестно»: это описание ТИПА бандла, а
// не архитектуры, и выдумывать по нему CPE-архитектуру нельзя. Ключей нет —
// значение "" приходит само из отсутствующего элемента map.
var macArchByKind = map[string]string{
	"arch_arm_i64": "universal",
	"arch_arm":     "arm64",
	"arch_i64":     "x86_64",
	"arch_i32":     "i386",
}

// Каталоги, из которых удаление бандла — это действительно деинсталляция.
const (
	machineAppsDir = "/Applications"
	userAppsSubdir = "Applications" // /Users/<кто-то>/Applications
	userHomePrefix = "/Users/"
)

// macUninstallMethod: fail-safe — метод выставляется только там, где агент
// РЕАЛЬНО снимет ПО тихо и неинтерактивно (rm -rf бандла + pkgutil --forget).
// Всё остальное — UninstallNone, иначе оператору покажут кнопку «удалить»,
// которая ничего не удалит.
func macUninstallMethod(p string) UninstallMethod {
	if isRemovableAppBundle(p) {
		return UninstallMacAppBundle
	}
	return UninstallNone
}

// isRemovableAppBundle: бандл должен лежать НЕПОСРЕДСТВЕННО в /Applications или в
// ~/Applications пользователя. Что отсекается и почему:
//   - /System/..., /usr/..., /Library/Apple/... (XProtect, MRT, MobileDevice) —
//     под SIP: rm вернёт EPERM даже root'у, снять их нечем;
//   - вложенные бандлы (.../Library/Application Support/<продукт>/Helper.app,
//     .../GoogleUpdater/<версия>/GoogleUpdater.app, шаблоны Script Editor) — это
//     ЧАСТИ чужой установки: удаление такого бандла по отдельности сломает
//     родительский продукт, а не деинсталлирует его;
//   - .app в произвольных каталогах пользователя (~/Downloads/...) — не установка,
//     а скачанный архив; «удаление ПО» там означало бы чистку чужих файлов.
//
// Проверяется именно прямое вложение (ровно один уровень), поэтому
// /Applications/<Пакет>/Sub.app тоже отсекается — там снимать надо каталог
// пакета, а не отдельный бандл.
func isRemovableAppBundle(p string) bool {
	slash := strings.LastIndex(p, "/")
	if slash < 0 {
		return false
	}
	dir, bundle := p[:slash], p[slash+1:]
	if bundle == ".app" || !strings.HasSuffix(bundle, ".app") {
		return false
	}
	if dir == machineAppsDir {
		return true
	}
	rest, ok := strings.CutPrefix(dir, userHomePrefix)
	if !ok {
		return false
	}
	user, tail, _ := strings.Cut(rest, "/")
	return user != "" && tail == userAppsSubdir
}

// macScope: всё под /Users — установка в профиль (ScopeUser), остальное машинное.
// Агент работает под root и технически удалит и per-user бандл, поэтому метод
// снятия для ~/Applications мы выставляем — но scope=user обязан доехать честно:
// (1) оператор должен видеть, что действие затронет чужой профиль, а не машину;
// (2) установка в профиль — типовой обход политики запрещённого ПО, её нельзя
// показывать как машинную; (3) dedupeSoftware по этому полю выбирает машинную
// запись вместо per-user, когда один продукт стоит и там, и там.
func macScope(p string) string {
	if strings.HasPrefix(p, userHomePrefix) {
		return ScopeUser
	}
	return ScopeMachine
}
