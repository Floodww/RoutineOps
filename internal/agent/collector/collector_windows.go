//go:build windows

package collector

import (
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// psOut запускает PowerShell-команду и возвращает её stdout (или "" при ошибке).
// [Console]::OutputEncoding принудительно переводится в UTF-8, чтобы Go читал
// байты корректно на системах с кодовой страницей CP1251/CP866.
func psOut(command string) string {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); `+command,
	).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// osVersion возвращает версию ОС чистым UTF-8. Раньше использовался `cmd /c ver`,
// но на локализованной Windows он печатает текст («Версия …») в OEM-кодировке
// (CP866/CP1251) — в UI это превращалось в ромбики. Берём строку через PowerShell
// (psOut форсирует UTF-8), `ver` оставлен лишь запасным путём.
func osVersion() string {
	if v := strings.TrimSpace(psOut(`$o = Get-CimInstance Win32_OperatingSystem; "$($o.Caption) ($($o.Version))"`)); v != "" {
		return v
	}
	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// cpuModel возвращает дружелюбное имя процессора («Intel(R) Core(TM) Ultra 5 …»).
// Раньше первым шёл PROCESSOR_IDENTIFIER, но он даёт лишь «Intel64 Family 6 Model
// … GenuineIntel» (семейство/модель, не маркетинговое имя). Имя лежит в реестре
// (ProcessorNameString) — читаем его нативно; env остаётся последним фолбэком.
func cpuModel() string {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		name, _, gerr := k.GetStringValue("ProcessorNameString")
		k.Close()
		if gerr == nil {
			if name = strings.TrimSpace(name); name != "" {
				return name
			}
		}
	}
	if v := strings.TrimSpace(psOut(`(Get-CimInstance Win32_Processor).Name`)); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("PROCESSOR_IDENTIFIER"))
}

func ramMegabytes() int64 {
	s := strings.TrimSpace(psOut(`(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory`))
	b, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return b / (1024 * 1024)
}

func diskTotal() string {
	// $env:SystemDrive (не хардкод 'C:') — на образах, где система не на C:,
	// хардкод давал пустой diskTotal при непустом diskFree (тот уже брал
	// SystemDrive) — рассогласованные поля инвентаря.
	s := strings.TrimSpace(psOut(`(Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").Size`))
	b, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return ""
	}
	return humanBytes(b)
}

func serialNumber() string {
	// Плейсхолдеры SMBIOS (VM/whitebox: "Default string", "To Be Filled…") — как
	// на Linux — отдаём как "", чтобы sticky-серийник в БД не затирался мусором,
	// одинаковым на десятках машин (isPlaceholderSerial в collector.go).
	s := strings.TrimSpace(psOut("(Get-CimInstance Win32_BIOS).SerialNumber"))
	if isPlaceholderSerial(s) {
		return ""
	}
	return s
}

// diskEncryption — BitLocker системного тома через Win32_EncryptableVolume
// (ProtectionStatus: 0=off, 1=on, 2=unknown). Числовой ответ выбран нарочно:
// вывод manage-bde локализован и парсится ненадёжно. Класс доступен только
// администраторам — служба работает под SYSTEM; интерактивный запуск без прав
// честно отдаёт "" (не знаю).
func diskEncryption() string {
	s := strings.TrimSpace(psOut(`(Get-CimInstance -Namespace root\cimv2\security\microsoftvolumeencryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'").ProtectionStatus`))
	switch s {
	case "1":
		return "enabled"
	case "0":
		return "disabled"
	}
	return ""
}

// osPatchDate — дата последнего установленного обновления ОС (Get-HotFix =
// Win32_QuickFixEngineering: KB/кумулятивные апдейты). ToString с InvariantCulture
// фиксирует не только порядок полей, но и григорианский календарь: без него на
// культуре с другим календарём (ar-SA/умм-аль-кура, th-TH, fa-IR) yyyy дал бы
// хиджру/буддийский год — строка синтаксически валидна, guard time.Parse ниже её
// пропустил бы, и в инвентарь уехала бы уверенно-неверная дата.
func osPatchDate() string {
	s := strings.TrimSpace(psOut(`$h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h) { $h.InstalledOn.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) }`))
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return ""
	}
	return s
}

// bootTime — абсолютное время загрузки из Win32_OperatingSystem.LastBootUpTime.
// Именно абсолютное значение, а не uptime, пересчитанный в момент снимка:
// пересчёт давал бы каждый раз новый boot_time (джиттер ±секунды) и ломал
// delta-подавление инвентаря. Каст DateTime→DateTimeOffset берёт локальный
// офсет системы, ToUnixTimeSeconds конвертирует в UTC-epoch корректно.
func bootTime() int64 {
	s := strings.TrimSpace(psOut(`([DateTimeOffset](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUnixTimeSeconds()`))
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func diskFree() string {
	s := strings.TrimSpace(psOut(`(Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace`))
	b, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return ""
	}
	return humanBytesBucketed(b)
}

// parseBool3 нормализует булев вывод PowerShell в трёхзначную строку
// "true"/"false"/"": false и «не знаю» различаются (см. proto DeviceInfo).
func parseBool3(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true":
		return "true"
	case "false":
		return "false"
	}
	return ""
}

func domainJoined() string {
	return parseBool3(psOut(`(Get-CimInstance Win32_ComputerSystem).PartOfDomain`))
}

// tpmPresent: Get-Tpm требует прав администратора (служба — SYSTEM);
// любая ошибка → "" (не знаю), а не выдуманный false.
func tpmPresent() string {
	return parseBool3(psOut(`try { (Get-Tpm).TpmPresent } catch { '' }`))
}

// secureBootEnabled: Confirm-SecureBootUEFI кидает PlatformNotSupportedException
// на legacy BIOS — это ЗАВЕДОМОЕ отсутствие Secure Boot ("false"), а не «не
// знаю». Остальные ошибки (недостаточно прав) — честное "".
func secureBootEnabled() string {
	return parseBool3(psOut(`try { Confirm-SecureBootUEFI } catch [System.PlatformNotSupportedException] { 'False' } catch { '' }`))
}

// uninstallBranch — ветка реестра со списком установленного ПО. Путь
// относительный: он одинаков и под HKLM (машинные установки), и под кустом
// пользователя в HKEY_USERS (per-user установки). Флаг wow помечает 32-битный
// вид реестра — это ЕДИНСТВЕННЫЙ доступный здесь признак разрядности продукта:
// в значениях ключа Uninstall архитектуры нет вообще.
type uninstallBranch struct {
	path string
	wow  bool
}

// uninstallBranches — 64-битная и 32-битная (Wow6432Node) ветки. Это разные
// физические ветки, не дубли друг друга.
var uninstallBranches = []uninstallBranch{
	{`Software\Microsoft\Windows\CurrentVersion\Uninstall`, false},
	{`Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, true},
}

// uninstallEntry — значения ОДНОГО подключа Uninstall, уже вычитанные из реестра.
// Промежуточное представление введено нарочно: решения «это продукт или шум»
// (skipEntry) и «чем его можно снять» (uninstallMethodFor) становятся чистыми
// функциями и покрываются табличными тестами без живого реестра, которого на
// сборочной машине нет.
//
// Ни одного волатильного значения тут нет намеренно: InstallDate, EstimatedSize,
// времена изменения ключей не читаются вовсе — SoftwareItem входит в хэш
// инвентаря целиком (inventory.hashReport), и любое дрейфующее поле молча
// вернуло бы отправку инвентаря каждые 5 минут по всему парку.
type uninstallEntry struct {
	// keyName — имя подключа. Для MSI это и есть ProductCode вида {GUID}, то
	// есть машинный ключ цели для msiexec; для остальных — произвольная строка,
	// заданная инсталлятором.
	keyName              string
	displayName          string
	displayVersion       string
	publisher            string
	installLocation      string
	uninstallString      string
	quietUninstallString string
	// parentKeyName непуст у записей-обновлений/дочерних компонентов.
	parentKeyName string
	// systemComponent / windowsInstaller — REG_DWORD, но часть инсталляторов
	// пишет их строкой ("1"), поэтому читаются через regDword с фолбэком.
	systemComponent  uint64
	windowsInstaller uint64
	// scope — из какого куста пришла запись (HKLM или профиль пользователя).
	scope string
}

// installedSoftware читает ветки реестра Uninstall НАТИВНО через Windows-реестр.
// Раньше шло через PowerShell + ConvertTo-Json, но на полевых данных DisplayName
// с кириллицей/неразрывными пробелами приходил битым (ромбики U+FFFD из-за
// кодовых страниц консоли). Реестр отдаёт строки в UTF-16, Go конвертирует их в
// UTF-8 сам — класс бага с кодировкой исчезает, заодно нет сабпроцесса.
//
// Читаются ОБА куста: HKLM (машинные установки) и загруженные профили из
// HKEY_USERS. До этого HKLM был единственным источником, и per-user установки
// (Chrome/Zoom/Teams в профиль пользователя) не попадали в инвентарь вообще —
// дыра не только в списке ПО, но и в политике запрещённого ПО: установка в
// профиль обходила детект.
func installedSoftware() []Software {
	sw := readUninstallRoot(registry.LOCAL_MACHINE, "", ScopeMachine)
	for _, sid := range loadedUserHives() {
		sw = append(sw, readUninstallRoot(registry.USERS, sid+`\`, ScopeUser)...)
	}
	return sw
}

// readUninstallRoot проходит обе ветки Uninstall внутри одного куста. prefix —
// путь до куста пользователя ("SID\") либо "" для HKLM.
func readUninstallRoot(root registry.Key, prefix, scope string) []Software {
	var sw []Software
	for _, b := range uninstallBranches {
		sw = append(sw, readUninstallBranch(root, prefix+b.path, b.wow, scope)...)
	}
	return sw
}

// readUninstallBranch вычитывает одну ветку Uninstall в срез Software. wow —
// признак 32-битного вида реестра, нужен только для Arch (см. archForBranch).
func readUninstallBranch(root registry.Key, path string, wow bool, scope string) []Software {
	k, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return nil // ветки может не быть (Wow6432Node на 32-битной ОС, пустой профиль)
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return nil
	}
	// Сортировка — не косметика: один продукт видно в нескольких профилях, а
	// dedupeSoftware (collector.go) оставляет ПЕРВУЮ запись пары (имя, версия).
	// Порядок перечисления подключей реестром не документирован, и если он
	// разойдётся между снимками, победитель дедупа принесёт другой
	// InstallLocation — снимок изменится без изменений на машине, то есть
	// лишняя отправка инвентаря. Сортировка делает выбор детерминированным.
	sort.Strings(names)

	var sw []Software
	for _, name := range names {
		sub, err := registry.OpenKey(root, path+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		e := readUninstallEntry(sub, name, scope)
		sub.Close()
		if skipEntry(e) {
			continue
		}
		sw = append(sw, softwareFromEntry(e, wow, runtime.GOARCH))
	}
	return sw
}

// readUninstallEntry вычитывает интересующие значения подключа. Ошибки чтения
// отдельных значений — норма (у большинства записей половины значений нет), они
// превращаются в пустые строки/нули.
func readUninstallEntry(k registry.Key, keyName, scope string) uninstallEntry {
	return uninstallEntry{
		keyName:              keyName,
		displayName:          regString(k, "DisplayName"),
		displayVersion:       regString(k, "DisplayVersion"),
		publisher:            regString(k, "Publisher"),
		installLocation:      regString(k, "InstallLocation"),
		uninstallString:      regString(k, "UninstallString"),
		quietUninstallString: regString(k, "QuietUninstallString"),
		parentKeyName:        regString(k, "ParentKeyName"),
		systemComponent:      regDword(k, "SystemComponent"),
		windowsInstaller:     regDword(k, "WindowsInstaller"),
		scope:                scope,
	}
}

func regString(k registry.Key, name string) string {
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// regDword читает числовой флаг. Фолбэк на строковое значение обязателен:
// SystemComponent/WindowsInstaller по документации REG_DWORD, но в поле
// встречаются инсталляторы, записавшие REG_SZ "1" — без фолбэка такой
// системный компонент прошёл бы фильтр, а MSI потерял бы метод снятия.
func regDword(k registry.Key, name string) uint64 {
	if v, _, err := k.GetIntegerValue(name); err == nil {
		return v
	}
	if s, _, err := k.GetStringValue(name); err == nil {
		if v, perr := strconv.ParseUint(strings.TrimSpace(s), 10, 64); perr == nil {
			return v
		}
	}
	return 0
}

// loadedUserHives — SID'ы загруженных кустов пользователей (подключи HKEY_USERS).
// Куст загружен, пока пользователь залогинен, поэтому после его выхода per-user
// записи из снимка исчезнут. Это отражение РЕАЛЬНОГО изменения состояния машины
// (логон/логоф), а не дрейф значения: на неизменной машине список стабилен, и
// инвариант хэша инвентаря не нарушается.
func loadedUserHives() []string {
	names, err := registry.USERS.ReadSubKeyNames(-1)
	if err != nil {
		return nil // нет доступа к HKEY_USERS — машинных записей это не лишает
	}
	return filterUserHives(names)
}

// filterUserHives отбрасывает служебные подключи HKEY_USERS: ".DEFAULT" — это
// шаблон профиля для новых пользователей (установленного ПО там нет), а кусты с
// суффиксом "_Classes" — это HKCR-часть профиля (COM-регистрации), ветки
// Uninstall в них нет вовсе, и перечислять их — только лишние OpenKey и шум.
// Результат сортируется: от порядка зависит, чья запись выживет в
// dedupeSoftware, а значит и стабильность снимка (см. readUninstallBranch).
func filterUserHives(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if strings.EqualFold(n, ".DEFAULT") || strings.HasSuffix(n, "_Classes") {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// skipEntry отбраковывает записи, которые не являются продуктами:
//
//   - без DisplayName — служебные и осиротевшие ключи, показывать нечего;
//   - SystemComponent=1 — этот флаг инсталлятор ставит РОВНО для того, чтобы
//     запись не появлялась в «Программах и компонентах» (рантаймы, драйверные
//     пакеты, служебные компоненты). Нормальный продукт его не ставит никогда:
//     он ставится ради обратной цели — быть в списке удаления. То есть фильтр
//     повторяет решение самого вендора, а не наше предположение;
//   - непустой ParentKeyName — запись объявляет себя ДОЧЕРНЕЙ к другому
//     продукту (патч, языковой пакет, обновление). Сам продукт-родитель
//     остаётся в реестре отдельной записью верхнего уровня, поэтому из списка
//     он не исчезает — уходят только его патчи, которые оператору в списке ПО
//     мешают (десятки строк «Обновление для …» на одну программу).
func skipEntry(e uninstallEntry) bool {
	return e.displayName == "" || e.systemComponent == 1 || e.parentKeyName != ""
}

// uninstallMethodFor решает, чем агент РЕАЛЬНО сможет снять это ПО тихо и
// неинтерактивно. Сомнение трактуется как UninstallNone: неверно выставленный
// метод показал бы оператору кнопку «Удалить», которая повиснет на
// интерактивном визарде в session 0 — невидимо, без вывода и без таймаута.
func uninstallMethodFor(e uninstallEntry) UninstallMethod {
	// Per-user установку из-под LocalSystem не снять: деинсталлятор лежит в
	// профиле, пишет в HKCU и часто требует токена того самого пользователя.
	// Показать кнопку здесь означало бы соврать оператору.
	if e.scope == ScopeUser {
		return UninstallNone
	}
	// MSI снимается `msiexec /x {ProductCode} /qn`, а ProductCode — это ИМЯ
	// подключа. Поэтому валидный GUID в имени ключа обязателен: без него
	// команду просто не собрать. Второе условие отсекает наследие
	// InstallShield/Wise — они тоже регистрируются под {GUID}-ключами, но MSI
	// не являются, и msiexec /x на них вернул бы 1605 «product not installed».
	// Признаком настоящего MSI считаем WindowsInstaller=1 либо msiexec в
	// UninstallString (его пишет сам Windows Installer).
	if isProductCode(e.keyName) && (e.windowsInstaller == 1 || mentionsMsiExec(e.uninstallString)) {
		return UninstallMSI
	}
	// Вендор сам объявил тихий режим — ему и доверяем.
	if e.quietUninstallString != "" {
		return UninstallWindowsQuiet
	}
	// Остался только интерактивный UninstallString (или вообще ничего):
	// снимать нечем.
	return UninstallNone
}

// isProductCode проверяет, что имя подключа — это GUID вида
// {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}, то есть пригодно как ProductCode для
// msiexec. Проверка ручная (без внешних зависимостей и без regexp на горячем
// пути перечисления сотен ключей).
func isProductCode(s string) bool {
	const productCodeLen = 38 // 36 символов GUID + две фигурные скобки
	if len(s) != productCodeLen || s[0] != '{' || s[productCodeLen-1] != '}' {
		return false
	}
	body := s[1 : productCodeLen-1]
	for i := 0; i < len(body); i++ {
		switch i {
		case 8, 13, 18, 23:
			if body[i] != '-' {
				return false
			}
		default:
			if !isHexDigit(body[i]) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// mentionsMsiExec — команда удаления ведёт через Windows Installer
// ("MsiExec.exe /X{...}"). Регистр и путь у разных версий разные, поэтому
// сравнение по подстроке в нижнем регистре.
func mentionsMsiExec(uninstallString string) bool {
	return strings.Contains(strings.ToLower(uninstallString), "msiexec")
}

// archForBranch выводит архитектуру продукта из ветки реестра, в которую его
// записал инсталлятор: другого признака в ключе Uninstall нет (честнее было бы
// читать PE-заголовок целевого бинаря, но его путь известен далеко не всегда, а
// разбор файлов на каждом снимке — лишняя работа).
//
// goarch — архитектура агентского бинаря, она же практически архитектура ОС:
//   - amd64: Wow6432Node → i386, обычная ветка → x86_64 (однозначно);
//   - arm64: обе ветки неоднозначны — в родную попадают и arm64-приложения, и
//     эмулируемые x64, в Wow6432Node — и x86, и легаси-ARM32. Отдаём "" («не
//     знаю») вместо уверенно-неверного значения;
//   - 386: 32-битный агент на 64-битной ОС читает реестр через WOW-редирект,
//     поэтому сама ветка перестаёт быть признаком — тоже "".
//
// Значение стабильно между снимками: зависит только от ветки и от архитектуры
// бинаря.
func archForBranch(wow bool, goarch string) string {
	if goarch != "amd64" {
		return ""
	}
	if wow {
		return "i386"
	}
	return "x86_64"
}

// softwareFromEntry собирает запись инвентаря из значений ключа. Вынесено в
// чистую функцию (goarch параметром), чтобы маппинг проверялся тестом без
// реестра.
func softwareFromEntry(e uninstallEntry, wow bool, goarch string) Software {
	return Software{
		Name:            e.displayName,
		Version:         e.displayVersion,
		Vendor:          e.publisher,
		InstallLocation: e.installLocation,
		Arch:            archForBranch(wow, goarch),
		// UninstallID — имя подключа: для MSI это ProductCode, для остальных —
		// адрес записи в реестре. И то и другое пригодно как машинный ключ цели
		// (по DisplayName одноимённые продукты разных вендоров резолвятся в
		// чужую запись) и стабильно, пока продукт не переустановят.
		UninstallID:     e.keyName,
		UninstallMethod: uninstallMethodFor(e),
		Scope:           e.scope,
	}
}
