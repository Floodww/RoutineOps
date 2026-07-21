//go:build windows

package collector

import (
	"os"
	"os/exec"
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

// uninstallPaths — ветки реестра со списком установленного ПО: 64-битная и
// 32-битная (Wow6432Node). Это разные физические ветки, не дубли друг друга.
var uninstallPaths = []string{
	`Software\Microsoft\Windows\CurrentVersion\Uninstall`,
	`Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// installedSoftware читает ветки реестра Uninstall (64/32-бит) НАТИВНО через
// Windows-реестр. Раньше шло через PowerShell + ConvertTo-Json, но на полевых
// данных DisplayName с кириллицей/неразрывными пробелами приходил битым (ромбики
// U+FFFD из-за кодовых страниц консоли). Реестр отдаёт строки в UTF-16, Go
// конвертирует их в UTF-8 сам — класс бага с кодировкой исчезает, заодно нет
// сабпроцесса. Достаточно DisplayName + DisplayVersion.
func installedSoftware() []Software {
	var sw []Software
	for _, base := range uninstallPaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
		if err != nil {
			continue // ветки может не быть (например, Wow6432Node на 32-битной ОС)
		}
		names, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, name := range names {
			sub, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			display, _, err := sub.GetStringValue("DisplayName")
			if err != nil || display == "" {
				sub.Close()
				continue // записи без DisplayName (обновления, системные компоненты) пропускаем
			}
			version, _, _ := sub.GetStringValue("DisplayVersion")
			sub.Close()
			sw = append(sw, Software{Name: display, Version: version})
		}
	}
	return sw
}
