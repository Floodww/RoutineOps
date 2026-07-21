//go:build linux

package collector

import (
	"bufio"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Linux — полноценная целевая платформа наравне с Windows/macOS.
// Всё железо читается из /proc и /sys, ПО — у пакетного менеджера: без cgo,
// а root нужен только для DMI-серийника (и там есть фолбэк).

func osVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	if m := regexp.MustCompile(`(?m)^PRETTY_NAME="?([^"\n]+)"?`).FindStringSubmatch(string(data)); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func cpuModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return runtime.GOARCH
	}
	return parseCPUModel(string(data)) // общий парсер в collector_procfs.go
}

func ramMegabytes() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "MemTotal:") {
			fields := strings.Fields(sc.Text()) // MemTotal:  16384256 kB
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

func diskTotal() string {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return ""
	}
	return humanBytes(st.Blocks * uint64(st.Bsize))
}

// diskEncryption — зашифрован ли корневой том: в цепочке блок-устройств под "/"
// (lsblk --inverse) есть слой TYPE=crypt (LUKS/dm-crypt). findmnt даёт источник
// корня; у btrfs он приходит с суффиксом subvolume ("/dev/sda2[/@]").
func diskEncryption() string {
	src, err := exec.Command("findmnt", "-no", "SOURCE", "/").Output()
	if err != nil {
		return ""
	}
	dev := strings.TrimSpace(string(src))
	if i := strings.IndexByte(dev, '['); i >= 0 {
		dev = dev[:i]
	}
	if !strings.HasPrefix(dev, "/dev/") {
		return "" // tmpfs/overlay/сетевой корень — не блок-устройство, статус неопределим
	}
	out, err := exec.Command("lsblk", "-rsno", "TYPE", dev).Output()
	if err != nil {
		return ""
	}
	return parseLsblkCrypt(string(out))
}

// parseLsblkCrypt разбирает `lsblk -rsno TYPE <dev>` (цепочка от устройства к
// физическому диску, по типу на строку): crypt в цепочке → enabled.
func parseLsblkCrypt(out string) string {
	seen := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		seen = true
		if t == "crypt" {
			return "enabled"
		}
	}
	if !seen {
		return ""
	}
	return "disabled"
}

// osPatchDate на Linux не собирается: универсального сигнала «когда ОС последний
// раз обновлялась» между dpkg/rpm/pacman/apk нет, а mtime пакетной базы меняет
// любая установка ПО — отдавать его как дату обновления ОС было бы враньём.
// Пустая строка = честное «не знаю» (контракт proto DeviceInfo).
func osPatchDate() string { return "" }

// bootTime: /proc/stat, строка "btime <unix>" — абсолютное время загрузки
// (стабильно между снимками, в отличие от uptime).
func bootTime() int64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return 0
			}
			return sec
		}
	}
	return 0
}

func diskFree() string {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return ""
	}
	return humanBytesBucketed(st.Bavail * uint64(st.Bsize))
}

// domainJoined — заведомое "false" (Linux в AD-домен в нашей модели не вводится,
// контракт хендоффа); TPM/SecureBoot — Windows-специфика, не собираются.
func domainJoined() string      { return "false" }
func tpmPresent() string        { return "" }
func secureBootEnabled() string { return "" }

// dmiSerialPath — серийник, выложенный ядром из SMBIOS. Читается без запуска
// dmidecode (которого на минимальных образах просто нет).
const dmiSerialPath = "/sys/class/dmi/id/product_serial"

// placeholderSerials/isPlaceholderSerial вынесены в кросс-платформенный
// collector.go (тем же фильтром пользуются Windows/darwin serialNumber).

// parseDmidecode берёт значение из вывода `dmidecode -s`: часть сборок печатает в
// stdout баннер («# dmidecode 3.3») перед самим значением, поэтому берём последнюю
// непустую строку без '#'.
func parseDmidecode(out string) string {
	var val string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		val = line
	}
	return val
}

// serialNumber: сначала sysfs (файл, без сабпроцесса), и только потом dmidecode —
// он требует root И отдельного пакета. Плейсхолдеры отбрасываем на обоих путях,
// иначе весь парк устройств приезжает с серийником "Default string".
func serialNumber() string {
	if data, err := os.ReadFile(dmiSerialPath); err == nil {
		if s := strings.TrimSpace(string(data)); !isPlaceholderSerial(s) {
			return s
		}
	}
	out, err := exec.Command("dmidecode", "-s", "system-serial-number").Output()
	if err != nil {
		return ""
	}
	if s := parseDmidecode(string(out)); !isPlaceholderSerial(s) {
		return s
	}
	return ""
}

// pkgProbes — пакетные менеджеры в порядке проверки PATH. Первый найденный
// выигрывает: на гибридных системах (rpm рядом с apk в контейнере) порядок
// фиксирует, чей ответ считается истиной.
var pkgProbes = []struct {
	bin   string
	args  []string
	parse func(string) []Software
}{
	{"dpkg-query", []string{"-W", "-f=${Package}\t${Version}\n"}, parseDpkg},
	{"rpm", []string{"-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"}, parseRpm},
	{"pacman", []string{"-Q"}, parsePacman},
	{"apk", []string{"info", "-v"}, parseApk},
}

// installedSoftware опрашивает пакетный менеджер, который есть в системе.
// Ни одного не нашлось — это не ошибка: инвентаризация ПО просто недоступна
// (Slackware, собранный из исходников образ), железо и ОС всё равно уедут.
func installedSoftware() []Software {
	for _, p := range pkgProbes {
		if _, err := exec.LookPath(p.bin); err != nil {
			continue
		}
		out, err := exec.Command(p.bin, p.args...).Output()
		if err != nil {
			return nil
		}
		return p.parse(string(out))
	}
	return nil
}

// parseTabbed разбирает формат "имя<TAB>версия" — его выдают и dpkg-query, и rpm
// (обоим формат задан флагом, см. pkgProbes). Версия может быть пустой: dpkg
// помнит удалённые, но не вычищенные пакеты.
func parseTabbed(out string) []Software {
	var sw []Software
	for _, line := range strings.Split(out, "\n") {
		name, ver, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t")
		if !ok || name == "" {
			continue
		}
		sw = append(sw, Software{Name: name, Version: ver})
	}
	return sw
}

func parseDpkg(out string) []Software { return parseTabbed(out) }
func parseRpm(out string) []Software  { return parseTabbed(out) }

// parsePacman разбирает `pacman -Q`: "имя версия" через пробел. Имя пакета в Arch
// пробелов не содержит, поэтому Fields безопасен.
func parsePacman(out string) []Software {
	var sw []Software
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		s := Software{Name: f[0]}
		if len(f) >= 2 {
			s.Version = f[1]
		}
		sw = append(sw, s)
	}
	return sw
}

// parseApk разбирает `apk info -v`: одно слитное поле "имя-версия-релиз"
// (zlib-1.2.13-r1). Разделителя нет, а дефис легален и внутри имени
// (py3-setuptools-68.0.0-r0), поэтому отрезаем ДВА последних дефиса и требуем,
// чтобы версия начиналась с цифры. Не сошлось — отдаём одно имя: пустая версия
// честнее нарезанного мусора.
func parseApk(out string) []Software {
	var sw []Software
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, ver := splitApkPackage(line)
		sw = append(sw, Software{Name: name, Version: ver})
	}
	return sw
}

func splitApkPackage(pkg string) (name, version string) {
	rel := strings.LastIndexByte(pkg, '-')
	if rel <= 0 {
		return pkg, ""
	}
	ver := strings.LastIndexByte(pkg[:rel], '-')
	if ver <= 0 {
		return pkg, ""
	}
	if v := pkg[ver+1 : rel]; v == "" || v[0] < '0' || v[0] > '9' {
		return pkg, ""
	}
	return pkg[:ver], pkg[ver+1:]
}
