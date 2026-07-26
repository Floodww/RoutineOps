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

// fieldSep — разделитель колонок в форматах dpkg-query/rpm: ASCII Unit Separator
// (0x1f). Именно он, а не TAB: новые колонки — это метаданные из самого пакета
// (Maintainer/Vendor — свободный текст с пробелами, запятыми и <>), а .deb/.rpm
// собирает кто угодно, и TAB внутри такого поля сдвинул бы колонки, подсунув в
// «архитектуру» произвольную строку из чужого пакета. 0x1f — непечатаемый
// управляющий символ: ни в однострочных полях control-файла dpkg, ни в строковых
// тегах rpm его не бывает, а сами утилиты отдают его в вывод байт-в-байт
// (проверено на debian:stable-slim и rockylinux:9). Свободный текст держим
// ПОСЛЕДНЕЙ колонкой: если он всё же принесёт разделитель, поедет только он сам,
// а не ключ удаления.
const fieldSep = "\x1f"

// Раскладка колонок общая для dpkg и rpm — парсер у них один (parseDelimited).
const (
	colName = iota
	colVersion
	colArch
	colUninstallID
	colVendor
)

// dpkgFormat/rpmFormat — ОДИН вызов на всю машину отдаёт сразу все поля инвентаря.
// Добирать вендора/архитектуру отдельным процессом на каждый пакет нельзя: на
// обычной Debian-машине это 2000+ процессов в каждом снимке (снимок — раз в 5 мин).
//
// ${binary:Package} — то имя, которым dpkg РЕАЛЬНО принимает пакет на удаление:
// у пакетов с Multi-Arch: same оно арх-квалифицировано ("libc6:arm64"), а
// `dpkg -r libc6` на системе с двумя архитектурами отвечает "ambiguous package
// name". Древние dpkg (<1.16.2) этого поля не знают, но на неизвестное поле
// dpkg-query подставляет пустую строку и выходит с кодом 0 (проверено), так что
// парсер просто откатится на имя пакета.
//
// У rpm арх-квалификации имени нет — ключ удаления там само %{NAME}, поэтому
// колонка ключа продублирована из имени: раскладка колонок остаётся общей.
// Дата установки/размер в формат НЕ берутся сознательно: SoftwareItem целиком
// входит в хэш инвентаря, и любое дрейфующее поле вернуло бы отправку каждые
// 5 минут по всему парку (см. инвариант у типа Software).
var (
	dpkgFormat = strings.Join([]string{
		"${Package}", "${Version}", "${Architecture}", "${binary:Package}", "${Maintainer}",
	}, fieldSep) + "\n"
	rpmFormat = strings.Join([]string{
		"%{NAME}", "%{VERSION}-%{RELEASE}", "%{ARCH}", "%{NAME}", "%{VENDOR}",
	}, fieldSep) + "\n"
)

// pkgVariant — один способ спросить у менеджера список пакетов. Вариантов больше
// одного там, где нужная нам форма вывода появилась не во всех версиях утилиты
// (apk list — только с apk-tools 2.10): следующий вариант пробуется, если
// предыдущий не запустился, и это по-прежнему процессы «на снимок», а не «на пакет».
type pkgVariant struct {
	args  []string
	parse func(string) []Software
}

// pkgProbes — пакетные менеджеры в порядке проверки PATH. Первый найденный
// выигрывает: на гибридных системах (rpm рядом с apk в контейнере) порядок
// фиксирует, чей ответ считается истиной.
var pkgProbes = []struct {
	bin      string
	variants []pkgVariant
}{
	{"dpkg-query", []pkgVariant{{[]string{"-W", "-f=" + dpkgFormat}, parseDpkg}}},
	{"rpm", []pkgVariant{{[]string{"-qa", "--qf", rpmFormat}, parseRpm}}},
	{"pacman", []pkgVariant{
		{[]string{"-Qi"}, parsePacman},     // единственная форма с архитектурой и мейнтейнером
		{[]string{"-Q"}, parsePacmanShort}, // фолбэк: имя+версия, разбор не зависит от подписей полей
	}},
	{"apk", []pkgVariant{
		{[]string{"list", "-I"}, parseApkList}, // отдаёт ещё и архитектуру
		{[]string{"info", "-v"}, parseApk},     // фолбэк для apk-tools без подкоманды list
	}},
}

// installedSoftware опрашивает пакетный менеджер, который есть в системе.
// Ни одного не нашлось — это не ошибка: инвентаризация ПО просто недоступна
// (Slackware, собранный из исходников образ), железо и ОС всё равно уедут.
func installedSoftware() []Software {
	for _, p := range pkgProbes {
		if _, err := exec.LookPath(p.bin); err != nil {
			continue
		}
		for _, v := range p.variants {
			cmd := exec.Command(p.bin, v.args...)
			// LC_ALL=C: `pacman -Qi` печатает ЛОКАЛИЗОВАННЫЕ подписи полей
			// ("Architecture" → "Архитектура"), и под неанглийской локалью машины
			// разбор молча отдал бы пустые вендора и архитектуру.
			// Форматам dpkg/rpm локаль безразлична, но выравнивать окружение
			// проще для всех, чем помнить исключение.
			cmd.Env = append(os.Environ(), "LC_ALL=C")
			out, err := cmd.Output()
			if err != nil {
				continue
			}
			sw := v.parse(string(out))
			// Утилита ответила, а разобрать не удалось ни одной записи — значит
			// формат разъехался с нашим (переименованная подпись поля в pacman -Qi,
			// другой порядок колонок). Молча отдать пустой список нельзя: сервер
			// прочитает это как «на машине не осталось ПО» и снесёт инвентарь
			// целиком, поэтому пробуем более грубый, но формат-независимый вариант.
			if len(sw) == 0 && strings.TrimSpace(string(out)) != "" {
				continue
			}
			return sw
		}
		// Менеджер есть, но ни один вариант не ответил: к следующему менеджеру не
		// идём — его список на этой системе был бы заведомо неполным.
		return nil
	}
	return nil
}

// pkgFieldPlaceholders — что менеджеры печатают ВМЕСТО пустого значения. rpm на
// незаполненный строковый тег выдаёт литерал "(none)" (так выглядят псевдопакеты
// gpg-pubkey: ARCH и VENDOR у них "(none)" — проверено на rockylinux:9), pacman —
// "None" и "Unknown Packager". В карточке устройства такое значение неотличимо от
// настоящего, поэтому приводим его к пустому «не знаю».
var pkgFieldPlaceholders = map[string]bool{
	"(none)":           true,
	"None":             true,
	"Unknown Packager": true,
}

// normalizePkgField приводит колонку вывода к контракту «пусто = не знаю».
func normalizePkgField(v string) string {
	v = strings.TrimSpace(v)
	if pkgFieldPlaceholders[v] {
		return ""
	}
	return v
}

// parseDelimited разбирает построчный вывод с колонками через fieldSep — его
// выдают и dpkg-query, и rpm (обоим раскладка задана флагом, см. pkgProbes).
// Колонок может прийти меньше, чем ждём (незнакомое поле формата у старой
// утилиты, пустой тег): недостающее остаётся пустым, но запись НЕ выбрасывается —
// имя с версией ценнее, чем пропущенный пакет. Версия тоже бывает пустой: dpkg
// помнит удалённые, но не вычищенные пакеты.
func parseDelimited(out string, method UninstallMethod) []Software {
	var sw []Software
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), fieldSep)
		if len(f) < 2 || f[colName] == "" {
			continue
		}
		s := Software{
			Name:    f[colName],
			Version: f[colVersion],
			// Ключ удаления — ИМЯ ПАКЕТА, а не отображаемое: менеджер принимает
			// на снятие только его. Колонки ещё нет (старая утилита) — имя пакета
			// сработает в подавляющем большинстве случаев.
			UninstallID: f[colName],
			// Метод ставим по фактически сработавшему пробнику: dpkg/rpm снимают
			// пакет одной неинтерактивной командой, интерактивных деинсталляторов
			// в пакетных менеджерах нет — кнопка «удалить» не зависнет.
			UninstallMethod: method,
			// Системный менеджер ставит ПО только машинно; per-user установок
			// (как в ветке HKCU у Windows) у него не существует.
			Scope: ScopeMachine,
		}
		if len(f) > colArch {
			s.Arch = normalizePkgField(f[colArch])
		}
		if len(f) > colUninstallID {
			if id := normalizePkgField(f[colUninstallID]); id != "" {
				s.UninstallID = id
			}
		}
		if len(f) > colVendor {
			s.Vendor = normalizePkgField(f[colVendor])
		}
		sw = append(sw, s)
	}
	return sw
}

func parseDpkg(out string) []Software { return parseDelimited(out, UninstallDpkg) }
func parseRpm(out string) []Software  { return parseDelimited(out, UninstallRPM) }

// pacmanFieldLabels — подписи полей `pacman -Qi`, которые нам нужны. Формата
// вывода вроде dpkg --qf у pacman нет (--print-format работает только для
// операций sync/upgrade, а expac — отдельный пакет, которого может не быть),
// зато -Qi — по-прежнему ОДИН процесс на всю машину. Всё остальное из записи
// игнорируется, и в первую очередь Install Date/Installed Size: они дрейфуют
// без изменения самого ПО и ломали бы дедуп отправки инвентаря.
const (
	pacmanFieldName    = "Name"
	pacmanFieldVersion = "Version"
	pacmanFieldArch    = "Architecture"
	pacmanFieldVendor  = "Packager"
)

// parsePacman разбирает `pacman -Qi`: записи через пустую строку, внутри записи
// "Подпись : значение". Подпись поля всегда начинается с первой колонки, а
// продолжение длинных списков (Depends On, Optional Deps) идёт с отбивкой
// пробелами и само может содержать двоеточие ("bash-completion: for tab
// completion") — поэтому отбитые строки пропускаем, иначе такое продолжение
// притворилось бы полем.
func parsePacman(out string) []Software {
	var sw []Software
	cur := Software{}
	flush := func() {
		if cur.Name != "" {
			cur.UninstallID = cur.Name // `pacman -Rns <имя>` — снятие только по имени пакета
			cur.UninstallMethod = UninstallPacman
			cur.Scope = ScopeMachine
			sw = append(sw, cur)
		}
		cur = Software{}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		label, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(label) {
		case pacmanFieldName:
			cur.Name = strings.TrimSpace(val)
		case pacmanFieldVersion:
			cur.Version = strings.TrimSpace(val)
		case pacmanFieldArch:
			cur.Arch = normalizePkgField(val)
		case pacmanFieldVendor:
			cur.Vendor = normalizePkgField(val)
		}
	}
	flush() // последняя запись замыкающей пустой строкой не отбита
	return sw
}

// parsePacmanShort разбирает `pacman -Q`: "имя версия" через пробел. Имя пакета в
// Arch пробелов не содержит, поэтому Fields безопасен. Это фолбэк-вариант: полей
// сверх имени и версии тут нет, зато разбор не зависит от подписей полей -Qi.
func parsePacmanShort(out string) []Software {
	var sw []Software
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		s := Software{Name: f[0], UninstallID: f[0], UninstallMethod: UninstallPacman, Scope: ScopeMachine}
		if len(f) >= 2 {
			s.Version = f[1]
		}
		sw = append(sw, s)
	}
	return sw
}

// apkSoftware — общая часть записи для обоих вариантов опроса apk (list/info).
func apkSoftware(name, version string) Software {
	return Software{
		Name:            name,
		Version:         version,
		UninstallID:     name, // `apk del <имя>` — только имя пакета
		UninstallMethod: UninstallAPK,
		Scope:           ScopeMachine,
	}
}

// parseApkList разбирает `apk list -I`:
//
//	zlib-1.3.1-r2 x86_64 {zlib} (Zlib) [installed]
//
// Первая колонка — то же слитное "имя-версия-релиз", что и у `apk info -v`
// (splitApkPackage), вторая — архитектура. Мейнтейнера apk в списке не отдаёт:
// он лежит только в `apk info -a`, а это процесс НА КАЖДЫЙ пакет — недопустимо.
func parseApkList(out string) []Software {
	var sw []Software
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		s := apkSoftware(splitApkPackage(f[0]))
		// Вторую колонку берём только если она похожа на арх-тег: origin, лицензия
		// и статус идут в скобках, и если в будущей версии apk порядок колонок
		// поедет, лучше отдать пустую архитектуру, чем "{zlib}" как настоящую.
		if len(f) > 1 && !strings.ContainsAny(f[1][:1], "{([") {
			s.Arch = normalizePkgField(f[1])
		}
		sw = append(sw, s)
	}
	return sw
}

// parseApk разбирает `apk info -v`: одно слитное поле "имя-версия-релиз"
// (zlib-1.2.13-r1). Разделителя нет, а дефис легален и внутри имени
// (py3-setuptools-68.0.0-r0), поэтому отрезаем ДВА последних дефиса и требуем,
// чтобы версия начиналась с цифры. Не сошлось — отдаём одно имя: пустая версия
// честнее нарезанного мусора. Архитектуры и мейнтейнера в этом выводе нет —
// он остался фолбэком для apk-tools без подкоманды list (см. pkgProbes).
func parseApk(out string) []Software {
	var sw []Software
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sw = append(sw, apkSoftware(splitApkPackage(line)))
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
