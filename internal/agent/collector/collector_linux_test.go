//go:build linux

package collector

import (
	"runtime"
	"strings"
	"testing"
)

// sep — тот же разделитель колонок, что агент подставляет в формат dpkg-query/rpm.
// В тестах он живёт под коротким именем, чтобы строки ожиданий читались.
const sep = fieldSep

// pkg — запись, какой её обязан вернуть парсер пакетного менеджера: Scope всегда
// машинный, ключ удаления по умолчанию равен имени пакета, метод — по менеджеру.
func pkg(name, version, arch, vendor string, m UninstallMethod) Software {
	return Software{
		Name: name, Version: version, Arch: arch, Vendor: vendor,
		UninstallID: name, UninstallMethod: m, Scope: ScopeMachine,
	}
}

// dpkg-query и rpm настроены на одну раскладку колонок (имя, версия, арх, ключ
// удаления, вендор), поэтому парсер у них общий.
func TestParseDelimitedPackages(t *testing.T) {
	tests := []struct {
		name  string
		parse func(string) []Software
		out   string
		want  []Software
	}{
		{
			name:  "dpkg: полная строка со всеми колонками",
			parse: parseDpkg,
			out:   "bash" + sep + "5.1-6ubuntu1" + sep + "amd64" + sep + "bash" + sep + "Matthias Klose <doko@debian.org>\n",
			want:  []Software{pkg("bash", "5.1-6ubuntu1", "amd64", "Matthias Klose <doko@debian.org>", UninstallDpkg)},
		},
		{
			// Multi-Arch: same — ${binary:Package} приходит арх-квалифицированным,
			// и снимать пакет надо именно по нему (dpkg -r libc6 = ambiguous).
			name:  "dpkg: арх-квалифицированный ключ удаления вытесняет имя",
			parse: parseDpkg,
			out:   "libc6" + sep + "2.41-12" + sep + "arm64" + sep + "libc6:arm64" + sep + "GNU Libc Maintainers <debian-glibc@lists.debian.org>\n",
			want: []Software{{
				Name: "libc6", Version: "2.41-12", Arch: "arm64",
				Vendor:      "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
				UninstallID: "libc6:arm64", UninstallMethod: UninstallDpkg, Scope: ScopeMachine,
			}},
		},
		{
			// Мейнтейнер — свободный текст: пробелы, запятые, точки, <> внутри
			// значения колонки ничего не сдвигают, разделитель только 0x1f.
			name:  "dpkg: запятые и пробелы в мейнтейнере не рвут колонки",
			parse: parseDpkg,
			out:   "gcc" + sep + "4:12.2" + sep + "amd64" + sep + "gcc" + sep + "Debian GCC Maintainers, Matthias Klose <debian-gcc@lists.debian.org>\n",
			want:  []Software{pkg("gcc", "4:12.2", "amd64", "Debian GCC Maintainers, Matthias Klose <debian-gcc@lists.debian.org>", UninstallDpkg)},
		},
		{
			// Удалённый, но не вычищенный пакет: dpkg помнит имя без версии.
			name:  "dpkg: пустая версия сохраняется",
			parse: parseDpkg,
			out:   "ghost" + sep + sep + "amd64" + sep + "ghost" + sep + "Somebody <s@example.org>\nbash" + sep + "5.1" + sep + "amd64" + sep + "bash" + sep + "Somebody <s@example.org>\n",
			want: []Software{
				pkg("ghost", "", "amd64", "Somebody <s@example.org>", UninstallDpkg),
				pkg("bash", "5.1", "amd64", "Somebody <s@example.org>", UninstallDpkg),
			},
		},
		{
			// Старый dpkg не знает ${binary:Package}: колонки приходят пустыми,
			// запись всё равно нужна, ключ удаления откатывается на имя пакета.
			name:  "dpkg: пустые арх/ключ/вендор → поля пустые, запись остаётся",
			parse: parseDpkg,
			out:   "bash" + sep + "5.1" + sep + sep + sep + "\n",
			want:  []Software{pkg("bash", "5.1", "", "", UninstallDpkg)},
		},
		{
			// Формат старого агента (только имя+версия) — обрезанных колонок
			// парсер не боится: недостающее пусто, пакет не теряется.
			name:  "усечённый вывод из двух колонок",
			parse: parseDpkg,
			out:   "bash" + sep + "5.1\n",
			want:  []Software{pkg("bash", "5.1", "", "", UninstallDpkg)},
		},
		{
			name:  "dpkg: строки без разделителя и пустые пропускаются",
			parse: parseDpkg,
			out:   "\nмусор без разделителя\n" + sep + "версия-без-имени\nbash" + sep + "5.1\n",
			want:  []Software{pkg("bash", "5.1", "", "", UninstallDpkg)},
		},
		{
			name:  "dpkg: CRLF не попадает в последнюю колонку",
			parse: parseDpkg,
			out:   "bash" + sep + "5.1" + sep + "amd64" + sep + "bash" + sep + "Somebody <s@example.org>\r\n",
			want:  []Software{pkg("bash", "5.1", "amd64", "Somebody <s@example.org>", UninstallDpkg)},
		},
		{
			name:  "rpm: имя + version-release + вендор",
			parse: parseRpm,
			out:   "glibc" + sep + "2.34-60.el9" + sep + "x86_64" + sep + "glibc" + sep + "Rocky Enterprise Software Foundation\n",
			want:  []Software{pkg("glibc", "2.34-60.el9", "x86_64", "Rocky Enterprise Software Foundation", UninstallRPM)},
		},
		{
			name:  "rpm: noarch остаётся как есть",
			parse: parseRpm,
			out:   "tzdata" + sep + "2023c-1.el9" + sep + "noarch" + sep + "tzdata" + sep + "Rocky Enterprise Software Foundation\n",
			want:  []Software{pkg("tzdata", "2023c-1.el9", "noarch", "Rocky Enterprise Software Foundation", UninstallRPM)},
		},
		{
			// Псевдопакет ключа: rpm печатает незаполненные теги как "(none)" —
			// это плейсхолдер, а не архитектура/вендор.
			name:  "rpm: (none) у gpg-pubkey → пустые арх и вендор",
			parse: parseRpm,
			out:   "gpg-pubkey" + sep + "350d275d-6279464b" + sep + "(none)" + sep + "gpg-pubkey" + sep + "(none)\n",
			want:  []Software{pkg("gpg-pubkey", "350d275d-6279464b", "", "", UninstallRPM)},
		},
		{
			name:  "пустой вывод → nil",
			parse: parseRpm,
			out:   "",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSoftware(t, tt.parse(tt.out), tt.want)
		})
	}
}

// pacman -Qi: записи через пустую строку, "Подпись : значение" с первой колонки.
func TestParsePacman(t *testing.T) {
	const bash = "Name            : bash\n" +
		"Version         : 5.2.015-1\n" +
		"Description     : The GNU Bourne Again shell\n" +
		"Architecture    : x86_64\n" +
		"Depends On      : readline  libreadline.so=8-64  glibc  ncurses\n" +
		"Optional Deps   : bash-completion: for tab completion\n" +
		"Installed Size  : 9.59 MiB\n" +
		"Packager        : Tobias Powalowski <tpowa@archlinux.org>\n" +
		"Install Date    : Sun Jul 19 00:00:00 2026\n" +
		"Validated By    : Signature\n"

	tests := []struct {
		name string
		out  string
		want []Software
	}{
		{
			name: "полная запись: берём только стабильные поля",
			out:  bash,
			want: []Software{pkg("bash", "5.2.015-1", "x86_64", "Tobias Powalowski <tpowa@archlinux.org>", UninstallPacman)},
		},
		{
			name: "две записи через пустую строку",
			out:  bash + "\n" + "Name            : linux\nVersion         : 6.6.1.arch1-1\nArchitecture    : x86_64\nPackager        : Arch Linux <arch@example.org>\n",
			want: []Software{
				pkg("bash", "5.2.015-1", "x86_64", "Tobias Powalowski <tpowa@archlinux.org>", UninstallPacman),
				pkg("linux", "6.6.1.arch1-1", "x86_64", "Arch Linux <arch@example.org>", UninstallPacman),
			},
		},
		{
			// Отбитое продолжение длинного списка содержит двоеточие и притворилось
			// бы полем, если бы парсер не отбрасывал строки с отступом.
			name: "продолжение списка с отступом не подменяет поля",
			out: "Name            : ncurses\nVersion         : 6.4-3\nArchitecture    : x86_64\n" +
				"Optional Deps   : foo: описание\n                  Packager: подделка\n" +
				"Packager        : Real Packager <real@archlinux.org>\n",
			want: []Software{pkg("ncurses", "6.4-3", "x86_64", "Real Packager <real@archlinux.org>", UninstallPacman)},
		},
		{
			name: "плейсхолдеры pacman → пустые поля",
			out:  "Name            : local-pkg\nVersion         : 1.0-1\nArchitecture    : any\nPackager        : Unknown Packager\nGroups          : None\n",
			want: []Software{pkg("local-pkg", "1.0-1", "any", "", UninstallPacman)},
		},
		{
			name: "запись без версии → только имя",
			out:  "Name            : sirenam\n",
			want: []Software{pkg("sirenam", "", "", "", UninstallPacman)},
		},
		{
			name: "мусор без двоеточия и лишние пустые строки пропускаются",
			out:  "\n\nмусор без двоеточия\nName            : bash\nVersion         : 5.2\n\n\n",
			want: []Software{pkg("bash", "5.2", "", "", UninstallPacman)},
		},
		{"пустой вывод → nil", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSoftware(t, parsePacman(tt.out), tt.want)
		})
	}
}

// Фолбэк `pacman -Q`: полей сверх имени и версии нет, но метод/scope/ключ
// удаления заполнены — иначе после откака на этот вариант ПО стало бы «неснимаемым».
func TestParsePacmanShort(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []Software
	}{
		{
			name: "обычный вывод",
			out:  "bash 5.2.015-1\nlinux 6.6.1.arch1-1\n",
			want: []Software{
				pkg("bash", "5.2.015-1", "", "", UninstallPacman),
				pkg("linux", "6.6.1.arch1-1", "", "", UninstallPacman),
			},
		},
		{"пакет без версии → только имя", "sirenam\n", []Software{pkg("sirenam", "", "", "", UninstallPacman)}},
		{"пустые строки пропускаются", "\n\nbash 5.2\n\n", []Software{pkg("bash", "5.2", "", "", UninstallPacman)}},
		{"пустой вывод → nil", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSoftware(t, parsePacmanShort(tt.out), tt.want)
		})
	}
}

// apk list -I: "имя-версия-релиз арх {origin} (лицензия) [installed]".
func TestParseApkList(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []Software
	}{
		{
			name: "полная строка: арх из второй колонки",
			out:  "zlib-1.3.1-r2 x86_64 {zlib} (Zlib) [installed]\n",
			want: []Software{pkg("zlib", "1.3.1-r2", "x86_64", "", UninstallAPK)},
		},
		{
			name: "дефис внутри имени",
			out:  "alpine-baselayout-3.6.8-r1 aarch64 {alpine-baselayout} (GPL-2.0-only) [installed]\n",
			want: []Software{pkg("alpine-baselayout", "3.6.8-r1", "aarch64", "", UninstallAPK)},
		},
		{
			// Порядок колонок поехал: во второй уже origin в скобках — лучше пустая
			// архитектура, чем "{zlib}" в карточке устройства.
			name: "вторая колонка в скобках → архитектуру не берём",
			out:  "zlib-1.3.1-r2 {zlib} (Zlib) [installed]\n",
			want: []Software{pkg("zlib", "1.3.1-r2", "", "", UninstallAPK)},
		},
		{
			name: "только имя-версия без колонок",
			out:  "musl-1.2.5-r0\n",
			want: []Software{pkg("musl", "1.2.5-r0", "", "", UninstallAPK)},
		},
		{
			name: "пустые строки пропускаются",
			out:  "\n  \nzlib-1.3.1-r2 x86_64 {zlib} (Zlib) [installed]\n",
			want: []Software{pkg("zlib", "1.3.1-r2", "x86_64", "", UninstallAPK)},
		},
		{"пустой вывод → nil", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSoftware(t, parseApkList(tt.out), tt.want)
		})
	}
}

// apk info -v (фолбэк): слитное "имя-версия-релиз", дефис легален и внутри имени.
func TestParseApk(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []Software
	}{
		{"простое имя", "zlib-1.2.13-r1\n", []Software{pkg("zlib", "1.2.13-r1", "", "", UninstallAPK)}},
		{"дефис внутри имени", "py3-setuptools-68.0.0-r0\n", []Software{pkg("py3-setuptools", "68.0.0-r0", "", "", UninstallAPK)}},
		{"несколько дефисов в имени", "ca-certificates-bundle-20230506-r0\n", []Software{pkg("ca-certificates-bundle", "20230506-r0", "", "", UninstallAPK)}},
		{"версия не с цифры → одно имя, пустая версия", "some-weird-pkg\n", []Software{pkg("some-weird-pkg", "", "", "", UninstallAPK)}},
		{"нет дефисов вовсе → одно имя", "musl\n", []Software{pkg("musl", "", "", "", UninstallAPK)}},
		{"один дефис → одно имя", "musl-utils\n", []Software{pkg("musl-utils", "", "", "", UninstallAPK)}},
		{"пустые строки пропускаются", "\n  \nzlib-1.2.13-r1\n", []Software{pkg("zlib", "1.2.13-r1", "", "", UninstallAPK)}},
		{"пустой вывод → nil", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSoftware(t, parseApk(tt.out), tt.want)
		})
	}
}

// Форматы обязаны просить у менеджеров РОВНО ту раскладку колонок, которую ждёт
// parseDelimited: разъехавшись, они молча положили бы вендора в ключ удаления.
func TestPackageFormatsMatchColumnLayout(t *testing.T) {
	tests := []struct {
		name, format string
		wantCols     []string
	}{
		{"dpkg", dpkgFormat, []string{"${Package}", "${Version}", "${Architecture}", "${binary:Package}", "${Maintainer}"}},
		{"rpm", rpmFormat, []string{"%{NAME}", "%{VERSION}-%{RELEASE}", "%{ARCH}", "%{NAME}", "%{VENDOR}"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.HasSuffix(tt.format, "\n") {
				t.Fatalf("формат %s не заканчивается переводом строки — записи склеятся", tt.name)
			}
			cols := strings.Split(strings.TrimSuffix(tt.format, "\n"), fieldSep)
			if len(cols) != len(tt.wantCols) {
				t.Fatalf("колонок %d (%q), ожидали %d", len(cols), cols, len(tt.wantCols))
			}
			for i := range tt.wantCols {
				if cols[i] != tt.wantCols[i] {
					t.Errorf("колонка %d: %q, ожидали %q", i, cols[i], tt.wantCols[i])
				}
			}
			// Свободный текст (мейнтейнер/вендор) обязан быть последним: стрей-
			// разделитель в нём тогда портит только его, а не ключ удаления.
			if cols[colVendor] != tt.wantCols[len(tt.wantCols)-1] {
				t.Errorf("вендор не в последней колонке: %q", cols)
			}
		})
	}
}

// Плейсхолдер менеджера в колонке хуже пустого значения: в карточке устройства он
// неотличим от настоящего вендора/архитектуры.
func TestNormalizePkgField(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"x86_64", "x86_64"},
		{"  amd64  ", "amd64"},
		{"(none)", ""},
		{"None", ""},
		{"Unknown Packager", ""},
		{" (none) ", ""},
		{"", ""},
		{"Rocky Enterprise Software Foundation", "Rocky Enterprise Software Foundation"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizePkgField(tt.in); got != tt.want {
				t.Errorf("normalizePkgField(%q)=%q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// Плейсхолдер из SMBIOS хуже пустого серийника: он одинаков на тысячах машин.
func TestIsPlaceholderSerial(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"   ", true},
		{"none", true},
		{"None", true},
		{"To Be Filled By O.E.M.", true},
		{"to be filled by o.e.m.", true},
		{"System Serial Number", true},
		{"Default string", true},
		{"Not Specified", true},
		{"0", true},
		{"  Default String \n", true},
		{"VMware-56 4d 1a", false},
		{"C02XK1GTJGH5", false},
		{"0123456789", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := isPlaceholderSerial(tt.in); got != tt.want {
				t.Errorf("isPlaceholderSerial(%q)=%v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseDmidecode(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{"чистое значение", "C02XK1GTJGH5\n", "C02XK1GTJGH5"},
		{"баннер сборки отбрасывается", "# dmidecode 3.3\nC02XK1GTJGH5\n", "C02XK1GTJGH5"},
		{"пустой вывод", "\n\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseDmidecode(tt.out); got != tt.want {
				t.Errorf("parseDmidecode(%q)=%q, want %q", tt.out, got, tt.want)
			}
		})
	}
}

// На aarch64 строки "model name" в /proc/cpuinfo нет — там Hardware/Model.
func TestParseCPUModel(t *testing.T) {
	tests := []struct {
		name    string
		cpuinfo string
		want    string
	}{
		{
			name:    "x86: model name",
			cpuinfo: "processor\t: 0\nmodel\t\t: 158\nmodel name\t: Intel(R) Core(TM) i7-8700\ncpu MHz\t\t: 3200\n",
			want:    "Intel(R) Core(TM) i7-8700",
		},
		{
			name:    "aarch64: Hardware вместо model name",
			cpuinfo: "processor\t: 0\nBogoMIPS\t: 108.00\nHardware\t: BCM2835\n",
			want:    "BCM2835",
		},
		{
			name:    "Raspberry Pi: Model",
			cpuinfo: "processor\t: 0\nModel\t\t: Raspberry Pi 4 Model B Rev 1.1\n",
			want:    "Raspberry Pi 4 Model B Rev 1.1",
		},
		{
			name:    "Hardware приоритетнее Model",
			cpuinfo: "Model\t\t: Raspberry Pi 4\nHardware\t: BCM2835\n",
			want:    "BCM2835",
		},
		{
			name:    "нижний регистр 'model' (номер модели x86) не путается с 'Model'",
			cpuinfo: "processor\t: 0\nmodel\t\t: 158\n",
			want:    runtime.GOARCH,
		},
		{
			name:    "пустое значение игнорируется",
			cpuinfo: "model name\t: \nHardware\t: BCM2835\n",
			want:    "BCM2835",
		},
		{
			name:    "ничего не нашли → архитектура",
			cpuinfo: "",
			want:    runtime.GOARCH,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseCPUModel(tt.cpuinfo); got != tt.want {
				t.Errorf("parseCPUModel()=%q, want %q", got, tt.want)
			}
		})
	}
}

func assertSoftware(t *testing.T, got, want []Software) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("получено %d записей (%+v), ожидали %d (%+v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("запись %d: %+v, ожидали %+v", i, got[i], want[i])
		}
	}
}

func TestParseLsblkCrypt(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"LUKS-цепочка", "lvm\ncrypt\npart\ndisk\n", "enabled"},
		{"без шифрования", "part\ndisk\n", "disabled"},
		{"пустой вывод", "\n", ""},
		{"crypt в конце", "part\ncrypt\n", "enabled"},
	}
	for _, c := range cases {
		if got := parseLsblkCrypt(c.in); got != c.want {
			t.Errorf("%s: parseLsblkCrypt = %q, want %q", c.name, got, c.want)
		}
	}
}

// bootTime читает /proc/stat живьём: на linux-CI обязан быть > 0.
func TestBootTimeLive(t *testing.T) {
	if bootTime() <= 0 {
		t.Error("bootTime на живой linux-системе должен быть > 0")
	}
}
