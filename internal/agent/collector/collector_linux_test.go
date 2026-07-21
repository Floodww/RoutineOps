//go:build linux

package collector

import (
	"runtime"
	"testing"
)

// dpkg-query и rpm настроены на один формат ("имя<TAB>версия"), поэтому парсер общий.
func TestParseTabbedPackages(t *testing.T) {
	tests := []struct {
		name  string
		parse func(string) []Software
		out   string
		want  []Software
	}{
		{
			name:  "dpkg: обычный вывод",
			parse: parseDpkg,
			out:   "bash\t5.1-6ubuntu1\nzlib1g\t1:1.2.11.dfsg-2\n",
			want:  []Software{{"bash", "5.1-6ubuntu1"}, {"zlib1g", "1:1.2.11.dfsg-2"}},
		},
		{
			// Удалённый, но не вычищенный пакет: dpkg помнит имя без версии.
			name:  "dpkg: пустая версия сохраняется",
			parse: parseDpkg,
			out:   "ghost\t\nbash\t5.1\n",
			want:  []Software{{"ghost", ""}, {"bash", "5.1"}},
		},
		{
			name:  "dpkg: строки без таба и пустые пропускаются",
			parse: parseDpkg,
			out:   "\nмусор без таба\n\tверсия-без-имени\nbash\t5.1\n",
			want:  []Software{{"bash", "5.1"}},
		},
		{
			name:  "dpkg: CRLF не попадает в версию",
			parse: parseDpkg,
			out:   "bash\t5.1\r\n",
			want:  []Software{{"bash", "5.1"}},
		},
		{
			name:  "rpm: имя + version-release",
			parse: parseRpm,
			out:   "glibc\t2.34-60.el9\nkernel\t5.14.0-362.el9\n",
			want:  []Software{{"glibc", "2.34-60.el9"}, {"kernel", "5.14.0-362.el9"}},
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

func TestParsePacman(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []Software
	}{
		{"обычный вывод", "bash 5.2.015-1\nlinux 6.6.1.arch1-1\n", []Software{{"bash", "5.2.015-1"}, {"linux", "6.6.1.arch1-1"}}},
		{"пакет без версии → только имя", "sirenam\n", []Software{{"sirenam", ""}}},
		{"пустые строки пропускаются", "\n\nbash 5.2\n\n", []Software{{"bash", "5.2"}}},
		{"пустой вывод → nil", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSoftware(t, parsePacman(tt.out), tt.want)
		})
	}
}

// apk отдаёт слитное "имя-версия-релиз"; дефис легален и внутри имени.
func TestParseApk(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []Software
	}{
		{"простое имя", "zlib-1.2.13-r1\n", []Software{{"zlib", "1.2.13-r1"}}},
		{"дефис внутри имени", "py3-setuptools-68.0.0-r0\n", []Software{{"py3-setuptools", "68.0.0-r0"}}},
		{"несколько дефисов в имени", "ca-certificates-bundle-20230506-r0\n", []Software{{"ca-certificates-bundle", "20230506-r0"}}},
		{"версия не с цифры → одно имя, пустая версия", "some-weird-pkg\n", []Software{{"some-weird-pkg", ""}}},
		{"нет дефисов вовсе → одно имя", "musl\n", []Software{{"musl", ""}}},
		{"один дефис → одно имя", "musl-utils\n", []Software{{"musl-utils", ""}}},
		{"пустые строки пропускаются", "\n  \nzlib-1.2.13-r1\n", []Software{{"zlib", "1.2.13-r1"}}},
		{"пустой вывод → nil", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSoftware(t, parseApk(tt.out), tt.want)
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
