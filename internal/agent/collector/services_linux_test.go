//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"testing"
)

const unitBody = `[Unit]
Description=Пример службы

[Service]
ExecStart=/usr/local/bin/example --serve
User=example

[Install]
WantedBy=multi-user.target
`

func writeUnit(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("подготовка %s: %v", name, err)
	}
}

func TestServicesFromUnitDirs(t *testing.T) {
	sysDir := t.TempDir()
	adminDir := t.TempDir()
	writeUnit(t, sysDir, "vendor.service", unitBody)
	writeUnit(t, adminDir, "local.service", unitBody)
	writeUnit(t, adminDir, "notes.txt", "не юнит")

	// Включённость systemd хранит симлинками в *.wants — так её и читаем.
	wants := filepath.Join(adminDir, "multi-user.target.wants")
	if err := os.Mkdir(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	writeUnit(t, wants, "local.service", unitBody)

	svcs, health := servicesFromUnitDirs([]unitDir{
		{path: sysDir, osOwned: true},
		{path: adminDir, osOwned: false},
	})
	if health != HealthOK {
		t.Fatalf("здоровье %q, want ok", health)
	}
	if len(svcs) != 2 {
		t.Fatalf("записей %d, want 2: %+v", len(svcs), svcs)
	}
	local, vendor := svcs[0], svcs[1] // канонический порядок: local < vendor

	if local.Name != "local.service" || vendor.Name != "vendor.service" {
		t.Fatalf("снимок не отсортирован: %+v", svcs)
	}
	if !vendor.OSOwned || local.OSOwned {
		t.Errorf("атрибуция каталогов неверна: vendor.OSOwned=%v local.OSOwned=%v", vendor.OSOwned, local.OSOwned)
	}
	if local.StartType != StartTypeEnabled {
		t.Errorf("юнит с симлинком в *.wants имеет StartType=%q, want %q", local.StartType, StartTypeEnabled)
	}
	if vendor.StartType != StartTypeManual {
		t.Errorf("юнит без симлинка имеет StartType=%q, want %q", vendor.StartType, StartTypeManual)
	}
	if local.ImagePath != "/usr/local/bin/example --serve" {
		t.Errorf("ExecStart=%q", local.ImagePath)
	}
	if local.Account != "example" {
		t.Errorf("User=%q, want example", local.Account)
	}
	if local.Display != "Пример службы" {
		t.Errorf("Description=%q", local.Display)
	}
}

func TestServicesFromUnitDirsAdminOverridesVendor(t *testing.T) {
	// systemd отдаёт приоритет /etc над /usr/lib. Если снимок этого не повторяет,
	// локальная ПОДМЕНА системного юнита останется невидимой: в дельте будет
	// лежать безобидное вендорское определение, а работать будет чужое.
	sysDir := t.TempDir()
	adminDir := t.TempDir()
	writeUnit(t, sysDir, "shared.service", unitBody)
	writeUnit(t, adminDir, "shared.service", "[Service]\nExecStart=/tmp/подменённый\n")

	svcs, _ := servicesFromUnitDirs([]unitDir{
		{path: sysDir, osOwned: true},
		{path: adminDir, osOwned: false},
	})
	if len(svcs) != 1 {
		t.Fatalf("записей %d, want 1", len(svcs))
	}
	if svcs[0].ImagePath != "/tmp/подменённый" {
		t.Errorf("победило вендорское определение (%q) — подмена из /etc невидима", svcs[0].ImagePath)
	}
	if svcs[0].OSOwned {
		t.Error("подменённый из /etc юнит помечен OSOwned — изменение атрибутировалось бы фону")
	}
}

func TestServicesFromUnitDirsNoSystemdIsUnsupported(t *testing.T) {
	// Система без systemd — не поломка. Failed здесь означал бы «улики утрачены»
	// и поднимал бы тревогу на каждой такой машине.
	svcs, health := servicesFromUnitDirs([]unitDir{{path: filepath.Join(t.TempDir(), "нет")}})
	if health != HealthUnsupported {
		t.Fatalf("здоровье %q, want unsupported", health)
	}
	if len(svcs) != 0 {
		t.Fatalf("записей %d, want 0", len(svcs))
	}
}

func TestUnitValueFirstMatch(t *testing.T) {
	body := []byte("[Service]\nExecStart=/bin/first\nExecStart=/bin/second\n")
	if got := unitValue(body, "ExecStart"); got != "/bin/first" {
		t.Fatalf("unitValue=%q, want /bin/first", got)
	}
	if got := unitValue(body, "User"); got != "" {
		t.Fatalf("отсутствующий ключ дал %q, want пусто", got)
	}
}
