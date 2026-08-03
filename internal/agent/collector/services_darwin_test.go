//go:build darwin

package collector

import (
	"os"
	"path/filepath"
	"testing"
)

const xmlPlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Label</key><string>com.example.daemon</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/example</string>
		<string>--serve</string>
	</array>
	<key>UserName</key><string>_example</string>
</dict>
</plist>
`

func writePlist(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("подготовка %s: %v", name, err)
	}
}

func TestServicesFromPlistDirs(t *testing.T) {
	sysDir := t.TempDir()
	adminDir := t.TempDir()
	writePlist(t, sysDir, "com.apple.builtin.plist", xmlPlist)
	writePlist(t, adminDir, "com.example.daemon.plist", xmlPlist)
	// Посторонние файлы каталога не должны попадать в снимок.
	writePlist(t, adminDir, "README.txt", "не plist")
	if err := os.Mkdir(filepath.Join(adminDir, "subdir.plist"), 0o755); err != nil {
		t.Fatal(err)
	}

	dirs := []plistDir{
		{path: sysDir, kind: KindService, osOwned: true},
		{path: adminDir, kind: KindService, osOwned: false},
	}
	svcs, health := servicesFromPlistDirs(dirs, map[string]bool{"com.example.daemon": true})

	if health != HealthOK {
		t.Fatalf("здоровье %q, want ok", health)
	}
	if len(svcs) != 2 {
		t.Fatalf("в снимке %d записей, want 2: %+v", len(svcs), svcs)
	}
	// Канонический порядок: com.apple.* < com.example.*
	sys, admin := svcs[0], svcs[1]

	if !sys.OSOwned {
		t.Error("демон из системного каталога обязан быть OSOwned — иначе штатное обновление ОС атрибутируется человеку")
	}
	if admin.OSOwned {
		t.Error("демон из /Library признан системным — подмена админского демона стала бы фоновым шумом")
	}
	if admin.StartType != StartTypeDisabled {
		t.Errorf("отключённый демон имеет StartType=%q, want %q", admin.StartType, StartTypeDisabled)
	}
	if sys.StartType != StartTypeEnabled {
		t.Errorf("включённый демон имеет StartType=%q, want %q", sys.StartType, StartTypeEnabled)
	}
	if admin.ImagePath != "/usr/local/bin/example" {
		t.Errorf("ImagePath=%q, want /usr/local/bin/example", admin.ImagePath)
	}
	if admin.Account != "_example" {
		t.Errorf("Account=%q, want _example", admin.Account)
	}
	if admin.DefHash == "" {
		t.Error("DefHash пуст — изменение бинарного plist осталось бы невидимым")
	}
}

func TestServicesFromPlistDirsDetectsDefinitionChange(t *testing.T) {
	// Смысл DefHash: аргументы запуска подменили, а все явные поля прежние.
	dir := t.TempDir()
	writePlist(t, dir, "com.example.daemon.plist", xmlPlist)
	dirs := []plistDir{{path: dir, kind: KindService}}

	before, _ := servicesFromPlistDirs(dirs, nil)
	writePlist(t, dir, "com.example.daemon.plist", xmlPlist+"<!-- вставлен аргумент -->\n")
	after, _ := servicesFromPlistDirs(dirs, nil)

	if before[0].DefHash == after[0].DefHash {
		t.Fatal("правка plist не изменила DefHash — подмена определения демона была бы невидима")
	}
}

func TestServicesFromPlistDirsMissingDirIsNotFailure(t *testing.T) {
	// Отсутствующий каталог — норма чистой системы. Если считать его поломкой,
	// каждая такая машина получит «улики недостоверны» на ровном месте, и
	// оператор перестанет верить признаку здоровья вообще.
	dir := t.TempDir()
	writePlist(t, dir, "com.example.daemon.plist", xmlPlist)
	dirs := []plistDir{
		{path: dir, kind: KindService},
		{path: filepath.Join(dir, "нет-такого-каталога"), kind: KindAgent},
	}
	svcs, health := servicesFromPlistDirs(dirs, nil)
	if health != HealthOK {
		t.Fatalf("здоровье %q при отсутствующем каталоге, want ok", health)
	}
	if len(svcs) != 1 {
		t.Fatalf("записей %d, want 1", len(svcs))
	}
}

func TestServicesFromPlistDirsAllDirsGoneIsFailure(t *testing.T) {
	// А вот полное отсутствие источников — уже провал: пустой снимок нельзя
	// показывать как «на машине ничего нет».
	dirs := []plistDir{{path: filepath.Join(t.TempDir(), "нет"), kind: KindService}}
	svcs, health := servicesFromPlistDirs(dirs, nil)
	if health != HealthFailed {
		t.Fatalf("здоровье %q, want failed", health)
	}
	if len(svcs) != 0 {
		t.Fatalf("записей %d, want 0", len(svcs))
	}
}

func TestPlistProgramPreferredOverArguments(t *testing.T) {
	// Ключ Program важнее ProgramArguments: launchd берёт именно его, и если бы
	// мы читали только массив, подмена исполняемого файла прошла бы мимо явного
	// поля (осталась бы только в хэше, без внятной строки в карточке).
	body := `<?xml version="1.0"?><plist><dict>
	<key>Program</key><string>/opt/real/bin</string>
	<key>ProgramArguments</key><array><string>/usr/bin/decoy</string></array>
	</dict></plist>`
	if got := plistFirstProgramArgument([]byte(body)); got != "/opt/real/bin" {
		t.Fatalf("ImagePath=%q, want /opt/real/bin", got)
	}
}

func TestPlistBinaryYieldsEmptyFieldsButHashes(t *testing.T) {
	// Бинарный plist мы не разбираем сознательно (сторонние библиотеки в проекте
	// запрещены). Проверяем, что это деградация, а не поломка: явные поля пусты,
	// но определение всё равно захэшировано и его изменение будет видно.
	dir := t.TempDir()
	writePlist(t, dir, "com.example.binary.plist", "bplist00\x00\x01\x02неразбираемо")
	svcs, health := servicesFromPlistDirs([]plistDir{{path: dir, kind: KindService}}, nil)
	if health != HealthOK || len(svcs) != 1 {
		t.Fatalf("здоровье %q, записей %d", health, len(svcs))
	}
	if svcs[0].ImagePath != "" || svcs[0].Account != "" {
		t.Errorf("из бинарного plist извлечены поля: %+v", svcs[0])
	}
	if svcs[0].DefHash == "" {
		t.Error("бинарный plist не захэширован — его подмена была бы невидима полностью")
	}
}
