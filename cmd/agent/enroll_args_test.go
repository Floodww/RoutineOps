package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/config"
	"github.com/Floodww/RoutineOps/internal/agent/keystore"
	"github.com/Floodww/RoutineOps/internal/agent/service"
)

// TestAbsCertPath проверяет якорение относительных путей к mTLS-материалу к
// каталогу бинаря: именно это чинит «служба не находит certs/agent.crt при
// старте из чужого рабочего каталога».
func TestAbsCertPath(t *testing.T) {
	dir := filepath.FromSlash("/opt/mdm")
	abs := filepath.Join(dir, "agent.crt") // уже абсолютный относительно dir

	cases := []struct {
		name string
		in   string
		dir  string
		want string
	}{
		{"относительный якорится к dir", "certs/agent.crt", dir, filepath.Join(dir, "certs", "agent.crt")},
		{"абсолютный не трогаем", abs, dir, abs},
		{"пустой не трогаем", "", dir, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := absCertPath(c.in, c.dir); got != c.want {
				t.Fatalf("absCertPath(%q, %q) = %q, хотим %q", c.in, c.dir, got, c.want)
			}
		})
	}

	// Без dir относительный путь всё равно становится абсолютным (резолв от CWD),
	// чтобы в службу никогда не попал относительный путь.
	got := absCertPath("certs/agent.crt", "")
	if !filepath.IsAbs(got) {
		t.Fatalf("absCertPath без dir вернул не абсолютный путь: %q", got)
	}
}

// TestInstallDir: каталог бинаря существует и абсолютен — годится как якорь.
func TestInstallDir(t *testing.T) {
	dir := installDir()
	if dir == "" {
		t.Skip("os.Executable недоступен в этом окружении")
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("installDir вернул не абсолютный путь: %q", dir)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("installDir вернул не каталог %q: %v", dir, err)
	}
}

// TestEnrollServiceArgs_File: в службу пишутся реальный адрес сервера и
// абсолютные пути к cert/key/ca (а не дефолты и не относительные пути).
func TestEnrollServiceArgs_File(t *testing.T) {
	cfg := &config.Config{
		ServerAddr: "203.0.113.5:50051",
		ServerName: "routineops-server",
		CertSource: "file",
		CertFile:   filepath.FromSlash("/opt/mdm/agent.crt"),
		KeyFile:    filepath.FromSlash("/opt/mdm/agent.key"),
		CAFile:     filepath.FromSlash("/opt/mdm/ca.crt"),
	}
	args := enrollServiceArgs(cfg, "dev-123")

	want := map[string]string{
		"-server":      cfg.ServerAddr,
		"-server-name": cfg.ServerName,
		"-cert":        cfg.CertFile,
		"-key":         cfg.KeyFile,
		"-ca":          cfg.CAFile,
	}
	got := flagPairs(t, args)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("аргумент %s = %q, хотим %q (args=%v)", k, got[k], v, args)
		}
	}
	for _, p := range []string{got["-cert"], got["-key"], got["-ca"]} {
		if !filepath.IsAbs(p) {
			t.Errorf("в службу попал относительный путь к сертификату: %q", p)
		}
	}
}

// TestEnrollServiceArgs_Keystore: для cert-source=keystore в службу пишутся
// источник keystore и метка идентичности, без путей к ключу на диске.
func TestEnrollServiceArgs_Keystore(t *testing.T) {
	cfg := &config.Config{
		ServerAddr: "203.0.113.5:50051",
		ServerName: "routineops-server",
		CertSource: keystore.SourceKeystore,
		CAFile:     filepath.FromSlash("/opt/mdm/ca.crt"),
	}
	got := flagPairs(t, enrollServiceArgs(cfg, "dev-123"))
	if got["-cert-source"] != "keystore" {
		t.Errorf("-cert-source = %q, хотим keystore", got["-cert-source"])
	}
	if got["-keystore-label"] != "dev-123" {
		t.Errorf("-keystore-label = %q, хотим device_id", got["-keystore-label"])
	}
	if _, ok := got["-key"]; ok {
		t.Errorf("для keystore не должно быть -key (ключ в хранилище ОС): %v", got)
	}
	if got["-server"] != cfg.ServerAddr {
		t.Errorf("-server = %q, хотим %q", got["-server"], cfg.ServerAddr)
	}
}

// TestDeriveUpdateURL: манифест самообновления выводится из enroll-URL (тот же
// сервер), нестандартный enroll-URL → "" (self-update не включаем).
func TestDeriveUpdateURL(t *testing.T) {
	cases := map[string]string{
		"http://routineops.example:8081/api/v1/enroll": "http://routineops.example:8081/api/v1/agent/version",
		"https://host/api/v1/enroll":                   "https://host/api/v1/agent/version",
		"":                                             "",
		"http://host/custom/path":                      "",
	}
	for in, want := range cases {
		if got := deriveUpdateURL(in); got != want {
			t.Errorf("deriveUpdateURL(%q) = %q, хотим %q", in, got, want)
		}
	}
}

// TestNormalizeEnrollURL: «голый» базовый URL (как из MSI ENROLL_URL без пути)
// дополняется каноническим /api/v1/enroll, явный путь не трогаем. Чинит HTTP 405
// при enroll и сохраняет вывод self-update-манифеста из enroll-URL.
func TestNormalizeEnrollURL(t *testing.T) {
	cases := map[string]string{
		"https://203.0.113.10:8081":       "https://203.0.113.10:8081/api/v1/enroll",
		"https://host:8081/":              "https://host:8081/api/v1/enroll",
		"https://host:8081/api/v1/enroll": "https://host:8081/api/v1/enroll",
		"https://host/custom/enroll":      "https://host/custom/enroll",
		"":                                "",
	}
	for in, want := range cases {
		if got := normalizeEnrollURL(in); got != want {
			t.Errorf("normalizeEnrollURL(%q) = %q, хотим %q", in, got, want)
		}
	}
	// После нормализации deriveUpdateURL находит манифест даже для базового URL.
	if got := deriveUpdateURL(normalizeEnrollURL("https://host:8081")); got != "https://host:8081/api/v1/agent/version" {
		t.Errorf("deriveUpdateURL после нормализации = %q, хотим манифест из enroll-URL", got)
	}
}

// TestAppendAbsFlag: только абсолютные пути попадают в аргументы службы; пустые и
// относительные (дефолты Windows/MSI) — отбрасываются, поведение установщика прежнее.
func TestAppendAbsFlag(t *testing.T) {
	abs := filepath.FromSlash("/var/lib/RoutineOps-agent/outbox")
	got := appendAbsFlag(nil, "-outbox-dir", abs)
	if len(got) != 2 || got[0] != "-outbox-dir" || got[1] != abs {
		t.Fatalf("абсолютный путь не добавлен: %v", got)
	}
	if got := appendAbsFlag(nil, "-outbox-dir", "agent_outbox"); len(got) != 0 {
		t.Fatalf("относительный путь не должен добавляться: %v", got)
	}
	if got := appendAbsFlag(nil, "-outbox-dir", ""); len(got) != 0 {
		t.Fatalf("пустой путь не должен добавляться: %v", got)
	}
}

// TestEnrollServiceArgs_StatePaths: после раскладки (абсолютные пути состояния в
// cfg) служба получает -outbox-dir/-task-state/-script-dedup/-forbidden-list/
// -lock-state — иначе run падал бы, пытаясь писать в read-only рабочий каталог (/).
func TestEnrollServiceArgs_StatePaths(t *testing.T) {
	data := filepath.FromSlash("/var/lib/RoutineOps-agent")
	cfg := &config.Config{
		ServerAddr:        "203.0.113.5:50051",
		ServerName:        "routineops-server",
		CertSource:        "file",
		CertFile:          filepath.Join(data, "certs", "agent.crt"),
		KeyFile:           filepath.Join(data, "certs", "agent.key"),
		CAFile:            filepath.Join(data, "certs", "ca.crt"),
		OutboxDir:         filepath.Join(data, "outbox"),
		TaskStateFile:     filepath.Join(data, "tasks.seen"),
		ScriptDedupFile:   filepath.Join(data, "scripts.seen"),
		ForbiddenListFile: filepath.Join(data, "forbidden_software.txt"),
		LockStateFile:     filepath.Join(data, "lock.json"),
	}
	got := flagPairs(t, enrollServiceArgs(cfg, "dev-123"))
	for flag, want := range map[string]string{
		"-outbox-dir":     cfg.OutboxDir,
		"-task-state":     cfg.TaskStateFile,
		"-script-dedup":   cfg.ScriptDedupFile,
		"-forbidden-list": cfg.ForbiddenListFile,
		"-lock-state":     cfg.LockStateFile,
	} {
		if got[flag] != want {
			t.Errorf("аргумент %s = %q, хотим %q", flag, got[flag], want)
		}
	}
}

// TestEnrollServiceArgs_UpdateURL: служба получает -update-url, выведенный из
// enroll-URL — иначе self-update не запустится (main.go стартует апдейтер только
// при заданном UpdateCheckURL). Имя флага = как в config.go (-update-url): раньше
// тут стоял -update-check, которого config.Load не знает → служба падала с 1053.
// Без enroll-URL флага быть не должно.
func TestEnrollServiceArgs_UpdateURL(t *testing.T) {
	cfg := &config.Config{
		ServerAddr: "203.0.113.5:50051", ServerName: "routineops-server", CertSource: "file",
		CertFile:  filepath.FromSlash("/opt/mdm/agent.crt"),
		KeyFile:   filepath.FromSlash("/opt/mdm/agent.key"),
		CAFile:    filepath.FromSlash("/opt/mdm/ca.crt"),
		EnrollURL: "http://routineops.example:8081/api/v1/enroll",
	}
	if got := flagPairs(t, enrollServiceArgs(cfg, "dev-123"))["-update-url"]; got != "http://routineops.example:8081/api/v1/agent/version" {
		t.Errorf("-update-url = %q, хотим манифест из enroll-URL", got)
	}

	cfg.EnrollURL = ""
	if _, ok := flagPairs(t, enrollServiceArgs(cfg, "dev-123"))["-update-url"]; ok {
		t.Error("без enroll-URL self-update не включаем — не должно быть -update-url")
	}
}

// TestEnrollServiceArgsParse — главный регресс-страж: аргументы, с которыми
// устанавливается служба, ДОЛЖНЫ парситься тем же config.Load, иначе служба падает
// «flag provided but not defined» ещё до StartServiceCtrlDispatcher → SCM 1053.
// Этот тест ловит ЛЮБОЙ рассинхрон имён флагов продюсера (enrollServiceArgs) и
// потребителя (config.Load), а не только конкретный -update-url.
func TestEnrollServiceArgsParse(t *testing.T) {
	cfg := &config.Config{
		ServerAddr: "203.0.113.5:50051", ServerName: "routineops-server", CertSource: "file",
		CertFile:  filepath.FromSlash("/opt/mdm/agent.crt"),
		KeyFile:   filepath.FromSlash("/opt/mdm/agent.key"),
		CAFile:    filepath.FromSlash("/opt/mdm/ca.crt"),
		EnrollURL: "http://routineops.example:8081/api/v1/enroll",
	}
	args := enrollServiceArgs(cfg, "dev-123")
	if _, err := config.Load(flag.NewFlagSet("agent", flag.ContinueOnError), args); err != nil {
		t.Fatalf("config.Load(enrollServiceArgs) = %v; служба с этими аргументами не стартует (1053). args=%v", err, args)
	}

	// keystore-режим даёт другой набор флагов (-cert-source, -keystore-label) — он
	// тоже обязан парситься.
	cfg.CertSource = keystore.SourceKeystore
	args = enrollServiceArgs(cfg, "dev-123")
	if _, err := config.Load(flag.NewFlagSet("agent", flag.ContinueOnError), args); err != nil {
		t.Fatalf("config.Load(enrollServiceArgs keystore) = %v; args=%v", err, args)
	}
}

// TestEnrollServiceArgs_NoStatePathsWhenRelative: дефолтные относительные пути
// состояния (Windows/MSI, Relocate=false) НЕ попадают в аргументы службы.
func TestEnrollServiceArgs_NoStatePathsWhenRelative(t *testing.T) {
	cfg := &config.Config{
		ServerAddr:        "203.0.113.5:50051",
		ServerName:        "routineops-server",
		CertSource:        "file",
		CertFile:          filepath.FromSlash("/opt/mdm/agent.crt"),
		KeyFile:           filepath.FromSlash("/opt/mdm/agent.key"),
		CAFile:            filepath.FromSlash("/opt/mdm/ca.crt"),
		OutboxDir:         "agent_outbox",
		TaskStateFile:     "agent_tasks.seen",
		ScriptDedupFile:   "agent_scripts.seen",
		ForbiddenListFile: "forbidden_software.txt",
	}
	got := flagPairs(t, enrollServiceArgs(cfg, "dev-123"))
	for _, flag := range []string{"-outbox-dir", "-task-state", "-script-dedup", "-forbidden-list", "-lock-state"} {
		if _, ok := got[flag]; ok {
			t.Errorf("относительный путь не должен уезжать в службу: %s=%q", flag, got[flag])
		}
	}
}

// TestRelocateForService_File: раскладка в file-режиме копирует бинарь, CA, cert и
// key в стабильные каталоги и переводит пути состояния в DataDir.
func TestRelocateForService_File(t *testing.T) {
	root := t.TempDir()
	lay := service.Layout{
		Relocate: true,
		BinPath:  filepath.Join(root, "bin", "RoutineOps-agent"),
		DataDir:  filepath.Join(root, "data"),
		CertDir:  filepath.Join(root, "data", "certs"),
		LogDir:   filepath.Join(root, "logs"),
	}
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "agent.crt"), "CERT")
	writeFile(t, filepath.Join(src, "agent.key"), "KEY")
	writeFile(t, filepath.Join(src, "ca.crt"), "CA")
	cfg := &config.Config{
		CertSource: "file",
		CertFile:   filepath.Join(src, "agent.crt"),
		KeyFile:    filepath.Join(src, "agent.key"),
		CAFile:     filepath.Join(src, "ca.crt"),
	}

	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("relocateForService: %v", err)
	}

	// Бинарь и весь mTLS-материал на месте.
	for _, p := range []string{lay.BinPath,
		filepath.Join(lay.CertDir, "ca.crt"),
		filepath.Join(lay.CertDir, "agent.crt"),
		filepath.Join(lay.CertDir, "agent.key")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("ожидался файл %q: %v", p, err)
		}
	}
	// Каталоги созданы.
	for _, d := range []string{lay.DataDir, lay.CertDir, lay.LogDir} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("ожидался каталог %q: %v", d, err)
		}
	}
	// cfg перенацелен на стабильные пути.
	wantCfg := map[string]string{
		"CAFile":            filepath.Join(lay.CertDir, "ca.crt"),
		"CertFile":          filepath.Join(lay.CertDir, "agent.crt"),
		"KeyFile":           filepath.Join(lay.CertDir, "agent.key"),
		"OutboxDir":         filepath.Join(lay.DataDir, "outbox"),
		"TaskStateFile":     filepath.Join(lay.DataDir, "tasks.seen"),
		"ScriptDedupFile":   filepath.Join(lay.DataDir, "scripts.seen"),
		"ForbiddenListFile": filepath.Join(lay.DataDir, "forbidden_software.txt"),
		"LockStateFile":     filepath.Join(lay.DataDir, "shared", "lock.json"),
		"UpdateFloorFile":   filepath.Join(lay.DataDir, "update_floor.txt"),
	}
	gotCfg := map[string]string{
		"CAFile": cfg.CAFile, "CertFile": cfg.CertFile, "KeyFile": cfg.KeyFile,
		"OutboxDir": cfg.OutboxDir, "TaskStateFile": cfg.TaskStateFile,
		"ScriptDedupFile": cfg.ScriptDedupFile, "ForbiddenListFile": cfg.ForbiddenListFile,
		"LockStateFile": cfg.LockStateFile, "UpdateFloorFile": cfg.UpdateFloorFile,
	}
	for k, want := range wantCfg {
		if gotCfg[k] != want {
			t.Errorf("cfg.%s = %q, хотим %q", k, gotCfg[k], want)
		}
	}
}

// TestRelocateForService_Keystore: в keystore-режиме копируется только CA (ключ уже
// в Keychain, на диске его нет) — cert/key в CertDir не создаются.
func TestRelocateForService_Keystore(t *testing.T) {
	root := t.TempDir()
	lay := service.Layout{
		Relocate: true,
		BinPath:  filepath.Join(root, "bin", "RoutineOps-agent"),
		DataDir:  filepath.Join(root, "data"),
		CertDir:  filepath.Join(root, "data", "certs"),
		LogDir:   filepath.Join(root, "logs"),
	}
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "ca.crt"), "CA")
	cfg := &config.Config{
		CertSource: keystore.SourceKeystore,
		CAFile:     filepath.Join(src, "ca.crt"),
	}

	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("relocateForService: %v", err)
	}
	if _, err := os.Stat(filepath.Join(lay.CertDir, "ca.crt")); err != nil {
		t.Errorf("CA должен быть скопирован и в keystore-режиме: %v", err)
	}
	if cfg.CAFile != filepath.Join(lay.CertDir, "ca.crt") {
		t.Errorf("cfg.CAFile не перенацелен: %q", cfg.CAFile)
	}
	for _, name := range []string{"agent.crt", "agent.key"} {
		if _, err := os.Stat(filepath.Join(lay.CertDir, name)); !os.IsNotExist(err) {
			t.Errorf("в keystore-режиме %s не должен создаваться (err=%v)", name, err)
		}
	}
}

// TestCopyFile: содержимое и права переносятся, существующий файл перезаписывается.
func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	writeFile(t, src, "hello")
	writeFile(t, dst, "OLD-LONGER-CONTENT")
	if err := copyFile(src, dst, 0o600); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatalf("содержимое dst = %q, хотим %q", b, "hello")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("права dst = %v, хотим 0600", fi.Mode().Perm())
		}
	}
}

// TestCopyFile_AliasedPathsNotZeroed: src и dst — разные строки на ОДИН inode (симлинк,
// как /var→/private/var на macOS). Строковый guard src==dst это не ловит; без проверки
// os.SameFile O_TRUNC обнулил бы общий файл ДО чтения, и CA/release_pubkey молча стал бы
// пустым. copyFile обязан распознать алиас и НЕ трогать данные.
func TestCopyFile_AliasedPathsNotZeroed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("симлинки на файлы на Windows требуют привилегий")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "ca.crt")
	writeFile(t, real, "REAL-CA-DATA")
	alias := filepath.Join(dir, "ca-alias.crt")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := copyFile(alias, real, 0o644); err != nil {
		t.Fatalf("copyFile по алиасу: %v", err)
	}
	if b, _ := os.ReadFile(real); string(b) != "REAL-CA-DATA" {
		t.Fatalf("данные обнулены алиас-копией: %q", b)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"localhost:55443":          true,
		"127.0.0.1:50051":          true,
		"[::1]:50051":              true,
		"203.0.113.5:50051":        false,
		"routineops.example:50051": false,
	}
	for addr, want := range cases {
		if got := isLoopbackHost(addr); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, хотим %v", addr, got, want)
		}
	}
}

// serviceLayout — Layout со всеми путями внутри t.TempDir() (тесты раскладки).
func serviceLayout(t *testing.T) service.Layout {
	t.Helper()
	root := t.TempDir()
	return service.Layout{
		Relocate: true,
		BinPath:  filepath.Join(root, "bin", "RoutineOps-agent"),
		DataDir:  filepath.Join(root, "data"),
		CertDir:  filepath.Join(root, "data", "certs"),
		LogDir:   filepath.Join(root, "logs"),
	}
}

// TestRelocateForService_Idempotent: вторая раскладка (переустановка/апгрейд/повторный
// enroll) обязана пройти по уже существующему бинарю в стабильном пути. Именно здесь
// на macOS всё умирало: copyFile делал O_TRUNC по файлу под schg.
func TestRelocateForService_Idempotent(t *testing.T) {
	lay := serviceLayout(t)
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "agent.crt"), "CERT")
	writeFile(t, filepath.Join(src, "agent.key"), "KEY")
	writeFile(t, filepath.Join(src, "ca.crt"), "CA")
	newCfg := func() *config.Config {
		return &config.Config{
			CertSource: "file",
			CertFile:   filepath.Join(src, "agent.crt"),
			KeyFile:    filepath.Join(src, "agent.key"),
			CAFile:     filepath.Join(src, "ca.crt"),
		}
	}
	for i := 1; i <= 2; i++ {
		if err := relocateForService(newCfg(), lay, discardLogger()); err != nil {
			t.Fatalf("relocateForService (проход %d): %v", i, err)
		}
	}
	if fi, err := os.Stat(lay.BinPath); err != nil || fi.Size() == 0 {
		t.Fatalf("бинарь после повторной раскладки: %v (err=%v)", fi, err)
	}
}

// TestRelocateForService_ReusedCAAdopted: src-CA нет (reused: enroll.Run не звался), а
// в CertDir лежит ca.crt от прошлой установки → раскладка НЕ падает, переиспользует его.
func TestRelocateForService_ReusedCAAdopted(t *testing.T) {
	lay := serviceLayout(t)
	if err := os.MkdirAll(lay.CertDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(lay.CertDir, "ca.crt"), "INSTALLED-CA")
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "agent.crt"), "CERT")
	writeFile(t, filepath.Join(src, "agent.key"), "KEY")
	cfg := &config.Config{
		CertSource: "file",
		CertFile:   filepath.Join(src, "agent.crt"),
		KeyFile:    filepath.Join(src, "agent.key"),
		CAFile:     filepath.Join(src, "ca.crt"), // не существует
	}
	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("adopt CA не должен падать: %v", err)
	}
	if cfg.CAFile != filepath.Join(lay.CertDir, "ca.crt") {
		t.Errorf("cfg.CAFile не перенацелен: %q", cfg.CAFile)
	}
	if b, _ := os.ReadFile(cfg.CAFile); string(b) != "INSTALLED-CA" {
		t.Errorf("установленный CA затёрт: %q", b)
	}
}

// TestRelocateForService_NoCAAnywhere: нет ни src-CA, ни CertDir/ca.crt → внятная
// ошибка с подсказкой (-ca/-ca-url), а не голый ENOENT.
func TestRelocateForService_NoCAAnywhere(t *testing.T) {
	lay := serviceLayout(t)
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "agent.crt"), "CERT")
	writeFile(t, filepath.Join(src, "agent.key"), "KEY")
	cfg := &config.Config{
		CertSource: "file",
		CertFile:   filepath.Join(src, "agent.crt"),
		KeyFile:    filepath.Join(src, "agent.key"),
		CAFile:     filepath.Join(src, "ca.crt"), // не существует
	}
	err := relocateForService(cfg, lay, discardLogger())
	if err == nil {
		t.Fatal("без CA нигде ждали ошибку")
	}
	if !strings.Contains(err.Error(), "-ca") || !strings.Contains(err.Error(), "-ca-url") {
		t.Errorf("ошибка должна подсказывать -ca/-ca-url: %v", err)
	}
}

// relocateCfgNoCA — конфиг file-режима с живой парой cert/key и НЕсуществующим CA:
// полевой reused-сценарий «идентичность жива, CA стёрт» (test-mac: снесён
// /var/lib/mdm-agent при файловой идентичности рядом с бинарём).
func relocateCfgNoCA(t *testing.T) *config.Config {
	t.Helper()
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "agent.crt"), "CERT")
	writeFile(t, filepath.Join(src, "agent.key"), "KEY")
	return &config.Config{
		CertSource: "file",
		CertFile:   filepath.Join(src, "agent.crt"),
		KeyFile:    filepath.Join(src, "agent.key"),
		CAFile:     filepath.Join(src, "ca.crt"), // не существует
	}
}

// serveCA поднимает httptest-сервер, отдающий body, и считает обращения.
func serveCA(t *testing.T, body []byte, hits *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// selfSignedLeafPEM — самоподписанный ЛИСТ (IsCA=false): валидный PEM-сертификат,
// который не годится как корень доверия. Для негативного теста ValidateCABundle.
func selfSignedLeafPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, // IsCA=false — явно лист
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestRelocateForService_NoCAOnDiskFetchedByURL: reused-путь на полу-очищенной машине —
// CA стёрт и с исходного пути, и из CertDir. Раньше adoptOrCopy падала «ни src, ни
// dst», хотя -ca-url/-ca-sha256 переданы. Теперь CA дотягивается по URL, сверяется с
// пином, проверяется на пригодность и кладётся в CertDir.
func TestRelocateForService_NoCAOnDiskFetchedByURL(t *testing.T) {
	ca := newRotCA(t, "Fetched Root CA")
	srv := serveCA(t, ca.pem, nil)

	lay := serviceLayout(t)
	cfg := relocateCfgNoCA(t)
	cfg.CAURL = srv.URL
	cfg.CASHA256 = sha256hex(ca.pem)
	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("relocateForService при живом -ca-url обязан дотянуть CA, а не падать: %v", err)
	}
	caDst := filepath.Join(lay.CertDir, "ca.crt")
	if b, err := os.ReadFile(caDst); err != nil || string(b) != string(ca.pem) {
		t.Errorf("скачанный CA в %q не совпал с отданным сервером (err=%v)", caDst, err)
	}
	if cfg.CAFile != caDst {
		t.Errorf("cfg.CAFile не перенацелен: %q", cfg.CAFile)
	}
}

// TestRelocateForService_NoCAOnDiskPinMismatch: тот же reused-путь без CA на диске, но
// скачанный бандл НЕ сходится с -ca-sha256 (MITM либо протухший пин) → раскладка падает,
// и битый CA НЕ появляется в CertDir.
func TestRelocateForService_NoCAOnDiskPinMismatch(t *testing.T) {
	ca := newRotCA(t, "Evil Root CA")
	srv := serveCA(t, ca.pem, nil)

	lay := serviceLayout(t)
	cfg := relocateCfgNoCA(t)
	cfg.CAURL = srv.URL
	cfg.CASHA256 = sha256hex([]byte("EXPECTED-OTHER-CA"))
	if err := relocateForService(cfg, lay, discardLogger()); err == nil {
		t.Fatal("при несовпадении пина ждали ошибку раскладки")
	}
	if _, err := os.Stat(filepath.Join(lay.CertDir, "ca.crt")); !os.IsNotExist(err) {
		t.Errorf("битый CA не должен записываться в CertDir (err=%v)", err)
	}
}

// TestRelocateForService_NoCAOnDiskURLWithoutPin: -ca-url задан БЕЗ -ca-sha256 и CA
// нигде нет → падение с точной TOFU-подсказкой про -ca-sha256 (а не общим «ни src,
// ни dst»), и скачивание даже не начинается.
func TestRelocateForService_NoCAOnDiskURLWithoutPin(t *testing.T) {
	hits := 0
	srv := serveCA(t, newRotCA(t, "Unpinned Root CA").pem, &hits)

	lay := serviceLayout(t)
	cfg := relocateCfgNoCA(t)
	cfg.CAURL = srv.URL // CASHA256 пуст
	err := relocateForService(cfg, lay, discardLogger())
	if err == nil {
		t.Fatal("без пина ждали ошибку раскладки")
	}
	if !strings.Contains(err.Error(), "ca-sha256") {
		t.Errorf("ошибка должна подсказывать -ca-sha256 (TOFU): %v", err)
	}
	if hits != 0 {
		t.Errorf("без пина скачивание не должно начинаться (обращений: %d)", hits)
	}
	if _, err := os.Stat(filepath.Join(lay.CertDir, "ca.crt")); !os.IsNotExist(err) {
		t.Errorf("CA не должен записываться в CertDir (err=%v)", err)
	}
}

// TestRelocateForService_LocalCAWinsOverURL: CA лежит на исходном пути И задан -ca-url —
// раскладка обязана взять локальный файл, не ходя в сеть (фетч только для случая
// «нет нигде»; приоритет источников тот же, что был до фикса).
func TestRelocateForService_LocalCAWinsOverURL(t *testing.T) {
	hits := 0
	remote := newRotCA(t, "Remote Root CA")
	srv := serveCA(t, remote.pem, &hits)

	lay := serviceLayout(t)
	cfg := relocateCfgNoCA(t)
	writeFile(t, cfg.CAFile, "LOCAL-CA") // src-CA существует
	cfg.CAURL = srv.URL
	cfg.CASHA256 = sha256hex(remote.pem)
	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("relocateForService: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(lay.CertDir, "ca.crt")); string(b) != "LOCAL-CA" {
		t.Errorf("локальный CA перебит фетчем: %q", b)
	}
	if hits != 0 {
		t.Errorf("при живом локальном CA в сеть ходить нельзя (обращений: %d)", hits)
	}
}

// TestRelocateForService_NoCAOnDiskFetchedNotACA: по -ca-url с ВЕРНЫМ пином отдан
// лист-сертификат, а не CA (перепутан эндпоинт/файл на сервере) → раскладка падает
// сразу с внятной ошибкой, огрызок не пишется — иначе это всплыло бы только вечным
// падением mTLS у службы.
func TestRelocateForService_NoCAOnDiskFetchedNotACA(t *testing.T) {
	leaf := selfSignedLeafPEM(t, "not-a-ca")
	srv := serveCA(t, leaf, nil)

	lay := serviceLayout(t)
	cfg := relocateCfgNoCA(t)
	cfg.CAURL = srv.URL
	cfg.CASHA256 = sha256hex(leaf)
	err := relocateForService(cfg, lay, discardLogger())
	if err == nil {
		t.Fatal("лист-сертификат вместо CA обязан ронять раскладку")
	}
	if !strings.Contains(err.Error(), "CA") {
		t.Errorf("ошибка должна объяснять, что бандл не годится как CA: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(lay.CertDir, "ca.crt")); !os.IsNotExist(serr) {
		t.Errorf("непригодный бандл не должен записываться в CertDir (err=%v)", serr)
	}
}

// TestRelocateForService_KeystoreReusedCAAdopted: keystore-режим, файлов на диске нет,
// CA только в CertDir → успех, cfg.CAFile перенацелен, cert/key не создаются.
func TestRelocateForService_KeystoreReusedCAAdopted(t *testing.T) {
	lay := serviceLayout(t)
	if err := os.MkdirAll(lay.CertDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(lay.CertDir, "ca.crt"), "INSTALLED-CA")
	cfg := &config.Config{
		CertSource: keystore.SourceKeystore,
		CAFile:     filepath.Join(t.TempDir(), "ca.crt"), // не существует
	}
	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("keystore adopt CA: %v", err)
	}
	for _, name := range []string{"agent.crt", "agent.key"} {
		if _, err := os.Stat(filepath.Join(lay.CertDir, name)); !os.IsNotExist(err) {
			t.Errorf("в keystore-режиме %s не должен создаваться (err=%v)", name, err)
		}
	}
}

// TestRelocateForService_IdentityPairAdopted: исходной пары cert+key нет, но в CertDir
// лежит рабочая пара от прошлой установки → переиспользуется, не затирается.
func TestRelocateForService_IdentityPairAdopted(t *testing.T) {
	lay := serviceLayout(t)
	if err := os.MkdirAll(lay.CertDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(lay.CertDir, "agent.crt"), "INSTALLED-CERT")
	writeFile(t, filepath.Join(lay.CertDir, "agent.key"), "INSTALLED-KEY")
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "ca.crt"), "CA") // только CA
	cfg := &config.Config{
		CertSource: "file",
		CertFile:   filepath.Join(src, "agent.crt"), // не существует
		KeyFile:    filepath.Join(src, "agent.key"), // не существует
		CAFile:     filepath.Join(src, "ca.crt"),
	}
	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("adopt пары: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(lay.CertDir, "agent.crt")); string(b) != "INSTALLED-CERT" {
		t.Errorf("установленный серт затёрт: %q", b)
	}
}

// TestRelocateForService_HalfIdentityNotMixed: есть исходный agent.crt, но нет
// agent.key; в CertDir целая пара → берём пару из CertDir, НЕ мешаем половинки.
func TestRelocateForService_HalfIdentityNotMixed(t *testing.T) {
	lay := serviceLayout(t)
	if err := os.MkdirAll(lay.CertDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(lay.CertDir, "agent.crt"), "INSTALLED-CERT")
	writeFile(t, filepath.Join(lay.CertDir, "agent.key"), "INSTALLED-KEY")
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "ca.crt"), "CA")
	writeFile(t, filepath.Join(src, "agent.crt"), "HALF-CERT") // ключа рядом НЕТ
	cfg := &config.Config{
		CertSource: "file",
		CertFile:   filepath.Join(src, "agent.crt"),
		KeyFile:    filepath.Join(src, "agent.key"), // не существует
		CAFile:     filepath.Join(src, "ca.crt"),
	}
	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("половинная идентичность не должна валить (есть пара в CertDir): %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(lay.CertDir, "agent.crt")); string(b) != "INSTALLED-CERT" {
		t.Errorf("установленный серт затёрт непарным исходным: %q", b)
	}
}

// TestRelocateForService_NoIdentityAnywhere: ни исходной пары, ни установленной →
// ошибка с подсказкой про -cert.
func TestRelocateForService_NoIdentityAnywhere(t *testing.T) {
	lay := serviceLayout(t)
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "ca.crt"), "CA")
	cfg := &config.Config{
		CertSource: "file",
		CertFile:   filepath.Join(src, "agent.crt"), // не существует
		KeyFile:    filepath.Join(src, "agent.key"), // не существует
		CAFile:     filepath.Join(src, "ca.crt"),
	}
	err := relocateForService(cfg, lay, discardLogger())
	if err == nil {
		t.Fatal("без идентичности нигде ждали ошибку")
	}
	if !strings.Contains(err.Error(), "-cert") {
		t.Errorf("ошибка должна подсказывать -cert: %v", err)
	}
}

// TestRelocateForService_CarriesReleaseKey — регрессия «self-update молча мёртв»:
// enroll кладёт release_pubkey рядом со СВОИМ CA, раскладка обязана перенести его в
// CertDir, иначе служба (её -ca смотрит в CertDir) ключ не найдёт.
func TestRelocateForService_CarriesReleaseKey(t *testing.T) {
	lay := serviceLayout(t)
	oldDir := installedCertDir
	defer func() { installedCertDir = oldDir }()
	installedCertDir = lay.CertDir

	src := t.TempDir() // enroll-каталог CA (у PKG это /usr/local/etc/mdm)
	writeFile(t, filepath.Join(src, "agent.crt"), "CERT")
	writeFile(t, filepath.Join(src, "agent.key"), "KEY")
	writeFile(t, filepath.Join(src, "ca.crt"), "CA")
	writeFile(t, filepath.Join(src, "release_pubkey"), "PUBKEY-B64")
	cfg := &config.Config{
		CertSource: "file",
		CertFile:   filepath.Join(src, "agent.crt"),
		KeyFile:    filepath.Join(src, "agent.key"),
		CAFile:     filepath.Join(src, "ca.crt"),
	}
	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("relocateForService: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(lay.CertDir, "release_pubkey"))
	if err != nil {
		t.Fatalf("release_pubkey не переехал в CertDir: %v", err)
	}
	if string(b) != "PUBKEY-B64" {
		t.Errorf("содержимое release_pubkey = %q, хотим %q", b, "PUBKEY-B64")
	}
	// Главный инвариант: служба стартует с cfg ПОСЛЕ раскладки и обязана найти ключ
	// ровно тем же резолвером, что и рантайм.
	if got := resolveUpdatePubKeyB64("", releaseKeyCandidates(cfg)...); got != "PUBKEY-B64" {
		t.Errorf("служба не находит ключ после раскладки: got %q", got)
	}
}

// TestRelocateForService_ReleaseKeyMissing_KeepsExisting — идемпотентный повтор: enroll.Run
// не звался, исходника нет, но ключ уже в CertDir. Не затираем и не падаем.
func TestRelocateForService_ReleaseKeyMissing_KeepsExisting(t *testing.T) {
	lay := serviceLayout(t)
	if err := os.MkdirAll(lay.CertDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(lay.CertDir, "release_pubkey"), "OLD-KEY")
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "agent.crt"), "CERT")
	writeFile(t, filepath.Join(src, "agent.key"), "KEY")
	writeFile(t, filepath.Join(src, "ca.crt"), "CA") // release_pubkey рядом НЕТ
	cfg := &config.Config{
		CertSource: "file",
		CertFile:   filepath.Join(src, "agent.crt"),
		KeyFile:    filepath.Join(src, "agent.key"),
		CAFile:     filepath.Join(src, "ca.crt"),
	}
	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("отсутствие release_pubkey не должно валить установку: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(lay.CertDir, "release_pubkey")); err != nil || string(b) != "OLD-KEY" {
		t.Errorf("существующий ключ затёрт/потерян: %q, err=%v", b, err)
	}
}

// TestRelocateForService_NoReleaseKeyAnywhere_NotFatal — деплой без self-update: ключа
// нет нигде, установка обязана пройти (агент работает, пусть без обновлений).
func TestRelocateForService_NoReleaseKeyAnywhere_NotFatal(t *testing.T) {
	lay := serviceLayout(t)
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "ca.crt"), "CA")
	cfg := &config.Config{CertSource: keystore.SourceKeystore, CAFile: filepath.Join(src, "ca.crt")}
	if err := relocateForService(cfg, lay, discardLogger()); err != nil {
		t.Fatalf("relocateForService: %v", err)
	}
	if _, err := os.Stat(filepath.Join(lay.CertDir, "release_pubkey")); !os.IsNotExist(err) {
		t.Errorf("ключа не было — не должно и появиться (err=%v)", err)
	}
}

// flagPairs разбирает плоский список -flag value в map для удобных проверок.
func flagPairs(t *testing.T, args []string) map[string]string {
	t.Helper()
	if len(args)%2 != 0 {
		t.Fatalf("ожидались пары -flag value, получили нечётное число аргументов: %v", args)
	}
	m := make(map[string]string, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		m[args[i]] = args[i+1]
	}
	return m
}

// writeFile создаёт файл с содержимым (хелпер тестов раскладки).
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("запись %q: %v", path, err)
	}
}

// discardLogger — логгер в никуда для тестов.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// гарантируем, что тест-файл не привязан к конкретной ОС.
var _ = runtime.GOOS
