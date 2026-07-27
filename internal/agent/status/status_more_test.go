package status

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// DefaultPath возвращает платформенный путь к status-файлу.
func TestDefaultPath(t *testing.T) {
	p := DefaultPath()
	if p == "" {
		t.Fatal("DefaultPath пустой")
	}
	if !strings.HasSuffix(p, ".json") {
		t.Fatalf("ожидали .json, got %q", p)
	}
	if runtime.GOOS == "windows" {
		if !strings.HasSuffix(p, filepath.Join("RoutineOps", "status.json")) {
			t.Fatalf("windows: ожидали ...RoutineOps\\status.json, got %q", p)
		}
	} else {
		if filepath.Base(p) != "RoutineOps-agent-status.json" {
			t.Fatalf("non-windows: ожидали RoutineOps-agent-status.json, got %q", p)
		}
	}
}

// Write атомарно перезаписывает существующий файл и ставит права 0644.
func TestWriteOverwriteAndPerm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	if err := Write(path, State{Version: "1"}); err != nil {
		t.Fatalf("первая запись: %v", err)
	}
	if err := Write(path, State{Version: "2", DeviceID: "d2"}); err != nil {
		t.Fatalf("перезапись: %v", err)
	}
	out, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.Version != "2" || out.DeviceID != "d2" {
		t.Fatalf("перезапись не применилась: %+v", out)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Fatalf("ожидали права 0644, got %o", fi.Mode().Perm())
	}
	// После атомарной записи в каталоге не должно остаться .tmp-огрызков.
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".status-") {
			t.Fatalf("остался временный файл: %s", e.Name())
		}
	}
}

// Write возвращает ошибку, если каталог создать нельзя (родитель — файл).
func TestWriteMkdirError(t *testing.T) {
	fileAsParent := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(fileAsParent, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// fileAsParent/sub/status.json — MkdirAll упрётся в файл.
	err := Write(filepath.Join(fileAsParent, "sub", "status.json"), State{Version: "1"})
	if err == nil {
		t.Fatal("ожидали ошибку Write при невозможности создать каталог")
	}
}

// Write возвращает ошибку, если финальный путь занят каталогом (rename не пройдёт),
// и не оставляет временный файл-огрызок.
func TestWriteRenameError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "status.json")
	if err := os.Mkdir(target, 0o755); err != nil { // путь — каталог, не файл
		t.Fatal(err)
	}
	if err := Write(target, State{Version: "1"}); err == nil {
		t.Fatal("ожидали ошибку Write: переименование поверх каталога")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".status-") {
			t.Fatalf("остался временный файл после ошибки rename: %s", e.Name())
		}
	}
}

// Read возвращает ошибку на повреждённом JSON.
func TestReadBadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(path, []byte("{не json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("ожидали ошибку Read на битом JSON")
	}
}

// Online: ровно на границе staleAfter heartbeat ещё считается живым.
func TestOnlineBoundary(t *testing.T) {
	s := State{LastHeartbeat: time.Now().Add(-time.Second)}
	if !s.Online(2 * time.Second) {
		t.Error("heartbeat в пределах порога должен быть online")
	}
}
