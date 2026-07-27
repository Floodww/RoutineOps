package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/config"
)

// TestStatusFilePathSharesLockDir — регресс на баг «в трее: агент не запущен» (macOS).
// Служба (root) и трей (юзер-сессия) должны вычислять ОДИН путь к status-файлу.
// Раньше обе стороны звали status.DefaultPath()=os.TempDir(), а он на macOS per-user →
// демон писал в свой tmp, трей читал пустоту в своём. Теперь status.json лежит рядом с
// lock.json в общем каталоге службы, который оба процесса получают из -lock-state.
func TestStatusFilePathSharesLockDir(t *testing.T) {
	shared := filepath.Join(os.TempDir(), "routineops-shared")
	cfg := &config.Config{LockStateFile: filepath.Join(shared, "lock.json")}

	got := statusFilePath(cfg)
	if want := filepath.Join(shared, "status.json"); got != want {
		t.Fatalf("statusFilePath = %q, want %q", got, want)
	}
	// В одном каталоге с lock.json и admin-request.json (общий машинный каталог,
	// который и служба-root, и трей-юзер видят одинаково).
	if dir, lockDir := filepath.Dir(got), filepath.Dir(lockStatePath(cfg)); dir != lockDir {
		t.Errorf("status не в общем каталоге lock-state: %q vs %q", dir, lockDir)
	}
	if dir, admDir := filepath.Dir(got), filepath.Dir(adminRequestPath(cfg)); dir != admDir {
		t.Errorf("status не рядом с admin-request: %q vs %q", dir, admDir)
	}
}
