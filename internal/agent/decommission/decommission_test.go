package decommission

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Run удаляет перечисленные файлы/каталоги и бинарь, зовёт оба хука.
func TestRun_RemovesEverythingAndCallsHooks(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "agent.crt")
	stateDir := filepath.Join(dir, "state")
	bin := filepath.Join(dir, "agent-bin")
	for _, f := range []string{cert, bin} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "outbox"), 0o755); err != nil {
		t.Fatal(err)
	}

	var stopped, disarmed bool
	err := Run(Plan{
		Files:   []string{cert, filepath.Join(dir, "missing.txt")}, // отсутствие — не ошибка
		Dirs:    []string{stateDir},
		BinPath: bin,
	}, Hooks{
		StopService:  func() error { stopped = true; return nil },
		DisarmTamper: func() { disarmed = true },
	}, quietLog())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !stopped || !disarmed {
		t.Errorf("хуки не вызваны: stopped=%v disarmed=%v", stopped, disarmed)
	}
	for _, p := range []string{cert, stateDir} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s не удалён (err=%v)", p, err)
		}
	}
	// На unix бинарь удаляется сразу; на Windows — отложенным делетером (здесь ещё
	// на месте), поэтому проверяем только на не-Windows.
	if runtime.GOOS != "windows" {
		if _, err := os.Stat(bin); !os.IsNotExist(err) {
			t.Errorf("бинарь не удалён на unix (err=%v)", err)
		}
	}
}

// Снос не прерывается, если снятие службы вернуло ошибку: device всё равно
// списывается, состояние обязано быть вычищено.
func TestRun_ContinuesWhenStopServiceFails(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "agent.crt")
	if err := os.WriteFile(cert, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(Plan{Files: []string{cert}}, Hooks{
		StopService: func() error { return os.ErrPermission },
	}, quietLog())
	if err != nil {
		t.Fatalf("Run не должен падать на ошибке StopService: %v", err)
	}
	if _, err := os.Stat(cert); !os.IsNotExist(err) {
		t.Errorf("серт не удалён несмотря на ошибку снятия службы (err=%v)", err)
	}
}

// removeDirSafe обязан отказаться удалять корень ФС и системные каталоги.
func TestRemoveDirSafe_RejectsDangerous(t *testing.T) {
	dangerous := []string{string(filepath.Separator), ""}
	if runtime.GOOS == "windows" {
		dangerous = append(dangerous, `C:\Windows`, `C:\Users`)
	} else {
		dangerous = append(dangerous, "/etc", "/usr", "/var", "/Library")
	}
	for _, p := range dangerous {
		if p == "" {
			continue // пустой путь = no-op, отдельно ниже
		}
		if err := removeDirSafe(p, quietLog()); err == nil {
			t.Errorf("removeDirSafe(%q) должен был отказать", p)
		}
	}
	if err := removeDirSafe("", quietLog()); err != nil {
		t.Errorf("removeDirSafe(\"\") должен быть no-op, got %v", err)
	}
}

// removeDirSafe не должен ходить по symlink/junction (защита от подмены пути).
func TestRemoveDirSafe_RejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("симлинки на Windows требуют привилегий — проверка на unix")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	link := filepath.Join(dir, "link")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "keep.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := removeDirSafe(link, quietLog()); err == nil {
		t.Error("removeDirSafe прошёл по symlink — возможна подмена пути")
	}
	if _, err := os.Stat(filepath.Join(victim, "keep.txt")); err != nil {
		t.Errorf("содержимое цели symlink пострадало: %v", err)
	}
}

// Отказ removeDirSafe по безопасности ОБЯЗАН быть errUnsafeDir — по нему Run
// отличает «нельзя трогать» от транзиентного сбоя и НЕ передаёт путь делетеру.
func TestRemoveDirSafe_UnsafeIsSentinel(t *testing.T) {
	sys := "/etc"
	if runtime.GOOS == "windows" {
		sys = `C:\Windows`
	}
	if err := removeDirSafe(sys, quietLog()); !errors.Is(err, errUnsafeDir) {
		t.Errorf("removeDirSafe(%q) = %v, ожидался errUnsafeDir", sys, err)
	}
}

// safeLeftover — второй барьер у делетера: небезопасный/reparse-путь отфильтровывается.
func TestSafeLeftover_FiltersUnsafe(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "state")
	if err := os.MkdirAll(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	sys := "/etc"
	if runtime.GOOS == "windows" {
		sys = `C:\Windows`
	}
	in := []string{ok, sys, ""}
	got := safeLeftover(in, quietLog())
	if len(got) != 1 || got[0] != ok {
		t.Fatalf("safeLeftover(%v) = %v, ожидался только %q", in, got, ok)
	}
}

// Ключевой инвариант #2: путь, отвергнутый removeDirSafe по безопасности (здесь —
// reparse-точка), НЕ уходит делетеру (leftover). На unix scheduleSelfDelete
// удаляет синхронно, поэтому «не запланирован к удалению» проверяем прямо:
// до фикса reparse-путь попадал в leftover → os.RemoveAll(link) сносил сам
// симлинк; после фикса он пропущен и симлинк на месте.
func TestRun_UnsafeDirNotScheduledForDeletion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("на unix scheduleSelfDelete удаляет синхронно — проверяем там")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := Run(Plan{Dirs: []string{link}}, Hooks{}, quietLog()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("reparse-путь попал в leftover и был удалён делетером (обход защиты): %v", err)
	}
}
