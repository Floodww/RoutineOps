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

// Run зовёт PurgeKeystore-хук и не прерывает снос на его ошибке (best-effort,
// как StopService): устройство списывается в любом случае.
func TestRun_CallsPurgeKeystoreHookAndContinuesOnError(t *testing.T) {
	var purged bool
	err := Run(Plan{}, Hooks{
		PurgeKeystore: func() error { purged = true; return os.ErrPermission },
	}, quietLog())
	if err != nil {
		t.Fatalf("Run не должен падать на ошибке PurgeKeystore: %v", err)
	}
	if !purged {
		t.Error("PurgeKeystore не вызван — идентичность в хранилище ОС пережила бы снос")
	}
}

// Инвариант ПОРЯДКА снятия службы, зависящий от платформы. На macOS launchctl
// bootout (внутри StopService) шлёт SIGKILL самому процессу-демону, выполняющему
// снос, поэтому службу обязано снимать ПОСЛЕ удаления бинаря; на Windows/Linux
// снятие безопасно РАНО (до удаления файлов) и делается там (см. stopServiceEarly).
//
// Тест НЕ скипается по GOOS: на linux/windows-CI он сторожит, что рефактор
// stopServiceEarly/scheduleSelfDelete не переставил снятие на этих платформах, а
// счётчик вызовов ловит частичную darwin-регрессию (снятие И рано, И поздно) на
// ЛЮБОЙ ОС. Живьём darwin-ветку («снятие после бинаря») исполняет только go test
// на маке — macOS-раннера в CI нет (заведение macOS-джобы — задача мейнтейнера).
func TestRun_StopServiceOrderingPerPlatform(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent-bin")
	if err := os.WriteFile(bin, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls int
	var binPresentEver bool // sticky: бинарь существовал ХОТЬ НА ОДНОМ вызове StopService
	err := Run(Plan{BinPath: bin}, Hooks{
		StopService: func() error {
			calls++
			if _, statErr := os.Stat(bin); statErr == nil {
				binPresentEver = true
			}
			return nil
		},
	}, quietLog())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Ровно один вызов на всех платформах: два вызова (ранний + поздний) означали бы
	// частичную darwin-регрессию, которую перезапись «последнего» флага замаскировала.
	if calls != 1 {
		t.Fatalf("StopService вызван %d раз, ожидался ровно 1", calls)
	}
	if runtime.GOOS == "darwin" {
		if binPresentEver {
			t.Error("darwin: StopService вызван при ЖИВОМ бинаре — ранний launchctl bootout снёс бы сам процесс сноса, teardown оборвался бы (полевой блокер v2.4.9)")
		}
	} else {
		if !binPresentEver {
			t.Errorf("%s: StopService вызван уже ПОСЛЕ удаления бинаря — рефактор изменил прежний (ранний) порядок снятия службы", runtime.GOOS)
		}
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
