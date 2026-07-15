//go:build darwin

package service

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallWritesPlist проверяет генерацию LaunchDaemon-plist установщиком без
// root: путь подменяется через ROUTINEOPS_LAUNCHD_PLIST, активация launchctl под
// не-root пропускается (см. install_darwin.go). Это гейт на корректность
// служебной обвязки, от которой зависит боевой e2e (enroll→heartbeat→selfupdate
// под launchd). Сам системный демон в /Library/LaunchDaemons тест НЕ трогает.
func TestInstallWritesPlist(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("тест рассчитан на не-root: под root Install активирует системный домен")
	}
	plist := filepath.Join(t.TempDir(), "RoutineOps-agent.test.plist")
	t.Setenv("ROUTINEOPS_LAUNCHD_PLIST", plist)
	t.Setenv("ROUTINEOPS_LAUNCH_AGENT_PLIST", filepath.Join(t.TempDir(), "RoutineOps-agent.tray.test.plist"))

	args := []string{"-server", "routineops.example:50051", "-cert-source", "keystore", "-keystore-label", "dev-device"}
	const exe = "/usr/local/bin/RoutineOps-agent"
	const workDir = "/var/lib/RoutineOps-agent"
	if err := Install(Config{Args: args, Exe: exe, WorkingDir: workDir}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data, err := os.ReadFile(plist)
	if err != nil {
		t.Fatalf("plist не записан: %v", err)
	}
	s := string(data)

	checks := []string{
		"<string>" + Name + "</string>", // Label
		"<string>run</string>",          // подкоманда службы
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",        // супервизор перезапустит после self-update
		"<key>WorkingDirectory</key>", // стабильный рабочий каталог
	}
	for _, want := range checks {
		if !strings.Contains(s, want) {
			t.Errorf("plist не содержит %q\n---\n%s", want, s)
		}
	}
	for _, a := range args {
		if !strings.Contains(s, "<string>"+a+"</string>") {
			t.Errorf("plist не пробросил аргумент %q", a)
		}
	}
	// Путь к бинарю должен быть абсолютным (launchd запускает без CWD) и равен
	// заданному cfg.Exe (стабильный путь после раскладки, а не временный бинарь).
	if !strings.Contains(s, "<string>"+exe+"</string>") {
		t.Errorf("plist не использует cfg.Exe %q как ProgramArguments[0]", exe)
	}
	// WorkingDirectory должен быть проброшен (служба пишет состояние в DataDir,
	// а не в read-only CWD = /).
	if !strings.Contains(s, "<key>WorkingDirectory</key>") || !strings.Contains(s, "<string>"+workDir+"</string>") {
		t.Errorf("plist не содержит WorkingDirectory=%q\n---\n%s", workDir, s)
	}

	// Uninstall (не-root) удаляет plist-файл.
	if err := Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Fatalf("plist не удалён Uninstall: stat err=%v", err)
	}
}

// TestInstallWritesPlist_CustomExe: cfg.Exe пробрасывается в ProgramArguments вместо os.Executable.
func TestInstallWritesPlist_CustomExe(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("тест рассчитан на не-root")
	}
	plist := filepath.Join(t.TempDir(), "RoutineOps-agent.test.plist")
	t.Setenv("ROUTINEOPS_LAUNCHD_PLIST", plist)
	t.Setenv("ROUTINEOPS_LAUNCH_AGENT_PLIST", filepath.Join(t.TempDir(), "RoutineOps-agent.tray.test.plist"))

	customExe := "/usr/local/bin/RoutineOps-agent"
	if err := Install(Config{Exe: customExe, Args: []string{"-server", "host:50051"}}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, _ := os.ReadFile(plist)
	if !strings.Contains(string(data), "<string>"+customExe+"</string>") {
		t.Errorf("plist должен содержать cfg.Exe=%q\n%s", customExe, data)
	}
}

// TestInstallWritesTrayPlist_PropagatesArgs — регресс полевого бага v1.5.1: трей
// ставился БЕЗ -lock-state и читал дефолтный os.TempDir()-путь своей сессии,
// никогда не видя locked:true, который демон пишет в другой (общий) файл —
// lock-screen не всплывал, хотя лок с сервера доходил.
func TestInstallWritesTrayPlist_PropagatesArgs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("тест рассчитан на не-root")
	}
	plist := filepath.Join(t.TempDir(), "RoutineOps-agent.test.plist")
	trayPlist := filepath.Join(t.TempDir(), "RoutineOps-agent.tray.test.plist")
	t.Setenv("ROUTINEOPS_LAUNCHD_PLIST", plist)
	t.Setenv("ROUTINEOPS_LAUNCH_AGENT_PLIST", trayPlist)

	args := []string{"-server", "routineops.example:50051", "-lock-state", "/var/lib/RoutineOps-agent/lock.json"}
	if err := Install(Config{Args: args, Exe: "/usr/local/bin/RoutineOps-agent"}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data, err := os.ReadFile(trayPlist)
	if err != nil {
		t.Fatalf("tray plist не записан: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "<string>tray</string>") {
		t.Errorf("tray plist не содержит подкоманду tray\n%s", s)
	}
	if !strings.Contains(s, "<string>-lock-state</string>") ||
		!strings.Contains(s, "<string>/var/lib/RoutineOps-agent/lock.json</string>") {
		t.Errorf("tray plist не пробросил -lock-state тем же путём, что и демону\n%s", s)
	}
}

// TestInstall_DaemonSurvivesTrayFailure — регресс главного бага: сбой установки трея
// НЕ должен мешать установке демона. Раньше Install начинался с InstallTrayAgent и на
// её ошибке делал return — устройство оставалось вообще без агента. Теперь демон
// пишется первым, а сбой трея возвращается как ErrTrayInstallFailed поверх него.
func TestInstall_DaemonSurvivesTrayFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("тест рассчитан на не-root: под root installDaemon трогает системный домен")
	}
	daemonPlist := filepath.Join(t.TempDir(), "RoutineOps-agent.plist")
	t.Setenv("ROUTINEOPS_LAUNCHD_PLIST", daemonPlist)
	// Путь трея ВНУТРЬ обычного файла → MkdirAll(filepath.Dir) даст ENOTDIR:
	// детерминированный сбой трея без root.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROUTINEOPS_LAUNCH_AGENT_PLIST", filepath.Join(blocker, "tray.plist"))

	err := Install(Config{Exe: "/usr/local/bin/RoutineOps-agent", Args: []string{"-server", "h:50051"}})
	if err == nil {
		t.Fatal("ждали ошибку установки трея")
	}
	if !errors.Is(err, ErrTrayInstallFailed) {
		t.Fatalf("ждали ErrTrayInstallFailed, got %v", err)
	}
	// ГЛАВНОЕ: демон установлен, несмотря на упавший трей.
	data, rerr := os.ReadFile(daemonPlist)
	if rerr != nil {
		t.Fatalf("демон не установлен при сбое трея: %v", rerr)
	}
	s := string(data)
	if !strings.Contains(s, "<string>/usr/local/bin/RoutineOps-agent</string>") || !strings.Contains(s, "<string>run</string>") {
		t.Errorf("daemon-plist неполный:\n%s", s)
	}
}

// TestUninstall_RemovesTrayPlist — Uninstall должен удалять и tray-plist (раньше его
// удаление вообще не проверялось, а под schg оно молча падало).
func TestUninstall_RemovesTrayPlist(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("тест рассчитан на не-root")
	}
	daemonPlist := filepath.Join(t.TempDir(), "RoutineOps-agent.plist")
	trayPlist := filepath.Join(t.TempDir(), "RoutineOps-agent.tray.plist")
	t.Setenv("ROUTINEOPS_LAUNCHD_PLIST", daemonPlist)
	t.Setenv("ROUTINEOPS_LAUNCH_AGENT_PLIST", trayPlist)

	if err := Install(Config{Exe: "/usr/local/bin/RoutineOps-agent", Args: []string{"-server", "h:50051"}}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	for _, p := range []string{daemonPlist, trayPlist} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("plist не удалён Uninstall: %q (err=%v)", p, err)
		}
	}
}

// TestInstallTrayAgentOverProtectedPlist — под root InstallTrayAgent обязан перезаписать
// plist, оставшийся под schg с прошлого Arm (иначе повторный enroll -install-service
// падает первой же строкой). launchctl здесь не дёргается — системный домен не трогаем.
func TestInstallTrayAgentOverProtectedPlist(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chflags schg требует root")
	}
	p := filepath.Join(t.TempDir(), "RoutineOps-agent.tray.plist")
	if err := os.WriteFile(p, []byte("<old/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("chflags", "schg", p).CombinedOutput(); err != nil {
		t.Fatalf("chflags schg: %v (%s)", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("chflags", "noschg", p).Run() })
	t.Setenv("ROUTINEOPS_LAUNCH_AGENT_PLIST", p)
	if err := InstallTrayAgent(Config{Exe: "/usr/local/bin/RoutineOps-agent"}); err != nil {
		t.Fatalf("InstallTrayAgent поверх schg-plist: %v", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "RoutineOps-agent.tray") {
		t.Fatalf("plist не перезаписан: %s", b)
	}
}

// TestInstallLayout_Darwin: InstallLayout возвращает Relocate=true и корректные пути.
func TestInstallLayout_Darwin(t *testing.T) {
	l := InstallLayout()
	if !l.Relocate {
		t.Error("Relocate должен быть true на macOS")
	}
	if l.BinPath != "/usr/local/bin/"+Name {
		t.Errorf("BinPath = %q, хотим /usr/local/bin/%s", l.BinPath, Name)
	}
	if l.DataDir == "" || l.CertDir == "" || l.LogDir == "" {
		t.Errorf("InstallLayout пустые пути: %+v", l)
	}
}
