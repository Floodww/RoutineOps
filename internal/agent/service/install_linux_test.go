//go:build linux

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallWritesUnit проверяет генерацию systemd unit-файла без root: путь
// подменяется через ROUTINEOPS_SYSTEMD_UNIT, активация systemctl под не-root
// пропускается (см. install_linux.go). Гейт на корректность служебной обвязки,
// от которой зависит боевой запуск агента как службы на Linux (роудмап v2).
// Системный /etc/systemd/system тест НЕ трогает. Прогоняется в CI на ubuntu.
func TestInstallWritesUnit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("тест рассчитан на не-root: под root Install активирует systemctl")
	}
	unit := filepath.Join(t.TempDir(), "RoutineOps-agent.service")
	t.Setenv("ROUTINEOPS_SYSTEMD_UNIT", unit)

	args := []string{"-server", "routineops.example:50051", "-cert-source", "keystore", "-keystore-label", "dev-device"}
	if err := Install(Config{Args: args}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data, err := os.ReadFile(unit)
	if err != nil {
		t.Fatalf("unit не записан: %v", err)
	}
	s := string(data)

	checks := []string{
		"Description=RoutineOps Agent",
		"Restart=always", // супервизор перезапустит после self-update
		"WantedBy=multi-user.target",
		"StateDirectory=RoutineOps-agent",
		"WorkingDirectory=/var/lib/RoutineOps-agent",
		`"run"`, // подкоманда службы в ExecStart
	}
	for _, want := range checks {
		if !strings.Contains(s, want) {
			t.Errorf("unit не содержит %q\n---\n%s", want, s)
		}
	}
	for _, a := range args {
		if !strings.Contains(s, `"`+a+`"`) {
			t.Errorf("unit не пробросил аргумент %q", a)
		}
	}
	// ExecStart должен начинаться с абсолютного пути к бинарю в кавычках.
	if !strings.Contains(s, `ExecStart="/`) {
		t.Error("ExecStart должен указывать абсолютный путь к бинарю")
	}

	// Uninstall (не-root) удаляет unit-файл.
	if err := Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Fatalf("unit не удалён Uninstall: stat err=%v", err)
	}
}

// TestInstallWritesUnit_CustomExe: cfg.Exe пробрасывается в ExecStart вместо os.Executable.
func TestInstallWritesUnit_CustomExe(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("тест рассчитан на не-root")
	}
	unit := filepath.Join(t.TempDir(), "RoutineOps-agent.service")
	t.Setenv("ROUTINEOPS_SYSTEMD_UNIT", unit)

	customExe := "/usr/local/bin/RoutineOps-agent"
	if err := Install(Config{Exe: customExe, Args: []string{"-server", "host:50051"}}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, _ := os.ReadFile(unit)
	if !strings.Contains(string(data), `"`+customExe+`"`) {
		t.Errorf("ExecStart должен содержать cfg.Exe=%q\n%s", customExe, data)
	}
}

// TestInstallLayout_Linux: InstallLayout возвращает Relocate=true и корректные пути.
func TestInstallLayout_Linux(t *testing.T) {
	l := InstallLayout()
	if !l.Relocate {
		t.Error("Relocate должен быть true на Linux")
	}
	if l.BinPath != "/usr/local/bin/"+Name {
		t.Errorf("BinPath = %q, хотим /usr/local/bin/%s", l.BinPath, Name)
	}
	if l.DataDir == "" || l.CertDir == "" || l.LogDir == "" {
		t.Errorf("InstallLayout пустые пути: %+v", l)
	}
}
