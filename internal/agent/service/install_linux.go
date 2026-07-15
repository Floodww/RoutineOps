//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

// unitName — имя systemd-юнита. systemctl адресует службу по нему. Производное от
// общего Name, чтобы имя службы не разъезжалось между платформами.
const unitName = Name + ".service"

// unitPath — путь к unit-файлу. Переопределяется через ROUTINEOPS_SYSTEMD_UNIT
// (удобно для теста/нестандартной установки).
func unitPath() string {
	if p := os.Getenv("ROUTINEOPS_SYSTEMD_UNIT"); p != "" {
		return p
	}
	return "/etc/systemd/system/" + unitName
}

var unitTmpl = template.Must(template.New("unit").Parse(`[Unit]
Description=RoutineOps Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.ExecStart}}
Restart=always
RestartSec=5
# StateDirectory создаёт/чистит /var/lib/RoutineOps-agent (там относительные файлы агента:
# outbox, *.seen, forbidden_software.txt).
StateDirectory=RoutineOps-agent
WorkingDirectory=/var/lib/RoutineOps-agent

[Install]
WantedBy=multi-user.target
`))

// Install пишет systemd unit-файл и (под root) активирует службу через systemctl.
// Restart=always обеспечивает и восстановление после падений, и штатный
// перезапуск после самообновления (агент выходит с ошибкой → systemd поднимает
// новый бинарь) — как KeepAlive на macOS и recovery actions на Windows.
func Install(cfg Config) error {
	exe, err := exePath(cfg)
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)

	data := struct{ ExecStart string }{
		ExecStart: execStartLine(exe, cfg.Args),
	}

	path := unitPath()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("запись unit %s (нужен root?): %w", path, err)
	}
	if err := unitTmpl.Execute(f, data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Активацию делает только root. Без root unit записан — активируйте вручную:
	// sudo systemctl daemon-reload && sudo systemctl enable --now RoutineOps-agent.service.
	if os.Geteuid() != 0 {
		return nil
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "enable", "--now", unitName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable --now %s: %w: %s", unitName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Uninstall останавливает/выключает службу и удаляет unit-файл.
func Uninstall() error {
	if os.Geteuid() == 0 {
		_ = exec.Command("systemctl", "disable", "--now", unitName).Run()
	}
	path := unitPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("удаление unit %s: %w", path, err)
	}
	if os.Geteuid() == 0 {
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	return nil
}

// Harden — no-op: ужесточение DACL службы только для Windows.
func Harden() error { return nil }

// execStartLine собирает строку ExecStart: путь к бинарю + "run" + аргументы,
// каждый токен в кавычках (systemd сам снимет кавычки) — безопасно для путей с
// пробелами.
func execStartLine(exe string, args []string) string {
	tokens := append([]string{exe, "run"}, args...)
	quoted := make([]string, len(tokens))
	for i, t := range tokens {
		quoted[i] = quoteToken(t)
	}
	return strings.Join(quoted, " ")
}

// quoteToken оборачивает токен в двойные кавычки systemd с экранированием \ и ".
func quoteToken(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
