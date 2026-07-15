//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/Floodww/RoutineOps/internal/agent/tamper"
)

// TrayPlistPath — путь к LaunchAgent-плисту трея. Экспортирован, чтобы
// launchTrayInActiveSession (cmd/agent/tray_darwin.go) мог забутстрапить тот же
// файл, что пишет InstallTrayAgent, без дублирования пути/env-переопределения.
func TrayPlistPath() string {
	return agentPlistPath()
}

func agentPlistPath() string {
	if p := os.Getenv("ROUTINEOPS_LAUNCH_AGENT_PLIST"); p != "" {
		return p
	}
	return "/Library/LaunchAgents/" + Name + ".tray.plist"
}

var agentPlistTmpl = template.Must(template.New("agent_plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}.tray</string>
	<key>ProgramArguments</key>
	<array>
{{range .Args}}		<string>{{.}}</string>
{{end}}	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<array>
		<string>Aqua</string>
	</array>
</dict>
</plist>
`))

// InstallTrayAgent пишет LaunchAgent plist для автозапуска трея и под root загружает его.
func InstallTrayAgent(cfg Config) error {
	exe, err := exePath(cfg)
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)

	data := struct {
		Label string
		Args  []string
	}{
		Label: Name,
		// Тем же набором флагов, что и демон (-lock-state и т.п.): трей и служба должны
		// читать/писать один и тот же файл состояния блокировки и заявок на админ-права,
		// иначе трей поллит дефолтный os.TempDir()-путь своей сессии и никогда не видит
		// locked:true, который пишет демон в другой каталог (полевой баг v1.5.1).
		Args: append([]string{exe, "tray"}, cfg.Args...),
	}

	path := agentPlistPath()
	// Каталог обычно есть, но путь переопределяем через ROUTINEOPS_LAUNCH_AGENT_PLIST — создаём.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("создание каталога agent plist %s: %w", filepath.Dir(path), err)
	}
	// tamper.Arm вешает schg и на tray-plist — без снятия O_TRUNC вернёт EPERM даже
	// под root. Именно на этой строке умирал повторный enroll -install-service.
	if err := tamper.Unlock(path); err != nil {
		return fmt.Errorf("снятие tamper-защиты с agent plist: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("запись agent plist %s (нужен root?): %w", path, err)
	}
	if err := agentPlistTmpl.Execute(f, data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return nil
	}

	// launchd подхватит новый LaunchAgent из /Library/LaunchAgents САМ только при
	// следующем логоне пользователя. Чтобы поднять трей СЕЙЧАС, вызывающий
	// (runEnroll) отдельно зовёт launchTrayInActiveSession — она бутстрапит
	// именно этот путь (agentPlistPath()) в активную GUI-сессию.
	return nil
}

// UninstallTrayAgent снимает агента и удаляет plist.
func UninstallTrayAgent() error {
	path := agentPlistPath()
	if os.Geteuid() == 0 {
		// Снять агента у всех активных пользователей сложно без перебора uid,
		// поэтому мы можем просто убить процесс 'RoutineOps-agent tray'.
		_ = exec.Command("pkill", "-f", "RoutineOps-agent tray").Run()
	}
	// Без снятия schg os.Remove вернёт EPERM даже под root.
	_ = tamper.Unlock(path)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("удаление agent plist %s: %w", path, err)
	}
	return nil
}
