//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Floodww/RoutineOps/internal/agent/tamper"
)

// plistPath — путь к LaunchDaemon. Переопределяется через ROUTINEOPS_LAUNCHD_PLIST
// (удобно для теста/нестандартной установки).
func plistPath() string {
	if p := os.Getenv("ROUTINEOPS_LAUNCHD_PLIST"); p != "" {
		return p
	}
	return "/Library/LaunchDaemons/" + Name + ".plist"
}

var plistTmpl = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
{{range .Args}}		<string>{{.}}</string>
{{end}}	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
{{if .WorkingDir}}	<key>WorkingDirectory</key>
	<string>{{.WorkingDir}}</string>
{{end}}	<key>StandardOutPath</key>
	<string>{{.LogOut}}</string>
	<key>StandardErrorPath</key>
	<string>{{.LogErr}}</string>
</dict>
</plist>
`))

// Install ставит агента на macOS: СНАЧАЛА LaunchDaemon (это и есть служба —
// heartbeat, инвентарь, задачи, лок, self-update), ПОТОМ LaunchAgent трея.
//
// Порядок принципиален. Раньше Install начинался с InstallTrayAgent и на её ошибке
// делал return: косметический трей был гейтом для службы. В поле запись
// /Library/LaunchAgents/RoutineOps-agent.tray.plist падала (schg с прошлой установки, его
// вешает tamper.Arm и никто не снимает при переустановке; либо просто нет прав на
// /Library/LaunchAgents), и устройство оставалось ВООБЩЕ без агента, хотя демон
// поставить было можно. Теперь трей best-effort: его сбой возвращается как
// ErrTrayInstallFailed ПОВЕРХ уже установленного демона, вызывающий пишет Warn.
func Install(cfg Config) error {
	if err := installDaemon(cfg); err != nil {
		return err
	}
	if err := InstallTrayAgent(cfg); err != nil {
		return fmt.Errorf("%w: %v", ErrTrayInstallFailed, err)
	}
	return nil
}

// installDaemon пишет plist LaunchDaemon и (под root) активирует службу через launchctl.
// Вынесен из Install, чтобы ранний выход «не под root» не съедал установку трея, которая
// теперь идёт после демона.
func installDaemon(cfg Config) error {
	exe, err := exePath(cfg)
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)

	// Каталог для логов демона; без прав root падаем в системный temp.
	logDir := InstallLayout().LogDir
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		logDir = filepath.Join(os.TempDir(), "RoutineOps")
		_ = os.MkdirAll(logDir, 0o755)
	}

	data := struct {
		Label, LogOut, LogErr, WorkingDir string
		Args                              []string
	}{
		Label:      Name,
		LogOut:     filepath.Join(logDir, "agent.out.log"),
		LogErr:     filepath.Join(logDir, "agent.err.log"),
		WorkingDir: cfg.WorkingDir,
		Args:       append([]string{exe, "run"}, cfg.Args...),
	}

	path := plistPath()
	// Переустановка поверх взведённого tamper: plist остался под schg с прошлого Arm,
	// и O_TRUNC ниже упёрся бы в EPERM даже под root. Снимаем флаг ровно с этого файла;
	// Arm в конце установки взведёт заново. На Linux/Windows Unlock — no-op.
	if err := tamper.Unlock(path); err != nil {
		return fmt.Errorf("снятие tamper-защиты с plist: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("запись plist %s (нужен root?): %w", path, err)
	}
	if err := plistTmpl.Execute(f, data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Активацию делает только root. Без root plist записан — активируйте вручную:
	// sudo launchctl bootstrap system <plist>.
	if os.Geteuid() != 0 {
		return nil
	}
	// Переустановка: старый демон уже загружен в системный домен, bootstrap на
	// занятый лейбл вернёт «service already loaded». Снимаем прежний инстанс
	// (best-effort), тогда bootstrap поднимет новый plist.
	_ = exec.Command("launchctl", "bootout", "system/"+Name).Run()
	if out, err := exec.Command("launchctl", "bootstrap", "system", path).CombinedOutput(); err != nil {
		// fallback на устаревший load (старые macOS)
		if out2, err2 := exec.Command("launchctl", "load", "-w", path).CombinedOutput(); err2 != nil {
			return fmt.Errorf("launchctl bootstrap: %s; load: %s",
				strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
		}
	}
	return nil
}

// Uninstall снимает службу и удаляет plist. Трей снимается best-effort.
func Uninstall() error {
	_ = UninstallTrayAgent()
	path := plistPath()
	// schg не даёт удалить plist даже root'у: без снятия os.Remove вернул бы EPERM,
	// и /usr/local/bin/RoutineOps-agent остался бы неудаляемым и обычным `rm`. Снимаем флаг и с
	// plist, и с бинаря. Best-effort: реальную причину покажет само удаление.
	_ = tamper.Unlock(path, InstallLayout().BinPath)
	if os.Geteuid() == 0 {
		_ = exec.Command("launchctl", "bootout", "system/"+Name).Run()
		_ = exec.Command("launchctl", "unload", "-w", path).Run()
		// Receipt .pkg: без forget `pkgutil --pkgs` числит агента установленным и
		// после сноса — аналог ARP-записи Windows, которую там снимает msiexec /x.
		// Best-effort: при ручной установке бинарём receipt-а нет («No receipt») —
		// это норма, не сбой снятия службы.
		_ = exec.Command("pkgutil", "--forget", pkgReceiptIdentifier).Run()
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("удаление plist %s: %w", path, err)
	}
	return nil
}

// Harden — no-op: ужесточение DACL службы только для Windows.
func Harden() error { return nil }
