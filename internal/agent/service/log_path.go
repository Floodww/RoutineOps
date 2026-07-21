package service

import (
	"path/filepath"
	"runtime"
)

// LogFilePath — путь к файлу лога службы, одинаково вычисляемый при запуске под
// менеджером служб. Служба пишет stderr в никуда (Windows) или в journald (Linux),
// поэтому отдельный файл нужен для диагностики старта и подключения в поле.
// Windows: %ProgramData%\RoutineOps\logs\agent.log (пишет SYSTEM); macOS:
// /Library/Logs/RoutineOps/agent.log; Linux: /var/log/RoutineOps-agent/agent.log — пути выровнены
// с LogDir из InstallLayout (см. layout_darwin.go/layout_linux.go).
func LogFilePath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(ProgramDataDir(), "RoutineOps", "logs", "agent.log")
	case "darwin":
		return filepath.Join("/Library/Logs/RoutineOps", "agent.log")
	default:
		return filepath.Join("/var/log/RoutineOps-agent", "agent.log")
	}
}
