// Package status хранит лёгкий снимок состояния агента в файле, который пишет
// служба (под LocalSystem) и читает трей (per-user процесс в сессии пользователя).
// Служба и трей не могут общаться напрямую (session-0 isolation), поэтому обмен
// идёт через файл в общедоступном машинном каталоге (Windows — ProgramData).
//
// Файл НЕ секрет: только версия, device_id, адрес сервера и время последнего
// heartbeat. «Подключённость» трей определяет по свежести LastHeartbeat
// (см. State.Online) — отдельный сигнал disconnect не нужен.
package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/service"
)

// State — снимок состояния агента для трея.
type State struct {
	Version       string    `json:"version"`
	DeviceID      string    `json:"device_id"`
	ServerAddr    string    `json:"server_addr"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}

// Online сообщает, считается ли агент на связи: heartbeat не старше порога
// (обычно 2× интервала heartbeat). Так staleness LastHeartbeat = потеря связи.
func (s State) Online(staleAfter time.Duration) bool {
	return !s.LastHeartbeat.IsZero() && time.Since(s.LastHeartbeat) <= staleAfter
}

// DefaultPath — самостоятельный дефолтный путь к status-файлу (fallback для
// standalone-использования пакета). Основной кросс-процессный путь агент берёт из
// общего каталога службы рядом с lock.json (statusFilePath в cmd/agent): на macOS
// os.TempDir() per-user, поэтому служба-root и трей-юзер по нему разошлись бы.
// Windows: %ProgramData%\RoutineOps\status.json — машинный каталог, общий для всех.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(service.ProgramDataDir(), "RoutineOps", "status.json")
	}
	return filepath.Join(os.TempDir(), "RoutineOps-agent-status.json")
}

// Write атомарно пишет состояние в path (tmp + rename), создавая каталог.
func Write(path string, s State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".status-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName) // не оставляем .tmp-огрызок, как и в ветках выше
		return err
	}
	return nil
}

// Read читает состояние из path.
func Read(path string) (State, error) {
	var s State
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}
