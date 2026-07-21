package service

import "os"

// ProgramDataDir возвращает машинный каталог данных Windows (%ProgramData%) с
// фолбэком C:\ProgramData, когда переменная окружения не выставлена. Единая
// точка правды для всех путей вида ProgramData\RoutineOps — раньше резолв был
// продублирован в lock.go, status.go и log_path.go и мог разъехаться.
// На не-Windows платформах значение смысла не имеет и не используется.
func ProgramDataDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return pd
	}
	return `C:\ProgramData`
}
