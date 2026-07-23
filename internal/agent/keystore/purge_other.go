//go:build !darwin && !windows

package keystore

import (
	"fmt"
	"runtime"
)

// Purge — заглушка: защищённого хранилища ОС нет (используется cert-source=file,
// файлы cert/key удаляет план decommission).
func Purge(label, target string) error {
	return fmt.Errorf("keystore: purge хранилища ОС не поддержан для GOOS=%s", runtime.GOOS)
}
