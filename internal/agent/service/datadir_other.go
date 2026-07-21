//go:build !windows

package service

import "os"

// EnsureDataDir создаёт каталог состояния службы. Вне Windows ACL-специфики нет:
// права задаются юниксовым режимом (владелец — root-демон), а раскладка macOS/
// Linux создаёт DataDir сама в relocateForService — сюда попадают только вызовы
// для платформ с Relocate=false.
func EnsureDataDir(dir string) error {
	return os.MkdirAll(dir, 0o755)
}
