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

// EnsureSecretDir создаёт каталог приватного материала mTLS с режимом 0700.
//
// Вне Windows режим файла реален, и ключ уже пишется 0600 — каталог закрываем
// того же ради: 0755 позволял бы любому пользователю перечислить содержимое и
// увидеть имена, а на общей машине это лишняя подсказка. Chmod поверх MkdirAll
// нужен потому, что MkdirAll режет режим umask'ом процесса и на уже
// существующем каталоге прав не меняет вовсе.
func EnsureSecretDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
