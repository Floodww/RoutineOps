//go:build !linux && !windows && !darwin

package decommission

import "log/slog"

// deregisterPackage — стаб для прочих unix (freebsd и т.п.), где selfdelete_other.go
// его зовёт, но пакетной регистрации dpkg/rpm нет. Linux — реальная реализация в
// pkgcleanup_linux.go. Windows и macOS его НЕ вызывают (selfdelete_windows/_darwin):
// на macOS receipt .pkg снимает service.Uninstall (`pkgutil --forget`), на Windows
// MSI-регистрацию — msiexec /x в bat-делетере.
func deregisterPackage(*slog.Logger) {}
