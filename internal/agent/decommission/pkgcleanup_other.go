//go:build !linux && !windows

package decommission

import "log/slog"

// deregisterPackage — вне Linux пакетной регистрации dpkg/rpm нет. На macOS
// аналог (receipt .pkg) снимает service.Uninstall (`pkgutil --forget`) через хук
// StopService; на Windows MSI-регистрацию снимает msiexec /x в bat-делетере.
func deregisterPackage(*slog.Logger) {}
