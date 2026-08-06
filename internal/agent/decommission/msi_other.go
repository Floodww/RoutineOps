//go:build !windows

package decommission

import (
	"context"
	"log/slog"
)

// unregisterMSI вне Windows — no-op: MSI существует только там. Стаб нужен, чтобы
// диспетчер подкоманд в cmd/agent оставался полностью тег-фри (как и для
// service.StopUserProcesses / deregisterPackage), а `agent msi-unregister` на
// macOS/Linux честно печатал «нечего снимать» вместо «неизвестная команда».
func unregisterMSI(_ context.Context, log *slog.Logger) (MSIUnregisterResult, error) {
	log.Info("msi-unregister: MSI существует только на Windows — на этой ОС снимать нечего")
	return MSIUnregisterResult{}, nil
}
