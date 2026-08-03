//go:build !enterprise

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/command"
	"github.com/Floodww/RoutineOps/internal/agent/config"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
)

// Open-core-агент: FileVault dynamic-lock + escrow — enterprise-фича. Провайдеры nil →
// executor/reconciler отклоняют lock_mode=FILEVAULT (fail-closed, НЕ тихий overlay),
// escrow не шлётся, age не в графе. Реальная проводка — filevault_wiring.go (enterprise).

// fileVaultRuntime — заглушка типа: в open-core wireFileVaultChain всегда возвращает
// nil, поля не инстанцируются, но обязаны тайп-чекаться. chain реализует обе
// FileVaultRevoker-абстракции (command и lock — идентичный метод RevokeAndShutdown).
type fileVaultRuntime struct {
	chain  command.FileVaultRevoker
	escrow interface {
		FlushPending(ctx context.Context) error
	}
}

func provisionFileVaultAtEnroll(_ *config.Config, _ string, _ *slog.Logger) {}

func wireFileVaultChain(_ *config.Config, _ string, _ *transport.Dialer, _ *slog.Logger) *fileVaultRuntime {
	return nil
}

func runFileVaultProvision(_ *config.Config, _ *slog.Logger) error {
	return errors.New("filevault-provision: enterprise feature not built")
}

// newFileVaultProvisioner — в open-core исполнителя нет, поэтому executor
// отчитывается по задаче ОШИБКОЙ («сборка без поддержки FileVault»), а не молчит.
func newFileVaultProvisioner(_ *config.Config, _ string, _ *transport.Dialer, _ *slog.Logger) command.FileVaultProvisioner {
	return nil
}

// runFileVaultDialog — подкоманды диалога в open-core нет.
func runFileVaultDialog(_, _ string, _ time.Duration) int {
	fmt.Fprintln(os.Stderr, "filevault-dialog: enterprise feature not built")
	return 1
}

// escrowSealerStatus — open-core всегда «выключено».
func escrowSealerStatus(_ *config.Config) (bool, string) {
	return false, "не собрано (enterprise-фича)"
}
