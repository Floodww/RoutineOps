//go:build !windows && !darwin && !linux

package uninstall

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// execute — заглушка для ОС без поддержки снятия ПО. Отказ ЯВНЫЙ: молчаливый
// «успех» на неподдержанной платформе показал бы оператору снятое ПО, которое
// осталось на месте.
func execute(_ context.Context, _ collector.Software, _ *slog.Logger) (string, error) {
	return "", fmt.Errorf("удаление ПО не поддержано на %s", runtime.GOOS)
}
