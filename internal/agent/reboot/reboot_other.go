//go:build !windows && !darwin && !linux

package reboot

import (
	"context"
	"errors"
	"runtime"
	"time"
)

// schedule — заглушка для платформ без поддержки. ЯВНАЯ ошибка, а не тихий
// успех: executor отчитается провалом задачи, оператор увидит причину в панели.
// Тихий возврат nil означал бы «перезагружено» на машине, которая никуда не
// уходила.
func schedule(_ context.Context, _ time.Duration, _ string) (time.Duration, error) {
	return 0, errors.New("перезагрузка не поддерживается на " + runtime.GOOS)
}
