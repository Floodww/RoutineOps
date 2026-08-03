//go:build !windows && !darwin && !linux

package lock

import "log/slog"

// NewPlatformLocker — Locker для службы под текущей ОС. Вне Windows, macOS и Linux
// полноэкранный оверлей не реализован — лог-заглушка (состояние всё равно
// персистится в lock.json). exe не используется.
func NewPlatformLocker(_ string, log *slog.Logger) Locker {
	return NewLogLocker(log)
}
