//go:build linux

package lock

import "log/slog"

// NewPlatformLocker — Locker для службы под текущей ОС. На Linux служба сама
// поднимает полноэкранный X11-оверлей в активной графической сессии пользователя
// (см. locker_session_linux.go). exe — путь к бинарю агента (os.Executable).
func NewPlatformLocker(exe string, log *slog.Logger) Locker {
	return NewSessionLocker(exe, log)
}
