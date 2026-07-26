//go:build windows

package lock

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Floodww/RoutineOps/internal/agent/winsession"
)

// SessionLocker — Locker для Windows-службы: реальный полноэкранный замок рисует
// отдельный процесс `agent lock-screen`, и поднимает его САМА служба в активной
// консольной сессии (CreateProcessAsUser в токене залогиненного пользователя).
// Служба живёт в session 0 без десктопа, поэтому GUI рисовать не может — но как
// LocalSystem имеет право запустить процесс в пользовательской сессии. Это убирает
// зависимость от трея: замок появится, даже если трей не запущен.
//
// Пока заблокировано, фоновый цикл следит, что оверлей жив: нет сессии на момент
// блокировки (никто не вошёл) → поднимем при входе; пользователь убил процесс →
// перезапустим. Идемпотентно: один оверлей за раз (см. overlayAlive).
type SessionLocker struct {
	log *slog.Logger
	exe string // путь к себе (RoutineOps-agent.exe); запускаем "<exe> lock-screen"

	mu     sync.Mutex
	cancel context.CancelFunc
	proc   windows.Handle // хэндл запущенного оверлея (0 = не запущен)
}

// NewSessionLocker создаёт локер. exe — путь к бинарю агента (os.Executable).
func NewSessionLocker(exe string, log *slog.Logger) *SessionLocker {
	return &SessionLocker{exe: exe, log: log}
}

// Show поднимает замок: запускает фоновый цикл, который держит оверлей в активной
// сессии. verify игнорируется — пароль проверяет сам оверлей (bcrypt из lock.json).
func (l *SessionLocker) Show(reason string, _ func(string) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cancel != nil {
		return // уже поднят (идемпотентность)
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	go l.ensureLoop(ctx)
	l.log.Warn("lock: служба поднимает замок в активной сессии", slog.String("reason", reason))
}

// Hide снимает замок: останавливает цикл и завершает процесс оверлея.
func (l *SessionLocker) Hide() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cancel == nil {
		return
	}
	l.cancel()
	l.cancel = nil
	l.terminateOverlayLocked()
	l.log.Warn("lock: замок снят (служба)")
}

// Reassert немедленно проверяет и при необходимости поднимает оверлей, не
// дожидаясь тика ensureLoop (3с). Зовёт tamper-путь Manager.detectOfflineUnlock:
// оверлей, прочитавший подделанный «разблокированный» lock.json, закрывается сам,
// и без этого вызова экран оставался бы открытым до следующего тика надзора.
// No-op, если замок не поднят или оверлей жив (идемпотентно, как ensureOverlay).
func (l *SessionLocker) Reassert() { l.ensureOverlay() }

// ensureLoop держит оверлей запущенным, пока замок активен.
func (l *SessionLocker) ensureLoop(ctx context.Context) {
	l.ensureOverlay()
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.ensureOverlay()
		}
	}
}

// ensureOverlay запускает lock-screen в активной сессии, если он ещё не запущен.
func (l *SessionLocker) ensureOverlay() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cancel == nil || l.overlayAliveLocked() {
		return
	}
	proc, err := winsession.LaunchInActiveSession(l.exe, []string{"lock-screen"})
	if err != nil {
		if !errors.Is(err, winsession.ErrNoActiveSession) {
			l.log.Warn("lock: не удалось поднять оверлей в активной сессии", slog.Any("error", err))
		}
		return // нет сессии — норма, поднимем при входе пользователя
	}
	l.proc = proc
	l.log.Info("lock: оверлей запущен службой в активной сессии")
}

// overlayAliveLocked сообщает, жив ли запущенный процесс оверлея. Вызывать под mu.
func (l *SessionLocker) overlayAliveLocked() bool {
	if l.proc == 0 {
		return false
	}
	if ev, err := windows.WaitForSingleObject(l.proc, 0); err == nil && ev == uint32(windows.WAIT_TIMEOUT) {
		return true // ещё работает
	}
	windows.CloseHandle(l.proc) // завершился — освобождаем хэндл
	l.proc = 0
	return false
}

// terminateOverlayLocked завершает процесс оверлея. Вызывать под mu.
func (l *SessionLocker) terminateOverlayLocked() {
	if l.proc != 0 {
		_ = windows.TerminateProcess(l.proc, 0)
		_ = windows.CloseHandle(l.proc)
		l.proc = 0
	}
}
