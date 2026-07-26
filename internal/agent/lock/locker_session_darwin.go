//go:build darwin

package lock

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// SessionLocker — Locker для macOS-службы: поднимает полноэкранный замок в
// активной сессии пользователя с помощью launchctl asuser.
type SessionLocker struct {
	log *slog.Logger
	exe string // путь к бинарю агента

	mu     sync.Mutex
	cancel context.CancelFunc
	cmd    *exec.Cmd
}

// NewSessionLocker создаёт локер.
func NewSessionLocker(exe string, log *slog.Logger) *SessionLocker {
	return &SessionLocker{exe: exe, log: log}
}

// Show поднимает замок: запускает фоновый цикл, который держит оверлей в активной сессии.
func (l *SessionLocker) Show(reason string, _ func(string) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cancel != nil {
		return // уже поднят
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
// дожидаясь тика ensureLoop (3с) — tamper-путь Manager.detectOfflineUnlock.
// No-op, если замок не поднят или оверлей жив (идемпотентно, как ensureOverlay).
func (l *SessionLocker) Reassert() { l.ensureOverlay() }

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

func (l *SessionLocker) ensureOverlay() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cancel == nil || l.overlayAliveLocked() {
		return
	}

	uid, err := activeConsoleUID()
	if err != nil {
		return // нет сессии — норма
	}

	cmd := exec.Command("launchctl", "asuser", uid, l.exe, "lock-screen")
	if err := cmd.Start(); err != nil {
		l.log.Warn("lock: не удалось поднять оверлей в активной сессии", slog.Any("error", err))
		return
	}

	l.cmd = cmd
	l.log.Info("lock: оверлей запущен службой в активной сессии", slog.String("uid", uid))

	// Очистка при завершении процесса
	go func(c *exec.Cmd) {
		_ = c.Wait()
		l.mu.Lock()
		if l.cmd == c {
			l.cmd = nil
		}
		l.mu.Unlock()
	}(cmd)
}

func (l *SessionLocker) overlayAliveLocked() bool {
	return l.cmd != nil
}

func (l *SessionLocker) terminateOverlayLocked() {
	if l.cmd != nil && l.cmd.Process != nil {
		_ = l.cmd.Process.Kill()
		l.cmd = nil
	}
}

func activeConsoleUID() (string, error) {
	cmd := exec.Command("stat", "-f", "%u", "/dev/console")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	uid := strings.TrimSpace(string(out))
	if uid == "0" {
		return "", errors.New("нет активной консольной сессии") // консоль у root = окно логина
	}
	return uid, nil
}
