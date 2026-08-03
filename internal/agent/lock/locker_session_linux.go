//go:build linux

package lock

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// SessionLocker — Locker для Linux-службы: держит полноэкранный замок в активной
// графической сессии пользователя. Служба живёт вне сессии (у неё нет ни DISPLAY, ни
// куки X-доступа), поэтому окно рисует отдельный процесс `agent lock-screen`,
// запущенный ОТ ИМЕНИ пользователя сессии с её окружением.
//
// Устройство SessionLocker намеренно повторяет macOS-вариант (см. locker_session_darwin.go):
// цикл раз в 3 секунды поднимает оверлей, если тот умер или сессия появилась позже
// команды блокировки. Отличается только способ найти сессию (systemd-logind вместо
// /dev/console) и необходимость сменить пользователя у дочернего процесса.
type SessionLocker struct {
	log *slog.Logger
	exe string // путь к бинарю агента

	mu        sync.Mutex
	cancel    context.CancelFunc
	cmd       *exec.Cmd
	statePath string // путь lock.json; передаём дочернему процессу явным флагом

	// warned — о каком бэкенде уже сказали в лог. Цикл тикает раз в 3 секунды, и без
	// этого поля Wayland-машина писала бы 1200 одинаковых строк в час.
	warned Backend
}

// NewSessionLocker создаёт локер.
func NewSessionLocker(exe string, log *slog.Logger) *SessionLocker {
	return &SessionLocker{exe: exe, log: log}
}

// SetStatePath принимает путь файла состояния от Manager (см. lock.New).
func (l *SessionLocker) SetStatePath(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.statePath = path
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
	l.warned = ""
	l.terminateOverlayLocked()
	l.log.Warn("lock: замок снят (служба)")
}

// Reassert немедленно проверяет и при необходимости поднимает оверлей, не дожидаясь
// тика цикла — tamper-путь Manager.detectOfflineUnlock.
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
	if l.cancel == nil || l.cmd != nil {
		return
	}

	sess, ok := DiscoverGraphicalSession()
	if !ok {
		return // никто не залогинен в графику — норма, ждём следующего тика
	}
	env := ReadSessionEnv(sess)
	if b := SessionBackend(sess, env); b != BackendX11 {
		l.warnBackendLocked(b, sess)
		return
	}
	l.warned = ""

	args := []string{"lock-screen"}
	// Флаг добавляем только для абсолютного пути: относительный в чужой сессии
	// разрешится от другого рабочего каталога и уведёт замок не туда.
	if filepath.IsAbs(l.statePath) {
		args = append(args, "-lock-state", l.statePath)
	}
	cmd := exec.Command(l.exe, args...)
	cmd.Env = OverlayEnv(sess, env)
	attr := &syscall.SysProcAttr{Setsid: true}
	// Меняем пользователя, только если сами root: под обычной учёткой setuid не
	// разрешён, и попытка дала бы «operation not permitted» вместо замка. Когда uid
	// совпадает (dev-запуск от того же пользователя), смена и не нужна.
	if os.Geteuid() == 0 && os.Geteuid() != sess.UID {
		gid, err := primaryGID(sess.UID)
		if err != nil {
			l.log.Warn("lock: не удалось определить группу пользователя сессии",
				slog.Int("uid", sess.UID), slog.Any("error", err))
			return
		}
		attr.Credential = &syscall.Credential{Uid: uint32(sess.UID), Gid: uint32(gid)}
	}
	cmd.SysProcAttr = attr

	if err := cmd.Start(); err != nil {
		l.log.Warn("lock: не удалось поднять оверлей в активной сессии", slog.Any("error", err))
		return
	}
	l.cmd = cmd
	l.log.Info("lock: оверлей запущен службой в активной сессии",
		slog.String("session", sess.ID), slog.String("user", sess.User))

	go func(c *exec.Cmd) {
		_ = c.Wait()
		l.mu.Lock()
		if l.cmd == c {
			l.cmd = nil
		}
		l.mu.Unlock()
	}(cmd)
}

// warnBackendLocked говорит про невозможность показать замок ОДИН раз на бэкенд.
// Молчать здесь нельзя: устройство числится заблокированным, а экран у сотрудника
// чистый — расхождение обязано быть видно в логе, когда за ним придут.
func (l *SessionLocker) warnBackendLocked(b Backend, s SessionInfo) {
	if l.warned == b {
		return
	}
	l.warned = b
	l.log.Error("lock: графический замок в этой сессии показать нельзя",
		slog.String("backend", string(b)),
		slog.String("session_type", s.Type),
		slog.String("user", s.User),
		slog.String("подробности", "оверлей реализован только для X11, см. docs/lock-linux.md"))
}

func (l *SessionLocker) terminateOverlayLocked() {
	if l.cmd != nil && l.cmd.Process != nil {
		_ = l.cmd.Process.Kill()
		l.cmd = nil
	}
}

// DiscoverGraphicalSession спрашивает у systemd-logind активные сессии и выбирает ту,
// где имеет смысл показывать замок.
func DiscoverGraphicalSession() (SessionInfo, bool) {
	out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		return SessionInfo{}, false
	}
	var sessions []SessionInfo
	for _, id := range ParseSessionIDs(out) {
		props, err := exec.Command("loginctl", "show-session", id,
			"-p", "Active", "-p", "State", "-p", "Type", "-p", "Remote",
			"-p", "User", "-p", "Name", "-p", "Leader", "-p", "Display").Output()
		if err != nil {
			continue
		}
		sessions = append(sessions, SessionFromProperties(id, ParseSessionProperties(props)))
	}
	return PickGraphicalSession(sessions)
}

// ReadSessionEnv читает окружение лидера сессии. Ошибку не поднимаем: без него
// OverlayEnv соберёт окружение из свойств logind и умолчаний — хуже, но рабоче.
func ReadSessionEnv(s SessionInfo) map[string]string {
	if s.Leader <= 0 {
		return nil
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(s.Leader) + "/environ")
	if err != nil {
		return nil
	}
	return ParseProcEnviron(b)
}

func primaryGID(uid int) (int, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Gid)
}
