package lock

import (
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeLocker записывает вызовы Show/Hide и хранит последний verify-колбэк, чтобы
// тест мог сымитировать ввод пароля сотрудником. Реализует и reasserter — так
// тесты видят принудительный подъём оверлея на tamper-пути.
type fakeLocker struct {
	mu         sync.Mutex
	shown      bool
	shows      int
	hides      int
	reasserted int
	reason     string
	verify     func(string) bool
}

func (f *fakeLocker) Show(reason string, verify func(string) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shown = true
	f.shows++
	f.reason = reason
	f.verify = verify
}

func (f *fakeLocker) Hide() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shown = false
	f.hides++
}

// Reassert — реализация reasserter: демон просит поднять оверлей немедленно.
func (f *fakeLocker) Reassert() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reasserted++
}

// reasserts — сколько раз просили принудительный подъём (потокобезопасно: на
// tamper-пути Reassert может звать фоновая горутина Manager.Run).
func (f *fakeLocker) reasserts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reasserted
}

func bcryptHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost) // MinCost — быстрее в тестах
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func newMgr(t *testing.T, l Locker) *Manager {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "lock.json"), l, quietLog())
}

// Lock поднимает замок и персистит состояние; Unlock — опускает.
func TestLockUnlockCycle(t *testing.T) {
	fl := &fakeLocker{}
	m := newMgr(t, fl)

	if err := m.Lock("r1", bcryptHash(t, "pw"), "Нарушение ИБ"); err != nil {
		t.Fatal(err)
	}
	if !m.Locked() || !fl.shown {
		t.Fatalf("после Lock ожидали заблокировано+замок поднят: locked=%v shown=%v", m.Locked(), fl.shown)
	}
	if fl.reason != "Нарушение ИБ" {
		t.Fatalf("текст замка не проброшен: %q", fl.reason)
	}
	if m.CurrentRequestID() != "r1" {
		t.Fatalf("request_id = %q", m.CurrentRequestID())
	}

	if err := m.Unlock(); err != nil {
		t.Fatal(err)
	}
	if m.Locked() || fl.shown {
		t.Fatalf("после Unlock ожидали разблокировано+замок снят: locked=%v shown=%v", m.Locked(), fl.shown)
	}
}

// Верный пароль снимает блокировку локально, неверный — нет.
func TestVerifyPassword(t *testing.T) {
	fl := &fakeLocker{}
	m := newMgr(t, fl)
	if err := m.Lock("r1", bcryptHash(t, "s3cret"), "причина"); err != nil {
		t.Fatal(err)
	}

	if fl.verify("wrong") {
		t.Fatal("неверный пароль не должен разблокировать")
	}
	if !m.Locked() {
		t.Fatal("после неверного пароля устройство должно оставаться заблокированным")
	}

	if !fl.verify("s3cret") {
		t.Fatal("верный пароль должен разблокировать")
	}
	if m.Locked() || fl.shown {
		t.Fatalf("после верного пароля ожидали разблокировку: locked=%v shown=%v", m.Locked(), fl.shown)
	}
}

// Состояние блокировки переживает рестарт: новый Manager.Load() поднимает замок.
func TestPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.json")
	hash := bcryptHash(t, "pw")

	m1 := New(path, &fakeLocker{}, quietLog())
	if err := m1.Lock("r1", hash, "увольнение"); err != nil {
		t.Fatal(err)
	}

	fl2 := &fakeLocker{}
	m2 := New(path, fl2, quietLog())
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if !m2.Locked() || !fl2.shown {
		t.Fatalf("после рестарта замок должен подняться: locked=%v shown=%v", m2.Locked(), fl2.shown)
	}
	if !fl2.verify("pw") { // хеш пережил рестарт — оффлайн-разблок работает
		t.Fatal("после рестарта верный пароль должен разблокировать")
	}
	if m2.Locked() {
		t.Fatal("после ввода пароля устройство должно разблокироваться")
	}
}

// Load без файла состояния — не ошибка и не поднимает замок.
func TestLoadNoFile(t *testing.T) {
	fl := &fakeLocker{}
	m := newMgr(t, fl)
	if err := m.Load(); err != nil {
		t.Fatalf("Load без файла не должен падать: %v", err)
	}
	if m.Locked() || fl.shown {
		t.Fatal("без файла состояния устройство не заблокировано")
	}
}

// Повторный Lock с тем же request_id — идемпотентный no-op (не дёргает замок снова).
func TestLockIdempotent(t *testing.T) {
	fl := &fakeLocker{}
	m := newMgr(t, fl)
	hash := bcryptHash(t, "pw")
	if err := m.Lock("r1", hash, "причина"); err != nil {
		t.Fatal(err)
	}
	if err := m.Lock("r1", hash, "причина"); err != nil {
		t.Fatal(err)
	}
	if fl.shows != 1 {
		t.Fatalf("повторная команда той же заявки не должна повторно поднимать замок: shows=%d", fl.shows)
	}
}

// verify на незаблокированном устройстве — true (нечего разблокировать).
func TestVerifyWhenUnlocked(t *testing.T) {
	m := newMgr(t, &fakeLocker{})
	if !m.verify("что угодно") {
		t.Fatal("на незаблокированном устройстве verify должен возвращать true")
	}
}
