package lock

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Контракт нового пути разблокировки (полевой баг v1.5.3, re-lock): лок-экран
// юзер-сессии не может писать lock.json напрямую (владелец — демон), поэтому
// кладёт запрос через WriteUnlockRequest, а Manager разгребает его через
// processUnlockRequests — так же, как сделал бы verify() при прямом вводе.
func TestProcessUnlockRequests_CorrectPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.json")
	fl := &fakeLocker{}
	m := New(path, fl, quietLog())
	if err := m.Lock("r1", bcryptHash(t, "s3cret"), "причина"); err != nil {
		t.Fatal(err)
	}

	if err := WriteUnlockRequest(dir, "s3cret"); err != nil {
		t.Fatalf("WriteUnlockRequest: %v", err)
	}

	var got string
	m.processUnlockRequests(func(reqID, hash string) { got = reqID })

	if got != "r1" {
		t.Fatalf("onUnlock ожидали с r1, got %q", got)
	}
	if m.Locked() || fl.shown {
		t.Fatalf("после верного пароля ожидали разблокировку: locked=%v shown=%v", m.Locked(), fl.shown)
	}
}

func TestProcessUnlockRequests_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.json")
	m := New(path, &fakeLocker{}, quietLog())
	if err := m.Lock("r1", bcryptHash(t, "s3cret"), "причина"); err != nil {
		t.Fatal(err)
	}

	if err := WriteUnlockRequest(dir, "wrong"); err != nil {
		t.Fatalf("WriteUnlockRequest: %v", err)
	}

	called := false
	m.processUnlockRequests(func(string, string) { called = true })

	if called || !m.Locked() {
		t.Fatalf("неверный пароль не должен снимать блокировку: called=%v locked=%v", called, m.Locked())
	}
}

// Запрос удаляется сразу после чтения — даже неверный пароль не должен
// оставлять файл на диске (replay/накопление).
func TestProcessUnlockRequests_ConsumesRequestFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.json")
	m := New(path, &fakeLocker{}, quietLog())
	if err := m.Lock("r1", bcryptHash(t, "s3cret"), "причина"); err != nil {
		t.Fatal(err)
	}
	if err := WriteUnlockRequest(dir, "wrong"); err != nil {
		t.Fatalf("WriteUnlockRequest: %v", err)
	}

	m.processUnlockRequests(func(string, string) {})

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), unlockRequestPrefix) {
			t.Fatalf("файл запроса %q должен быть удалён после обработки", e.Name())
		}
	}
}

// Без активной блокировки процесс не должен дёргать onUnlock (нет request_id,
// verify() тривиально вернул бы true — колбэк был бы шумным, без смысла).
func TestProcessUnlockRequests_NotLocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.json")
	m := New(path, &fakeLocker{}, quietLog())

	if err := WriteUnlockRequest(dir, "что угодно"); err != nil {
		t.Fatalf("WriteUnlockRequest: %v", err)
	}

	called := false
	m.processUnlockRequests(func(string, string) { called = true })
	if called {
		t.Fatal("на незаблокированном устройстве onUnlock дёргать не должны")
	}
}

// Находка 1.3 через реальную петлю службы: подделка файла состояния при живой
// службе НЕ должна ни снять лок, ни отчитаться серверу об «unlocked» (иначе
// сервер снял бы desired=locked и устройство осталось бы открытым легально).
// Файл обязан вернуться в locked, оверлей — подняться принудительно.
func TestRun_ForgedUnlockIsReassertedAndNotReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.json")
	fl := &fakeLocker{}
	m := New(path, fl, quietLog())
	durable := filepath.Join(t.TempDir(), "lock.last_unlocked")
	m.SetDurableUnlockPath(durable)
	hash := bcryptHash(t, "s3cret")
	if err := m.Lock("r1", hash, "увольнение"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reported := make(chan string, 1)
	go m.Run(ctx, 10*time.Millisecond, func(reqID, _ string) {
		select {
		case reported <- reqID:
		default:
		}
	})

	// Атакующий пишет «разблокировано» напрямую, без пароля.
	forgeUnlocked(t, path, "")

	deadline := time.After(2 * time.Second)
	for {
		st, err := ReadState(path)
		if err == nil && st.Locked && st.Hash == hash {
			break // файл пере-утверждён
		}
		select {
		case <-deadline:
			t.Fatalf("подделка не пере-утверждена за отведённое время: %+v (err=%v)", st, err)
		case <-time.After(10 * time.Millisecond):
		}
	}

	select {
	case reqID := <-reported:
		t.Fatalf("серверу отчитались о снятии %q по подделке файла", reqID)
	default:
	}
	if !m.Locked() {
		t.Fatal("Manager разблокирован подделкой файла")
	}
	if _, err := os.Stat(durable); !os.IsNotExist(err) {
		t.Fatalf("durable-маркер снятия записан по подделке (err=%v)", err)
	}
	if fl.reasserts() == 0 {
		t.Fatal("оверлей не поднят принудительно после подделки")
	}
}

// Run вызывает processUnlockRequests на каждом тике — интеграционная проверка,
// что путь через файл-запрос действительно снимает блокировку в фоне службы.
func TestRun_ProcessesUnlockRequest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.json")
	fl := &fakeLocker{}
	m := New(path, fl, quietLog())
	if err := m.Lock("r1", bcryptHash(t, "s3cret"), "причина"); err != nil {
		t.Fatal(err)
	}
	if err := WriteUnlockRequest(dir, "s3cret"); err != nil {
		t.Fatalf("WriteUnlockRequest: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	unlocked := make(chan string, 1)
	go m.Run(ctx, 20*time.Millisecond, func(reqID, hash string) {
		select {
		case unlocked <- reqID:
		default:
		}
	})

	select {
	case reqID := <-unlocked:
		if reqID != "r1" {
			t.Fatalf("reqID = %q", reqID)
		}
	case <-ctx.Done():
		t.Fatal("Run не обработал запрос на разблокировку за отведённое время")
	}
	if m.Locked() {
		t.Fatal("после обработки запроса устройство должно быть разблокировано")
	}
}
