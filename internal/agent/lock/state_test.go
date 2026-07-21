package lock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Контракт лок-экрана: служба пишет состояние (Manager.Lock), лок-экран читает его
// (ReadState) и после верного пароля снимает (ClearState) — всё через общий файл.
func TestReadStateAndClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.json")
	hash := bcryptHash(t, "pw")

	m := New(path, &fakeLocker{}, quietLog())
	if err := m.Lock("r1", hash, "Увольнение"); err != nil {
		t.Fatal(err)
	}

	st, err := ReadState(path)
	if err != nil {
		t.Fatalf("ReadState: %v", err)
	}
	if !st.Locked || st.Hash != hash || st.Reason != "Увольнение" || st.RequestID != "r1" {
		t.Fatalf("ReadState вернул не то: %+v", st)
	}

	if err := ClearState(path); err != nil {
		t.Fatalf("ClearState: %v", err)
	}
	st2, err := ReadState(path)
	if err != nil {
		t.Fatalf("ReadState после ClearState: %v", err)
	}
	if st2.Locked {
		t.Fatalf("после ClearState ожидали Locked=false, got %+v", st2)
	}
}

// ReadState на отсутствующем файле → os.ErrNotExist (вызывающий трактует как «не заблокировано»).
func TestReadStateNoFile(t *testing.T) {
	_, err := ReadState(filepath.Join(t.TempDir(), "нет.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ожидали ErrNotExist, got %v", err)
	}
}

// DefaultPath даёт непустой путь к lock.json (общий машинный каталог).
func TestDefaultPath(t *testing.T) {
	p := DefaultPath()
	if p == "" || !strings.HasSuffix(p, "lock.json") {
		t.Fatalf("DefaultPath = %q", p)
	}
}

// Служба замечает оффлайн-разблок (лок-экран очистил файл) → колбэк + синхронизация.
func TestDetectOfflineUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.json")
	fl := &fakeLocker{}
	m := New(path, fl, quietLog())
	if err := m.Lock("r1", bcryptHash(t, "pw"), "увольнение"); err != nil {
		t.Fatal(err)
	}

	if err := ClearState(path); err != nil { // имитируем разблок лок-экраном
		t.Fatal(err)
	}
	var got string
	m.detectOfflineUnlock(func(reqID, hash string) { got = reqID })

	if got != "r1" {
		t.Fatalf("onOfflineUnlock ожидали с r1, got %q", got)
	}
	if m.Locked() {
		t.Fatal("после оффлайн-разблока Manager должен быть разблокирован")
	}
	if fl.shown {
		t.Fatal("замок должен быть скрыт после оффлайн-разблока")
	}
}

// Пока файл всё ещё заблокирован — detectOfflineUnlock ничего не делает.
func TestDetectOfflineUnlock_StillLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.json")
	m := New(path, &fakeLocker{}, quietLog())
	if err := m.Lock("r1", bcryptHash(t, "pw"), "reason"); err != nil {
		t.Fatal(err)
	}
	called := false
	m.detectOfflineUnlock(func(string, string) { called = true })
	if called || !m.Locked() {
		t.Fatalf("пока заблокировано, колбэк не дёргаем: called=%v locked=%v", called, m.Locked())
	}
}

// MarkUnlocked (Windows-оверлей) кладёт в файл hash сверенного лока: снятие
// ТЕКУЩЕГО лока легитимно — детект синхронизирует память, зовёт колбэк и
// durable-сохраняет LastUnlockedHash (реконсиляция не пере-запрёт по
// устаревшему desired).
func TestDetectOfflineUnlock_MarkedWithCurrentHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.json")
	fl := &fakeLocker{}
	m := New(path, fl, quietLog())
	hash := bcryptHash(t, "pw")
	if err := m.Lock("r1", hash, "увольнение"); err != nil {
		t.Fatal(err)
	}
	if err := MarkUnlocked(path, hash); err != nil {
		t.Fatal(err)
	}

	var gotReq, gotHash string
	m.detectOfflineUnlock(func(reqID, h string) { gotReq, gotHash = reqID, h })

	if gotReq != "r1" || gotHash != hash {
		t.Fatalf("колбэк ожидали с (r1, hash), got (%q, %q)", gotReq, gotHash)
	}
	if m.Locked() {
		t.Fatal("после легитимного снятия Manager должен быть разблокирован")
	}
	if got := m.LastUnlockedHash(); got != hash {
		t.Fatalf("LastUnlockedHash=%q, ожидали hash снятого лока", got)
	}
	st, err := ReadState(path)
	if err != nil || st.Locked || st.LastUnlockedHash != hash {
		t.Fatalf("на диске ожидали {unlocked, last=hash}, got %+v (err=%v)", st, err)
	}
}

// Гонка со сменой лока: оверлей, живший под старым H1, затёр файл уже ПОСЛЕ
// применения нового лока H2. Маркер в файле (H1) не совпадает с текущим (H2) —
// снятие НЕлегитимно: замок не опускается, колбэк не зовётся, файл
// пере-утверждается текущим locked-состоянием (до фикса демон затирал и память,
// и диск «разблокированным», а в худшем варианте durable-запоминал
// LastUnlockedHash=H2 — kill-switch выключался насовсем).
func TestDetectOfflineUnlock_StaleMarkerReassertsLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.json")
	fl := &fakeLocker{}
	m := New(path, fl, quietLog())
	oldHash := bcryptHash(t, "old-pw")
	newHash := bcryptHash(t, "new-pw")
	if err := m.Lock("r2", newHash, "эскалация ИБ"); err != nil {
		t.Fatal(err)
	}
	// Оверлей сверил пароль СТАРОГО лока и затёр файл своим маркером.
	if err := MarkUnlocked(path, oldHash); err != nil {
		t.Fatal(err)
	}

	called := false
	m.detectOfflineUnlock(func(string, string) { called = true })

	if called {
		t.Fatal("колбэк вызван для снятия устаревшего лока")
	}
	if !m.Locked() || m.CurrentHash() != newHash {
		t.Fatalf("текущий лок H2 должен остаться: locked=%v hash=%q", m.Locked(), m.CurrentHash())
	}
	st, err := ReadState(path)
	if err != nil || !st.Locked || st.Hash != newHash {
		t.Fatalf("на диске ожидали пере-утверждённый locked-H2, got %+v (err=%v)", st, err)
	}
	if got := m.LastUnlockedHash(); got != "" {
		t.Fatalf("LastUnlockedHash=%q — устаревшее снятие не должно запоминаться (реконсиляция бы навсегда пропускала re-lock)", got)
	}
}
