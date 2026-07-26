package lock

import (
	"encoding/json"
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

// forgeUnlocked пишет в файл состояния «разблокировано» НАПРЯМУЮ, как это делает
// атакующий: обычным os.WriteFile, минуя любые API пакета (каталог lock.json на
// Windows намеренно user-writable — см. EnsureUserWritableDir). marker — значение
// last_unlocked_hash, которое атакующий может и оставить пустым, и скопировать из
// соседнего поля hash того же файла.
func forgeUnlocked(t *testing.T, path, marker string) {
	t.Helper()
	b, err := json.Marshal(State{Locked: false, LastUnlockedHash: marker})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// assertTamperReasserted — общий контракт tamper-пути: память осталась
// заблокированной, файл пере-утверждён тем же локом, снятие НЕ задурабилено и
// серверу не отчитано.
func assertTamperReasserted(t *testing.T, m *Manager, path, durable, wantHash string) {
	t.Helper()
	if !m.Locked() || m.CurrentHash() != wantHash {
		t.Fatalf("лок должен остаться в силе: locked=%v hash=%q", m.Locked(), m.CurrentHash())
	}
	st, err := ReadState(path)
	if err != nil || !st.Locked || st.Hash != wantHash {
		t.Fatalf("на диске ожидали пере-утверждённый locked, got %+v (err=%v)", st, err)
	}
	if got := m.LastUnlockedHash(); got != "" {
		t.Fatalf("LastUnlockedHash=%q — подделка файла не должна давать durable-подавление пере-запирания", got)
	}
	if durable != "" {
		if _, err := os.Stat(durable); !os.IsNotExist(err) {
			t.Fatalf("durable-файл снятия создан по подделке файла состояния (err=%v)", err)
		}
	}
}

// Находка 1.3: обычный пользователь (без прав, служба НЕ остановлена) пишет одну
// строку {"locked":false} в user-writable lock.json. Пароль при этом нигде не
// сверялся, поэтому снятием это быть не может — демон обязан пере-утвердить лок и
// НЕ писать durable-маркер подавления (иначе подделка переживала бы ребут и
// выключала kill-switch бессрочно).
func TestDetectOfflineUnlock_ForgedEmptyMarkerIsTamper(t *testing.T) {
	fl := &fakeLocker{}
	m, durable := newMgrDurable(t, fl)
	hash := bcryptHash(t, "pw")
	if err := m.Lock("r1", hash, "увольнение"); err != nil {
		t.Fatal(err)
	}

	forgeUnlocked(t, m.path, "")
	m.detectOfflineUnlock()

	assertTamperReasserted(t, m, m.path, durable, hash)
	if !fl.shown {
		t.Fatal("замок опущен по подделке файла состояния")
	}
	if fl.reasserts() == 0 {
		t.Fatal("оверлей не поднят принудительно — он мог закрыться сам, прочитав подделку")
	}
}

// Тот же вектор, но атакующий копирует hash активного лока из соседнего поля того
// же файла в last_unlocked_hash. Ровно этот случай прежняя проверка
// («маркер совпал с текущим hash» = легитимно) пропускала как настоящее снятие:
// bcrypt-хеш не секрет и лежит рядом, так что «доказательство» подделывается
// вместе с самим снятием.
func TestDetectOfflineUnlock_ForgedWithCopiedHashIsTamper(t *testing.T) {
	fl := &fakeLocker{}
	m, durable := newMgrDurable(t, fl)
	hash := bcryptHash(t, "pw")
	if err := m.Lock("r1", hash, "увольнение"); err != nil {
		t.Fatal(err)
	}

	// Атакующий читает файл и копирует hash в маркер — как сделал бы руками.
	st, err := ReadState(m.path)
	if err != nil {
		t.Fatal(err)
	}
	forgeUnlocked(t, m.path, st.Hash)
	m.detectOfflineUnlock()

	assertTamperReasserted(t, m, m.path, durable, hash)
	if !fl.shown {
		t.Fatal("замок опущен по подделке с скопированным hash")
	}
}

// Пока файл всё ещё заблокирован — detectOfflineUnlock ничего не делает.
func TestDetectOfflineUnlock_StillLocked(t *testing.T) {
	fl := &fakeLocker{}
	m := New(filepath.Join(t.TempDir(), "lock.json"), fl, quietLog())
	if err := m.Lock("r1", bcryptHash(t, "pw"), "reason"); err != nil {
		t.Fatal(err)
	}
	m.detectOfflineUnlock()
	if !m.Locked() || fl.reasserts() != 0 {
		t.Fatalf("согласованное состояние не должно ничего трогать: locked=%v reasserts=%d", m.Locked(), fl.reasserts())
	}
}

// Гонка со сменой лока: оверлей, живший под старым H1, затёр файл уже ПОСЛЕ
// применения нового лока H2. Маркер (H1) не совпадает с текущим (H2) —
// пере-утверждаем H2. Ветка была введена вместе с MarkUnlocked и сохраняется как
// частный случай общего правила: файлу не верим ни при каком содержимом.
func TestDetectOfflineUnlock_StaleMarkerReassertsLock(t *testing.T) {
	fl := &fakeLocker{}
	m, durable := newMgrDurable(t, fl)
	oldHash := bcryptHash(t, "old-pw")
	newHash := bcryptHash(t, "new-pw")
	if err := m.Lock("r2", newHash, "эскалация ИБ"); err != nil {
		t.Fatal(err)
	}
	forgeUnlocked(t, m.path, oldHash)

	m.detectOfflineUnlock()

	assertTamperReasserted(t, m, m.path, durable, newHash)
}

// Легитимный путь не должен попадать под tamper-правило: демон сам снял лок
// (запрос с паролем от лок-экрана), память и файл согласованы и разблокированы —
// детектор обязан выйти молча, не пере-запирая устройство обратно.
func TestDetectOfflineUnlock_NoopAfterDaemonUnlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.json")
	fl := &fakeLocker{}
	m := New(path, fl, quietLog())
	m.SetDurableUnlockPath(filepath.Join(t.TempDir(), "lock.last_unlocked"))
	hash := bcryptHash(t, "s3cret")
	if err := m.Lock("r1", hash, "увольнение"); err != nil {
		t.Fatal(err)
	}
	if err := WriteUnlockRequest(dir, "s3cret"); err != nil {
		t.Fatal(err)
	}

	var reported string
	m.processUnlockRequests(func(reqID, _ string) { reported = reqID })
	if reported != "r1" || m.Locked() {
		t.Fatalf("демон должен был снять лок по верному паролю: reported=%q locked=%v", reported, m.Locked())
	}

	m.detectOfflineUnlock()

	if m.Locked() {
		t.Fatal("детектор пере-запер устройство после ЛЕГИТИМНОГО снятия демоном")
	}
	if got := m.LastUnlockedHash(); got != hash {
		t.Fatalf("durable-память снятия = %q, ожидали hash снятого лока (реконсиляция иначе пере-запрёт после ребута)", got)
	}
	if fl.reasserts() != 0 {
		t.Fatal("оверлей поднят после легитимного снятия")
	}
}

// plainLocker — Locker без Reassert: tamper-путь обязан работать и с локером,
// который принудительный подъём не поддерживает (Linux/лог-заглушка).
type plainLocker struct{ shown bool }

func (p *plainLocker) Show(string, func(string) bool) { p.shown = true }
func (p *plainLocker) Hide()                          { p.shown = false }

func TestDetectOfflineUnlock_TamperWithoutReasserter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.json")
	pl := &plainLocker{}
	m := New(path, pl, quietLog())
	hash := bcryptHash(t, "pw")
	if err := m.Lock("r1", hash, "увольнение"); err != nil {
		t.Fatal(err)
	}

	forgeUnlocked(t, path, "")
	m.detectOfflineUnlock()

	assertTamperReasserted(t, m, path, "", hash)
	if !pl.shown {
		t.Fatal("замок опущен по подделке")
	}
}
