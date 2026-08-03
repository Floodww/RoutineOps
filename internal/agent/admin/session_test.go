package admin

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

func TestSessionStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := NewSessionStore(dir, dir)
	if !st.Durable() {
		t.Fatal("состояние не устойчиво при совпадающих каталогах")
	}

	if got, err := st.Load(); err != nil || got != nil {
		t.Fatalf("пустой каталог: state=%+v err=%v — отсутствие файла не ошибка", got, err)
	}

	want := &SessionState{
		RequestID: "req-1", User: "ivanov",
		Expires: time.Unix(1750003600, 0), WasAdmin: false,
		GrantedAt: time.Unix(1750000000, 0), BootTime: 1749990000,
		SoftwareHealth: string(collector.HealthOK), ServicesHealth: string(collector.HealthOK),
		Software: []SoftFP{{Key: "k1", Name: "Браузер", Version: "141"}},
		Services: []SvcFP{{Key: "svc", DefHash: "h1", OSOwned: true}},
	}
	if err := st.Save(want); err != nil {
		t.Fatalf("сохранение: %v", err)
	}
	got, err := st.Load()
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if got.RequestID != want.RequestID || got.User != want.User || got.WasAdmin != want.WasAdmin {
		t.Errorf("состояние гранта не сохранилось: %+v", got)
	}
	if len(got.Software) != 1 || got.Software[0].Version != "141" {
		t.Errorf("базовая линия ПО не сохранилась: %+v", got.Software)
	}
	if len(got.Services) != 1 || !got.Services[0].OSOwned {
		t.Errorf("базовая линия служб не сохранилась: %+v", got.Services)
	}
}

// В файле лежит полный список установленного на машине ПО — читать его посторонним
// нельзя. На Windows права проверяет DACL каталога, режим файла там не показателен.
func TestSessionStateFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("на Windows доступ ограничивает DACL каталога, а не режим файла")
	}
	dir := t.TempDir()
	st := NewSessionStore(dir, dir)
	if err := st.Save(&SessionState{RequestID: "r"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "admin-session.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("права файла состояния %#o, want 0600 — список ПО пользователя читал бы кто угодно", perm)
	}
}

// Каталог мимо DataDir выключает устойчивость ЦЕЛИКОМ, а не пишет куда сказали:
// иначе переопределённый оператором флаг унёс бы файл со списком ПО туда, где нет
// admin-only DACL, и подотчётный смог бы подменить собственную базовую линию.
func TestSessionStoreOutsideDataDirIsDisabled(t *testing.T) {
	dataDir := t.TempDir()
	other := t.TempDir()

	st := NewSessionStore(other, dataDir)
	if st.Durable() {
		t.Fatal("каталог вне DataDir не отключил устойчивое состояние")
	}
	if err := st.Save(&SessionState{RequestID: "r"}); err != ErrNoDurableState {
		t.Fatalf("Save вернул %v, want ErrNoDurableState", err)
	}
	if _, err := st.Load(); err != ErrNoDurableState {
		t.Fatalf("Load вернул %v, want ErrNoDurableState", err)
	}
	// Clear обязан молчать: сессия просто не имеет устойчивого состояния.
	if err := st.Clear(); err != nil {
		t.Fatalf("Clear вернул %v", err)
	}
	if entries, _ := os.ReadDir(other); len(entries) != 0 {
		t.Fatalf("в чужой каталог всё-таки писали: %v", entries)
	}
}

func TestSessionStoreEmptyDirsAreDisabled(t *testing.T) {
	for _, c := range []struct{ state, data string }{{"", "/tmp"}, {"/tmp", ""}, {"", ""}} {
		if NewSessionStore(c.state, c.data).Durable() {
			t.Fatalf("пустой путь (%q,%q) не отключил устойчивость", c.state, c.data)
		}
	}
}

func TestSessionStoreClear(t *testing.T) {
	dir := t.TempDir()
	st := NewSessionStore(dir, dir)
	if err := st.Save(&SessionState{RequestID: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got, err := st.Load(); err != nil || got != nil {
		t.Fatalf("после Clear: state=%+v err=%v", got, err)
	}
	// Повторный Clear не должен быть ошибкой: снятие прав вызывается и повторно.
	if err := st.Clear(); err != nil {
		t.Fatalf("повторный Clear: %v", err)
	}
}

func TestSessionStoreBrokenFileReportsError(t *testing.T) {
	// Битый файл не должен молча читаться как «сессии не было»: это разные
	// ситуации, и вторая тихо скрыла бы уже выданные права.
	dir := t.TempDir()
	st := NewSessionStore(dir, dir)
	if err := os.WriteFile(filepath.Join(dir, "admin-session.json"), []byte("{это не json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(); err == nil {
		t.Fatal("битый файл прочитан без ошибки")
	}
}

func TestRebootedDetection(t *testing.T) {
	s := &SessionState{BootTime: 100}
	if s.Rebooted(100) {
		t.Error("тот же boot time признан ребутом")
	}
	if !s.Rebooted(200) {
		t.Error("смена boot time не признана ребутом")
	}
	// Неизвестное значение не даёт утверждать ни то, ни другое: ложный признак
	// ребута объяснял бы фоном изменения, которых фон не делал.
	if s.Rebooted(0) {
		t.Error("нулевой boot time признан ребутом")
	}
	if (&SessionState{}).Rebooted(200) {
		t.Error("отсутствие базового boot time признано ребутом")
	}
	var nilState *SessionState
	if nilState.Rebooted(200) {
		t.Error("nil-состояние признано ребутом")
	}
}

func TestSnapshotSeparatesHealth(t *testing.T) {
	// Пустой список при упавшем сборщике обязан отличаться от честного «ничего нет».
	softOK := func() ([]collector.Software, error) {
		return []collector.Software{{Name: "Браузер", Version: "141", UninstallID: "{GUID}"}}, nil
	}
	softFail := func() ([]collector.Software, error) { return nil, os.ErrPermission }
	svcOK := func() ([]collector.Service, collector.Health) {
		return []collector.Service{{Name: "svc", DefHash: "h"}}, collector.HealthOK
	}
	svcFail := func() ([]collector.Service, collector.Health) { return nil, collector.HealthFailed }

	sw, swH, svc, svcH := Snapshot(softOK, svcOK)
	if len(sw) != 1 || swH != string(collector.HealthOK) || len(svc) != 1 || svcH != string(collector.HealthOK) {
		t.Fatalf("исправный сбор: sw=%d/%s svc=%d/%s", len(sw), swH, len(svc), svcH)
	}
	if sw[0].Key != "{GUID}" {
		t.Errorf("ключ ПО %q, want {GUID} — по нему сходятся снимки", sw[0].Key)
	}

	_, swH, _, svcH = Snapshot(softFail, svcFail)
	if swH != string(collector.HealthFailed) || svcH != string(collector.HealthFailed) {
		t.Fatalf("упавший сбор отдал здоровье sw=%s svc=%s", swH, svcH)
	}
}

func TestSoftwareKeyFallsBackToNameVendor(t *testing.T) {
	// macOS не даёт UninstallID для части приложений. Ключ обязан оставаться
	// устойчивым, иначе каждое обновление читалось бы как удаление и установка.
	withID := collector.Software{Name: "Пакет", Vendor: "ACME", UninstallID: "{GUID}"}
	if got := softwareKey(withID); got != "{GUID}" {
		t.Fatalf("ключ %q, want {GUID}", got)
	}
	a := softwareKey(collector.Software{Name: "Пакет", Vendor: "ACME", Version: "1.0"})
	b := softwareKey(collector.Software{Name: "Пакет", Vendor: "ACME", Version: "2.0"})
	if a != b {
		t.Fatal("ключ зависит от версии — обновление читалось бы как удаление+установка")
	}
	if a == softwareKey(collector.Software{Name: "Пакет", Vendor: "OTHER"}) {
		t.Fatal("ключ не различает вендоров")
	}
}
