package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

// Врезка состояния сессии в Manager. Проверяется то, что раньше ломалось молча:
// временный грант, переживший рестарт агента, и права, слетающие от транзиентного
// отказа пробы консольного пользователя.

type sessPriv struct {
	granted   map[string]bool
	revoked   []string
	isAdmin   bool
	grantErr  error
	revokeErr error
}

func newSessPriv() *sessPriv { return &sessPriv{granted: map[string]bool{}} }

func (f *sessPriv) Grant(user string) error {
	if f.grantErr != nil {
		return f.grantErr
	}
	f.granted[user] = true
	return nil
}

func (f *sessPriv) Revoke(user string) error {
	f.revoked = append(f.revoked, user)
	delete(f.granted, user)
	return f.revokeErr
}

func (f *sessPriv) IsAdmin(user string) (bool, error) { return f.isAdmin || f.granted[user], nil }

// mgr — Manager с подставленными зависимостями и включённым состоянием на диске.
func mgr(t *testing.T, priv PrivilegeManager, user string, probed bool, resp *pb.FetchAdminStatusResponse) (*Manager, *SessionStore, string) {
	t.Helper()
	dir := t.TempDir()
	store := NewSessionStore(dir, dir)
	m := &Manager{
		log:         quietLog(),
		priv:        priv,
		store:       store,
		consoleUser: func() (string, bool) { return user, probed },
		snapshot: func() ([]SoftFP, string, []SvcFP, string) {
			return []SoftFP{{Key: "k1", Name: "Браузер", Version: "141"}}, "ok",
				[]SvcFP{{Key: "svc", DefHash: "h1"}}, "ok"
		},
		bootTime: func() int64 { return 12345 },
		fetch:    func(context.Context) (*pb.FetchAdminStatusResponse, error) { return resp, nil },
		report:   func(context.Context, *pb.ReportAdminAccessRequest) error { return nil },
	}
	return m, store, dir
}

func approvedResp(reqID string, expires time.Time) *pb.FetchAdminStatusResponse {
	var exp int64
	if !expires.IsZero() {
		exp = expires.Unix()
	}
	return &pb.FetchAdminStatusResponse{
		RequestId: reqID,
		Status:    pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED,
		ExpiresAt: exp,
	}
}

func TestGrantPersistsStateBeforeGranting(t *testing.T) {
	priv := newSessPriv()
	m, store, _ := mgr(t, priv, "ivanov", true, approvedResp("req-1", time.Now().Add(time.Hour)))
	m.collectChanges = true // сервер просит собирать улики — базовая линия снимается

	m.poll(context.Background())

	if !priv.granted["ivanov"] {
		t.Fatal("права не выданы")
	}
	st, err := store.Load()
	if err != nil || st == nil {
		t.Fatalf("состояние не записано: %+v %v", st, err)
	}
	if st.RequestID != "req-1" || st.User != "ivanov" || st.WasAdmin {
		t.Errorf("состояние гранта: %+v", st)
	}
	if len(st.Software) != 1 || len(st.Services) != 1 {
		t.Errorf("базовая линия не снята: ПО=%d служб=%d", len(st.Software), len(st.Services))
	}
	if st.BootTime != 12345 {
		t.Errorf("boot time не сохранён: %d", st.BootTime)
	}
}

// Сбор улик выключен сервером — состояние сессии пишется всё равно (иначе грант
// не переживёт рестарт), но срез инвентаря НЕ снимается: обход реестра и каталогов
// на каждой выдаче прав ради данных, которых никто не просил, не бесплатен.
func TestGrantWithoutCollectSkipsBaseline(t *testing.T) {
	priv := newSessPriv()
	m, store, _ := mgr(t, priv, "ivanov", true, approvedResp("req-1", time.Now().Add(time.Hour)))
	snapshots := 0
	m.snapshot = func() ([]SoftFP, string, []SvcFP, string) {
		snapshots++
		return []SoftFP{{Key: "k1"}}, "ok", []SvcFP{{Key: "svc"}}, "ok"
	}
	m.collectChanges = false

	m.poll(context.Background())

	if !priv.granted["ivanov"] {
		t.Fatal("права не выданы")
	}
	if snapshots != 0 {
		t.Errorf("срез инвентаря снят при выключенном сборе: %d раз", snapshots)
	}
	st, err := store.Load()
	if err != nil || st == nil {
		t.Fatalf("состояние сессии не записано: %+v %v", st, err)
	}
	if st.Collect {
		t.Errorf("защёлка сбора взведена при выключенном флаге")
	}
	if len(st.Software) != 0 || len(st.Services) != 0 {
		t.Errorf("базовая линия снята вопреки выключенному сбору: ПО=%d служб=%d",
			len(st.Software), len(st.Services))
	}
}

// Не смогли записать состояние — прав не выдаём. Иначе на машине остаются права,
// о которых после рестарта никто не знает, и снять их будет некому.
func TestGrantRefusedWhenStateUnwritable(t *testing.T) {
	priv := newSessPriv()
	m, store, dir := mgr(t, priv, "ivanov", true, approvedResp("req-1", time.Now().Add(time.Hour)))
	// Каталог запирается тем механизмом, которым он запирается на этой ОС
	// (см. makeUnwritable): CreateTemp внутри Save обязан упасть.
	makeUnwritable(t, dir)
	// Предпосылку проверяем, а не предполагаем: если запись всё равно проходит,
	// тест ничего не проверяет и обязан сказать это вслух, а не зеленеть.
	if f, err := os.CreateTemp(dir, "probe-*"); err == nil {
		f.Close()
		_ = os.Remove(f.Name())
		t.Skip("каталог остался доступным на запись — условие теста не воспроизводится")
	}

	m.poll(context.Background())

	if priv.granted["ivanov"] {
		t.Fatal("права выданы, хотя состояние сессии записать не удалось")
	}
	if m.grantedUser != "" || m.lastReqID != "" {
		t.Errorf("в памяти осталось состояние несостоявшегося гранта: user=%q req=%q", m.grantedUser, m.lastReqID)
	}
	_ = store
}

// Права не выдались на уровне ОС — состояние на диске не должно остаться, иначе
// restore() поднимет сессию, которой не было.
func TestGrantFailureClearsState(t *testing.T) {
	priv := newSessPriv()
	priv.grantErr = errors.New("dseditgroup: отказано")
	m, store, _ := mgr(t, priv, "ivanov", true, approvedResp("req-1", time.Now().Add(time.Hour)))

	m.poll(context.Background())

	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st != nil {
		t.Fatalf("после неудачной выдачи осталось состояние: %+v", st)
	}
}

// Главный из чинимых багов: после рестарта агента временный грант обязан
// сниматься. Раньше состояние жило только в памяти, wasAdmin определялся заново
// по УЖЕ выданному членству и получался true — права не снимались никогда.
func TestRestoreRevokesTemporaryGrantAfterRestart(t *testing.T) {
	priv := newSessPriv()
	m, store, dir := mgr(t, priv, "ivanov", true, approvedResp("req-1", time.Now().Add(time.Hour)))
	m.poll(context.Background())
	if !priv.granted["ivanov"] {
		t.Fatal("подготовка: права не выданы")
	}

	// Рестарт агента: новый Manager с тем же каталогом состояния. Сервер больше
	// не подтверждает заявку (её закрыли, пока агент лежал).
	m2 := &Manager{
		log: quietLog(), priv: priv, store: NewSessionStore(dir, dir),
		consoleUser: func() (string, bool) { return "ivanov", true },
		fetch: func(context.Context) (*pb.FetchAdminStatusResponse, error) {
			return &pb.FetchAdminStatusResponse{}, nil
		},
		report: func(context.Context, *pb.ReportAdminAccessRequest) error { return nil },
	}
	m2.restore()
	if m2.grantedUser != "ivanov" || m2.lastReqID != "req-1" {
		t.Fatalf("сессия не восстановлена: user=%q req=%q", m2.grantedUser, m2.lastReqID)
	}
	if m2.grantedWasAdmin {
		t.Fatal("wasAdmin восстановлен как true — права никогда не снялись бы")
	}

	m2.poll(context.Background())

	if priv.granted["ivanov"] {
		t.Fatal("после рестарта временные права остались выданными")
	}
	if len(priv.revoked) != 1 || priv.revoked[0] != "ivanov" {
		t.Fatalf("Revoke не вызван: %v", priv.revoked)
	}
	if st, _ := store.Load(); st != nil {
		t.Fatalf("состояние не очищено после снятия: %+v", st)
	}
}

// Обратная сторона того же: пользователь БЫЛ админом до гранта — его собственные
// права не наши, и после рестарта их тоже нельзя снимать.
func TestRestoreKeepsPreexistingAdmin(t *testing.T) {
	priv := newSessPriv()
	priv.isAdmin = true
	m, _, dir := mgr(t, priv, "petrov", true, approvedResp("req-2", time.Now().Add(time.Hour)))
	m.poll(context.Background())

	m2 := &Manager{
		log: quietLog(), priv: priv, store: NewSessionStore(dir, dir),
		consoleUser: func() (string, bool) { return "petrov", true },
		fetch: func(context.Context) (*pb.FetchAdminStatusResponse, error) {
			return &pb.FetchAdminStatusResponse{}, nil
		},
		report: func(context.Context, *pb.ReportAdminAccessRequest) error { return nil },
	}
	m2.restore()
	if !m2.grantedWasAdmin {
		t.Fatal("wasAdmin не восстановлен — собственные права администратора сняли бы")
	}
	m2.poll(context.Background())
	if len(priv.revoked) != 0 {
		t.Fatalf("сняли собственные права пользователя: %v", priv.revoked)
	}
}

// Транзиентный отказ пробы — «не знаю», а не «вышел». Раньше это снимало права
// посреди работы и записывало в журнал ложную причину.
func TestUnprobedConsoleUserKeepsRights(t *testing.T) {
	priv := newSessPriv()
	m, _, _ := mgr(t, priv, "ivanov", true, approvedResp("req-1", time.Now().Add(time.Hour)))
	m.poll(context.Background())
	if !priv.granted["ivanov"] {
		t.Fatal("подготовка: права не выданы")
	}

	m.consoleUser = func() (string, bool) { return "", false } // проба не отработала
	m.poll(context.Background())

	if !priv.granted["ivanov"] {
		t.Fatal("права сняты по неудачной пробе консольного пользователя")
	}
	if len(priv.revoked) != 0 {
		t.Fatalf("Revoke вызван при неизвестном пользователе: %v", priv.revoked)
	}
}

// А настоящий логаут (проба отработала и показала, что никого нет) обязан снимать
// права — иначе бессрочная заявка, которая живёт «до логаута», станет вечной.
func TestProbedLogoutRevokesRights(t *testing.T) {
	priv := newSessPriv()
	m, _, _ := mgr(t, priv, "ivanov", true, approvedResp("req-1", time.Time{})) // бессрочная
	m.poll(context.Background())
	if !priv.granted["ivanov"] {
		t.Fatal("подготовка: права не выданы")
	}

	m.consoleUser = func() (string, bool) { return "", true } // успешная проба: никого
	m.poll(context.Background())

	if priv.granted["ivanov"] {
		t.Fatal("после логаута права остались — бессрочный грант стал вечным")
	}
}

// Срок действия не зависит от того, определился ли пользователь: истёкшие права
// снимаются даже при неработающей пробе.
func TestExpiryRevokesEvenWhenUserUnknown(t *testing.T) {
	priv := newSessPriv()
	// Срок заявки заведомо не истекает сам: истечение навязывается ниже явным
	// сдвигом grantedExpires. Короткий реальный таймаут делал бы тест флейки —
	// при групповом прогоне он успевал истечь ещё до выдачи прав.
	m, _, _ := mgr(t, priv, "ivanov", true, approvedResp("req-1", time.Now().Add(time.Hour)))
	m.poll(context.Background())
	if !priv.granted["ivanov"] {
		t.Fatal("подготовка: права не выданы")
	}

	m.grantedExpires = time.Now().Add(-time.Second) // срок вышел
	m.consoleUser = func() (string, bool) { return "", false }
	m.poll(context.Background())

	if priv.granted["ivanov"] {
		t.Fatal("истёкшие права не сняты из-за неопределённого пользователя")
	}
}

// Проба не отработала в момент выдачи — грант откладывается, а не выдаётся
// «кому-то». Заявка никуда не денется и приедет на следующем тике.
func TestGrantDeferredWhenUserUnprobed(t *testing.T) {
	priv := newSessPriv()
	m, store, _ := mgr(t, priv, "", false, approvedResp("req-1", time.Now().Add(time.Hour)))

	m.poll(context.Background())

	if len(priv.granted) != 0 {
		t.Fatalf("права выданы при неопределённом пользователе: %v", priv.granted)
	}
	if st, _ := store.Load(); st != nil {
		t.Fatalf("записано состояние сессии, которой не было: %+v", st)
	}
	if m.lastReqID != "" {
		t.Errorf("заявка помечена обработанной (%q) — повторной попытки не будет", m.lastReqID)
	}
}

// Без устойчивого состояния (dev-запуск, каталог мимо DataDir) выдача продолжает
// работать: иначе фича прав ломалась бы на всех нештатных раскладках.
func TestGrantWorksWithoutDurableStore(t *testing.T) {
	priv := newSessPriv()
	dir := t.TempDir()
	m := &Manager{
		log: quietLog(), priv: priv,
		store:       NewSessionStore(filepath.Join(dir, "чужой"), dir), // не совпадает → выключено
		consoleUser: func() (string, bool) { return "ivanov", true },
		fetch: func(context.Context) (*pb.FetchAdminStatusResponse, error) {
			return approvedResp("req-1", time.Now().Add(time.Hour)), nil
		},
		report: func(context.Context, *pb.ReportAdminAccessRequest) error { return nil },
	}
	m.poll(context.Background())
	if !priv.granted["ivanov"] {
		t.Fatal("без устойчивого состояния права не выданы")
	}
}
