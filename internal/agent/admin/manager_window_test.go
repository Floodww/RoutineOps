package admin

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

// Планировщик окон улик внутри Manager: когда окно уходит, когда молчит и что
// именно оно видит. Отдельно закреплён порядок «финальное окно ДО очистки
// состояния» — базовая линия лежит ровно в том файле, который очистка удаляет.

// windowMgr — Manager с активной сессией и подключённым приёмником окон.
func windowMgr(t *testing.T, collect bool) (*Manager, *[]Window) {
	t.Helper()
	priv := newSessPriv()
	m, _, _ := mgr(t, priv, "ivanov", true, approvedResp("req-1", time.Now().Add(time.Hour)))
	m.windowInterval = time.Hour
	m.collectChanges = collect
	var got []Window
	m.sendWindow = func(_ context.Context, w Window) error {
		got = append(got, w)
		return nil
	}
	// Выдаём права: снимается базовая линия, сессия становится живой.
	m.grant(context.Background(), "req-1", time.Now().Add(time.Hour))
	if m.grantedUser != "ivanov" {
		t.Fatalf("подготовка: права не выданы")
	}
	return m, &got
}

// Сервер не просил собирать улики — агент молчит. Это не оптимизация: сбор идёт в
// ту же FIFO-очередь, что ИБ-алерты и статусы лока, и агент новее сервера не
// имеет права её забить записями, которые сервер не умеет принимать.
func TestNoWindowUntilServerAsks(t *testing.T) {
	m, got := windowMgr(t, false)
	m.nextWindowAt = time.Now().Add(-time.Minute) // срок окна давно прошёл

	m.poll(context.Background())
	m.revoke(context.Background(), "тест")

	if len(*got) != 0 {
		t.Fatalf("окна ушли без флага сервера: %+v", *got)
	}
}

// Отправка ещё не подключена (нет proto) — планировщик не падает и не блокирует
// ни выдачу, ни снятие прав.
func TestNoSenderIsNotFatal(t *testing.T) {
	m, _ := windowMgr(t, true)
	m.sendWindow = nil
	m.nextWindowAt = time.Now().Add(-time.Minute)

	m.poll(context.Background())
	m.revoke(context.Background(), "тест")

	if m.grantedUser != "" {
		t.Fatalf("права не сняты: %q", m.grantedUser)
	}
}

func TestIntermediateWindowEmittedWhenDue(t *testing.T) {
	m, got := windowMgr(t, true)
	// Появилось новое ПО и новая служба.
	m.snapshot = func() ([]SoftFP, string, []SvcFP, string) {
		return []SoftFP{{Key: "k1", Name: "Браузер", Version: "141"}, {Key: "k2", Name: "Утилита"}}, "ok",
			[]SvcFP{{Key: "svc", DefHash: "h1"}, {Key: "svc2", DefHash: "h2"}}, "ok"
	}
	m.nextWindowAt = time.Now().Add(-time.Minute)

	m.poll(context.Background())

	if len(*got) != 1 {
		t.Fatalf("окон: got %d, want 1", len(*got))
	}
	w := (*got)[0]
	if w.Final {
		t.Errorf("промежуточное окно помечено финальным")
	}
	if w.Seq != 1 || w.RequestID != "req-1" {
		t.Errorf("нумерация/привязка окна: seq=%d req=%q", w.Seq, w.RequestID)
	}
	if len(w.Changes) != 2 || w.Completeness != CompletenessComplete {
		t.Errorf("дельта окна: %d изменений, полнота %q", len(w.Changes), w.Completeness)
	}
	// Номер и отпечаток сохранены — следующее окно поедет под seq 2.
	st, err := m.store.Load()
	if err != nil || st == nil {
		t.Fatalf("состояние сессии: %+v %v", st, err)
	}
	if st.WindowSeq != 1 || st.LastWindowDigest == "" {
		t.Errorf("номер/отпечаток окна не сохранены: seq=%d digest=%q", st.WindowSeq, st.LastWindowDigest)
	}
	if m.nextWindowAt.Before(time.Now()) {
		t.Errorf("следующее окно не запланировано")
	}
}

// Тихая сессия не должна множить строки улик: то же окно под новым номером не
// добавляет серверу ни одного факта.
func TestIdenticalIntermediateWindowSuppressed(t *testing.T) {
	m, got := windowMgr(t, true)
	m.snapshot = func() ([]SoftFP, string, []SvcFP, string) {
		return []SoftFP{{Key: "k1", Name: "Браузер", Version: "141"}, {Key: "k2", Name: "Утилита"}}, "ok",
			[]SvcFP{{Key: "svc", DefHash: "h1"}}, "ok"
	}

	m.nextWindowAt = time.Now().Add(-time.Minute)
	m.poll(context.Background())
	m.nextWindowAt = time.Now().Add(-time.Minute)
	m.poll(context.Background())

	if len(*got) != 1 {
		t.Fatalf("повтор того же окна ушёл на сервер: %d окон", len(*got))
	}

	// А вот изменившееся окно уходит и получает следующий номер.
	m.snapshot = func() ([]SoftFP, string, []SvcFP, string) {
		return []SoftFP{{Key: "k1", Name: "Браузер", Version: "141"}, {Key: "k2", Name: "Утилита"}, {Key: "k3", Name: "Ещё"}}, "ok",
			[]SvcFP{{Key: "svc", DefHash: "h1"}}, "ok"
	}
	m.nextWindowAt = time.Now().Add(-time.Minute)
	m.poll(context.Background())

	if len(*got) != 2 {
		t.Fatalf("изменившееся окно не ушло: %d окон", len(*got))
	}
	if (*got)[1].Seq != 2 {
		t.Errorf("номер второго окна: got %d, want 2", (*got)[1].Seq)
	}
}

// Финальное окно уходит ВСЕГДА, даже если ничего не изменилось: его отсутствие —
// это отдельное событие «улик нет», и подменять его тишиной нельзя.
func TestFinalWindowSentEvenWhenIdentical(t *testing.T) {
	m, got := windowMgr(t, true)
	m.nextWindowAt = time.Now().Add(-time.Minute)
	m.poll(context.Background()) // первое окно: изменений нет

	m.revoke(context.Background(), "истёк срок прав")

	if len(*got) != 2 {
		t.Fatalf("окон: got %d, want 2 (промежуточное + финальное)", len(*got))
	}
	fin := (*got)[1]
	if !fin.Final {
		t.Errorf("последнее окно не помечено финальным")
	}
	if fin.Completeness != CompletenessComplete {
		t.Errorf("полнота финального окна: %q", fin.Completeness)
	}
}

// ГЛАВНЫЙ ТЕСТ ПОРЯДКА: финальное окно снимается ДО очистки состояния сессии.
// Поменяй местами emitWindow и store.Clear() — и финал уедет пустым с полнотой
// no_baseline, то есть подотчётность потеряется ровно в тот момент, ради которого
// она делалась.
func TestFinalWindowSeesBaselineBeforeClear(t *testing.T) {
	m, got := windowMgr(t, true)
	m.snapshot = func() ([]SoftFP, string, []SvcFP, string) {
		return []SoftFP{{Key: "k1", Name: "Браузер", Version: "141"}, {Key: "hack", Name: "Сомнительное"}}, "ok",
			[]SvcFP{{Key: "svc", DefHash: "h1"}}, "ok"
	}

	m.revoke(context.Background(), "пользователь вышел из системы")

	if len(*got) != 1 {
		t.Fatalf("финальное окно не отправлено")
	}
	w := (*got)[0]
	if w.BaselineLost || w.Completeness != CompletenessComplete {
		t.Fatalf("финал снят уже после очистки состояния: baseline_lost=%v полнота=%q",
			w.BaselineLost, w.Completeness)
	}
	if len(w.Changes) != 1 || w.Changes[0].Subject != "Сомнительное" {
		t.Fatalf("дельта финального окна: %+v", w.Changes)
	}
	// И только после этого состояние действительно очищено.
	st, err := m.store.Load()
	if err != nil || st != nil {
		t.Fatalf("состояние сессии не очищено: %+v %v", st, err)
	}
}

// Неудачная отправка не сжигает номер: сервер отвергает окна, ушедшие вперёд от
// последнего принятого больше чем на 64, а очередь агента бывает недоступна.
func TestSeqNotBurnedOnSendFailure(t *testing.T) {
	m, _ := windowMgr(t, true)
	m.snapshot = func() ([]SoftFP, string, []SvcFP, string) {
		return []SoftFP{{Key: "k1", Name: "Браузер"}, {Key: "k2", Name: "Новое"}}, "ok",
			[]SvcFP{{Key: "svc", DefHash: "h1"}}, "ok"
	}
	fail := true
	var sent []Window
	m.sendWindow = func(_ context.Context, w Window) error {
		if fail {
			return errors.New("очередь недоступна")
		}
		sent = append(sent, w)
		return nil
	}

	m.nextWindowAt = time.Now().Add(-time.Minute)
	m.poll(context.Background())

	st, _ := m.store.Load()
	if st.WindowSeq != 0 || st.LastWindowDigest != "" {
		t.Fatalf("номер сожжён неудачной отправкой: seq=%d digest=%q", st.WindowSeq, st.LastWindowDigest)
	}

	fail = false
	m.nextWindowAt = time.Now().Add(-time.Minute)
	m.poll(context.Background())

	if len(sent) != 1 || sent[0].Seq != 1 {
		t.Fatalf("повторная отправка пошла не под тем номером: %+v", sent)
	}
}

// Без устойчивого состояния окно всё равно доезжает — иначе «улик нет» было бы
// неотличимо от молчания агента.
func TestWindowWithoutDurableStoreStillCarriesRequestID(t *testing.T) {
	priv := newSessPriv()
	m, _, _ := mgr(t, priv, "ivanov", true, approvedResp("req-9", time.Now().Add(time.Hour)))
	m.store = NewSessionStore("/nonexistent-a", "/nonexistent-b") // устойчивость выключена
	m.windowInterval = time.Hour
	m.collectChanges = true
	var got []Window
	m.sendWindow = func(_ context.Context, w Window) error { got = append(got, w); return nil }

	m.poll(context.Background()) // выдача без базовой линии
	m.revoke(context.Background(), "тест")

	if len(got) == 0 {
		t.Fatal("окно не отправлено вовсе — «улик нет» стало молчанием")
	}
	w := got[len(got)-1]
	if w.RequestID != "req-9" {
		t.Errorf("окно не привязано к заявке: %q", w.RequestID)
	}
	if !w.BaselineLost || w.Completeness != CompletenessNoBaseline {
		t.Errorf("окно без базовой линии не помечено: baseline_lost=%v полнота=%q", w.BaselineLost, w.Completeness)
	}
	if len(w.Changes) != 0 {
		t.Errorf("без базовой линии дельта обязана быть пустой: %+v", w.Changes)
	}
}

// Флаги сбора приезжают с сервера и перечитываются каждый поллинг.
func TestPollReadsCollectFlags(t *testing.T) {
	m, _ := windowMgr(t, true)
	m.collectChanges = false
	m.windowInterval = time.Second
	// Сервер, уже умеющий поля контракта: просит собирать и ставит период ниже
	// нижней границы — агент обязан поднять его до неё, а не выполнить буквально.
	m.collectFlags = func(*pb.FetchAdminStatusResponse) (bool, int32) { return true, 10 }

	m.poll(context.Background())

	if !m.collectChanges {
		t.Errorf("флаг сбора не перечитан с сервера: %v", m.collectChanges)
	}
	if m.windowInterval != MinWindowInterval {
		t.Errorf("период окон не перечитан с сервера: %v", m.windowInterval)
	}
}

// Защёлка сбора: решение принимается на выдаче прав и за сессию не пересматривается.
//
// Оператор может щёлкнуть глобальным флагом посреди сессии, и оба направления
// ломают подотчётность, если читать флаг живьём.

// Выключили флаг посреди сессии — улики всё равно доезжают до финала. Иначе
// сессия с уже снятой базовой линией осталась бы без финального окна и на сервере
// выглядела бы РОВНО как дыра: выключатель сам производил бы тот алерт, ради
// которого дыры и ищут.
func TestCollectLatchSurvivesFlagTurnedOffMidSession(t *testing.T) {
	m, got := windowMgr(t, true)
	m.snapshot = func() ([]SoftFP, string, []SvcFP, string) {
		return []SoftFP{{Key: "k1", Name: "Браузер", Version: "141"}, {Key: "new", Name: "Новое"}}, "ok",
			[]SvcFP{{Key: "svc", DefHash: "h1"}}, "ok"
	}
	// Сервер выключил сбор.
	m.collectFlags = func(*pb.FetchAdminStatusResponse) (bool, int32) { return false, 0 }
	m.nextWindowAt = time.Now().Add(-time.Minute)

	m.poll(context.Background())
	if len(*got) != 1 {
		t.Fatalf("промежуточное окно не ушло после выключения флага: %d", len(*got))
	}
	m.revoke(context.Background(), "истёк срок прав")

	if len(*got) != 2 || !(*got)[1].Final {
		t.Fatalf("финальное окно не ушло после выключения флага: %+v", *got)
	}
	if m.collectChanges {
		t.Errorf("живой флаг не перечитан — проверяем не то, что думаем")
	}
}

// Включили флаг посреди сессии — сбор НЕ начинается: базовой линии нет и взять её
// неоткуда, а окна «мы не знаем» на ровном месте создали бы ложную дыру.
func TestCollectLatchIgnoresFlagTurnedOnMidSession(t *testing.T) {
	m, got := windowMgr(t, false) // на t0 сбор выключен
	m.collectFlags = func(*pb.FetchAdminStatusResponse) (bool, int32) { return true, 0 }
	m.nextWindowAt = time.Now().Add(-time.Minute)

	m.poll(context.Background())
	m.revoke(context.Background(), "истёк срок прав")

	if len(*got) != 0 {
		t.Fatalf("сбор начался посреди сессии без базовой линии: %+v", *got)
	}
	if !m.collectChanges {
		t.Errorf("живой флаг не перечитан — проверяем не то, что думаем")
	}
}

// Защёлка переживает рестарт агента: она лежит в состоянии сессии, а не только
// в памяти службы.
func TestCollectLatchRestoredAfterRestart(t *testing.T) {
	m, _ := windowMgr(t, true)
	dir := filepath.Dir(m.store.path)

	// Рестарт: новый Manager на том же каталоге состояния, сервер сбор уже выключил.
	var got []Window
	m2 := &Manager{
		log: quietLog(), priv: newSessPriv(), store: NewSessionStore(dir, dir),
		windowInterval: time.Hour,
		consoleUser:    func() (string, bool) { return "ivanov", true },
		snapshot: func() ([]SoftFP, string, []SvcFP, string) {
			return []SoftFP{{Key: "k1", Name: "Браузер", Version: "141"}, {Key: "new", Name: "Новое"}}, "ok",
				[]SvcFP{{Key: "svc", DefHash: "h1"}}, "ok"
		},
		collectFlags: func(*pb.FetchAdminStatusResponse) (bool, int32) { return false, 0 },
		fetch: func(context.Context) (*pb.FetchAdminStatusResponse, error) {
			return &pb.FetchAdminStatusResponse{}, nil
		},
		report:     func(context.Context, *pb.ReportAdminAccessRequest) error { return nil },
		sendWindow: func(_ context.Context, w Window) error { got = append(got, w); return nil },
	}
	m2.restore()
	if !m2.collectLatched {
		t.Fatal("защёлка сбора не восстановлена с диска")
	}

	// Сервер заявку не подтверждает — права снимаются, финальное окно обязано уйти.
	m2.poll(context.Background())

	if len(got) != 1 || !got[0].Final {
		t.Fatalf("после рестарта финальное окно не ушло: %+v", got)
	}
	if len(got[0].Changes) != 1 {
		t.Fatalf("дельта финального окна после рестарта: %+v", got[0].Changes)
	}
}
