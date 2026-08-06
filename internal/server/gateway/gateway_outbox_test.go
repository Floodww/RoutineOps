package gateway_test

import (
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"strings"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/alerting"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	pb "github.com/Floodww/RoutineOps/proto"
)

// outboxAlerts возвращает только алерты про мёртвую очередь: в этих тестах устройство
// чистое, но фильтр всё равно явный — иначе тест начал бы врать, как только рядом
// появится ещё один источник алертов.
func outboxAlerts(t *testing.T, db *storage.DB, deviceID string) []storage.Alert {
	t.Helper()
	all, err := db.ListAlerts(tenantCtx(), tenancy.DefaultTenantID, deviceID, 100)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	var out []storage.Alert
	for _, a := range all {
		if a.AlertType == "outbox_unavailable" {
			out = append(out, a)
		}
	}
	return out
}

func deviceByFP(t *testing.T, db *storage.DB, fp string) *storage.Device {
	t.Helper()
	id, err := db.GetDeviceIDByFingerprint(tenantCtx(), fp)
	if err != nil || id == "" {
		t.Fatalf("device by fingerprint: id=%q err=%v", id, err)
	}
	d, _, err := db.GetDevice(tenantCtx(), tenancy.DefaultTenantID, id)
	if err != nil || d == nil {
		t.Fatalf("GetDevice: %v", err)
	}
	return d
}

// Алерт — на ПЕРЕХОД, а не на каждый кадр: признак приезжает в каждом heartbeat, то
// есть раз в 30 секунд, и алерт на кадр залил бы панель ИБ с одной сломанной машины.
//
// Причины у кадров РАЗНЫЕ намеренно. С одинаковыми тест был бы ложно-зелёным: дедуп
// внутри CreateAlert (device+type+details+непринятый) подавил бы второй алерт даже
// если бы детекции перехода не существовало вовсе, и проверялся бы дедуп, а не она.
func TestConnect_OutboxDown_AlertsOnEdgeNotEveryBeat(t *testing.T) {
	db := newDB(t)
	bot := &MockNotifier{}
	gw := newGWWithBot(t, db, bot)

	ctx, fp := makeCertCtx(t, "outbox-edge")
	stream := &mockStream{
		ctx: ctx,
		msgs: []*pb.HeartbeatRequest{
			{IpAddress: "192.0.2.10", OutboxUnavailable: true, DegradedDetail: "открыть outbox: отказано в доступе"},
			{IpAddress: "192.0.2.10", OutboxUnavailable: true, DegradedDetail: "запись в outbox: устройство переполнено"},
		},
	}
	if err := gw.Connect(stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	d := deviceByFP(t, db, fp)
	if !d.OutboxUnavailable {
		t.Error("флаг деградации не доехал до карточки устройства")
	}
	// Причина — от ПОСЛЕДНЕГО кадра: оператору нужна текущая ошибка, а не первая.
	if d.DegradedDetail != "запись в outbox: устройство переполнено" {
		t.Errorf("degraded_detail = %q, ожидалась причина последнего кадра", d.DegradedDetail)
	}
	if d.DegradedSince == nil {
		t.Error("degraded_since пуст — «сколько уже молчит» ответить нечем")
	}

	if got := outboxAlerts(t, db, d.ID); len(got) != 1 {
		t.Fatalf("алертов %d, ожидался ровно 1 (на переход, не на кадр)", len(got))
	}
}

// Флаг снялся — состояние устройства обязано очиститься само, без вмешательства
// оператора: агент гасит признак ближайшим успешным сливом очереди. Строка в alerts
// при этом ОСТАЁТСЯ: то, что очередь ожила, не значит, что за время слепоты на машине
// ничего не произошло, и закрывает алерт человек.
func TestConnect_OutboxRecovers_ClearsDeviceStateKeepsAlert(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fp := makeCertCtx(t, "outbox-recover")
	stream := &mockStream{
		ctx: ctx,
		msgs: []*pb.HeartbeatRequest{
			{IpAddress: "192.0.2.11", OutboxUnavailable: true, DegradedDetail: "открыть outbox: отказано в доступе"},
			{IpAddress: "192.0.2.11"},
		},
	}
	if err := gw.Connect(stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	d := deviceByFP(t, db, fp)
	if d.OutboxUnavailable {
		t.Error("флаг не снялся при живой очереди — устройство навсегда осталось бы «слепым»")
	}
	if d.DegradedDetail != "" {
		t.Errorf("degraded_detail = %q — в карточке висит причина позавчерашнего сбоя", d.DegradedDetail)
	}
	if d.DegradedSince != nil {
		t.Error("degraded_since не сброшен — панель показывала бы деградацию у здоровой машины")
	}
	if got := outboxAlerts(t, db, d.ID); len(got) != 1 {
		t.Errorf("алертов %d, ожидался 1: восстановление не стирает историю", len(got))
	}
}

// Реконнект — это норма (сеть, рестарт службы), а не новое событие. Проверяем обе
// стороны: «лежит с» не перезапускается, и повторный алерт не создаётся (детекция
// перехода живёт в памяти стрима, и на новом стриме её подстраховывает дедуп).
func TestConnect_OutboxDown_SinceStickyAcrossReconnect(t *testing.T) {
	db := newDB(t)
	gw := newGW(t, db)

	ctx, fp := makeCertCtx(t, "outbox-reconnect")
	beat := func() {
		s := &mockStream{
			ctx:  ctx,
			msgs: []*pb.HeartbeatRequest{{IpAddress: "192.0.2.12", OutboxUnavailable: true, DegradedDetail: "открыть outbox: отказано в доступе"}},
		}
		if err := gw.Connect(s); err != nil {
			t.Fatalf("Connect: %v", err)
		}
	}

	beat()
	first := deviceByFP(t, db, fp)
	if first.DegradedSince == nil {
		t.Fatal("degraded_since пуст после первого кадра")
	}

	beat()
	second := deviceByFP(t, db, fp)
	if second.DegradedSince == nil || !second.DegradedSince.Equal(*first.DegradedSince) {
		t.Errorf("degraded_since сдвинулся на реконнекте (%v → %v) — «лежит с» стало дублем last_seen_at",
			first.DegradedSince, second.DegradedSince)
	}
	if got := outboxAlerts(t, db, second.ID); len(got) != 1 {
		t.Errorf("алертов %d, ожидался 1: реконнект не событие", len(got))
	}
}

// Уведомление IT уходит один раз и говорит главное: тишина с этой машины больше не
// означает, что на ней всё спокойно. Проверяем именно смысл, а не факт отправки —
// сообщение «агент деградировал» без этого объяснения оператор проигнорирует.
func TestConnect_OutboxDown_NotifiesITOnce(t *testing.T) {
	db := newDB(t)
	bot := newMockNotifier()
	gw := newGWWithBot(t, db, bot)

	ctx, _ := makeCertCtx(t, "outbox-notify")
	stream := &mockStream{
		ctx: ctx,
		msgs: []*pb.HeartbeatRequest{
			{IpAddress: "192.0.2.13", OutboxUnavailable: true, DegradedDetail: "открыть outbox: отказано в доступе"},
			{IpAddress: "192.0.2.13", OutboxUnavailable: true, DegradedDetail: "открыть outbox: отказано в доступе"},
		},
	}
	if err := gw.Connect(stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	select {
	case <-bot.notified:
	case <-time.After(time.Second):
		t.Fatal("уведомление IT не ушло")
	}

	bot.mu.Lock()
	defer bot.mu.Unlock()
	if len(bot.Messages) != 1 {
		t.Fatalf("уведомлений %d, ожидалось 1", len(bot.Messages))
	}
	if !strings.Contains(bot.Messages[0], "outbox-notify") {
		t.Errorf("в уведомлении нет имени устройства: %q", bot.Messages[0])
	}
	if !strings.Contains(bot.Messages[0], "отказано в доступе") {
		t.Errorf("в уведомлении нет причины: %q", bot.Messages[0])
	}
	// Порог доставки: через NotifyAlert с severity high, не мимо NotifyITAdmins.
	if len(bot.Severities) != 1 || bot.Severities[0] != alerting.SeverityHigh {
		t.Fatalf("severity = %v, want [high] — иначе порог users.notify_min_severity обойдён", bot.Severities)
	}
}
