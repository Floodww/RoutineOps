package storage_test

import (
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/alerting"
)

// TestCreateAlert_AssignsSeverity: критичность проставляется при вставке, из карты
// alerting, и НЕ зависит от регистра alert_type — gateway кладёт в БД
// strings.ToLower от имени proto-энума, но исторические вызовы шлют верхний.
func TestCreateAlert_AssignsSeverity(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	cases := []struct {
		alertType string
		want      alerting.Severity
	}{
		{"lock_tamper", alerting.SeverityCritical},
		{"FORBIDDEN_SOFTWARE", alerting.SeverityHigh},
		{"unauthorized_install", alerting.SeverityMedium},
		// Тип, которого сервер не знает (агент новее): high, а не тишина.
		{"totally_unknown_event", alerting.SeverityHigh},
	}
	for _, c := range cases {
		d := mustCreateDevice(t, db, fmt.Sprintf("host-sev-%s", uniq(t)), "macos")
		if _, err := db.CreateAlert(ctx, d.ID, c.alertType, `{}`, ""); err != nil {
			t.Fatalf("CreateAlert(%s): %v", c.alertType, err)
		}
		alerts, err := db.ListAlerts(ctx, tenancy.DefaultTenantID, d.ID, 10)
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) != 1 {
			t.Fatalf("%s: ждали 1 алерт, получили %d", c.alertType, len(alerts))
		}
		if alerts[0].Severity != string(c.want) {
			t.Errorf("%s: severity = %q, want %q", c.alertType, alerts[0].Severity, c.want)
		}
	}
}

// TestDetectUnreachable_SeverityLow: алерт, который заводит серверный детектор
// собственным SQL (мимо CreateAlert), тоже обязан получить критичность из карты —
// иначе он лёг бы с DEFAULT 'medium' и оказался важнее реальных нарушений политики.
func TestDetectUnreachableDevices_AssignsSeverity(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	d := mustCreateDevice(t, db, fmt.Sprintf("host-unreach-%s", uniq(t)), "macos")

	if _, err := db.Pool().Exec(ctx,
		`UPDATE devices SET status = 'active', last_seen_at = now() - interval '30 days' WHERE id = $1`, d.ID); err != nil {
		t.Fatalf("подготовка устройства: %v", err)
	}
	if _, err := db.DetectUnreachableDevices(ctx, 10, 0); err != nil {
		t.Fatalf("DetectUnreachableDevices: %v", err)
	}
	alerts, err := db.ListAlerts(ctx, tenancy.DefaultTenantID, d.ID, 10)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("детектор не создал алерт")
	}
	if got, want := alerts[0].Severity, string(alerting.SeverityLow); got != want {
		t.Errorf("agent_unreachable severity = %q, want %q", got, want)
	}
}

// TestListAlerts_OrdersUnackedThenSeverity фиксирует ключевой инвариант сортировки:
// критичность — ВТОРОЙ ключ, после признака принятости. Принятый critical уже
// разобран человеком и не должен вытеснять непринятые из окна LIMIT — иначе
// вернулся бы ровно тот баг, ради которого появилась сортировка по acknowledged_at.
func TestListAlerts_OrdersUnackedThenSeverity(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	d := mustCreateDevice(t, db, fmt.Sprintf("host-order-%s", uniq(t)), "macos")

	// critical, который СРАЗУ принимают.
	if _, err := db.CreateAlert(ctx, d.ID, "lock_tamper", `{"n":1}`, ""); err != nil {
		t.Fatalf("CreateAlert critical: %v", err)
	}
	acked, _ := db.ListAlerts(ctx, tenancy.DefaultTenantID, d.ID, 10)
	if err := db.AcknowledgeAlert(ctx, tenancy.DefaultTenantID, acked[0].ID); err != nil {
		t.Fatalf("AcknowledgeAlert: %v", err)
	}
	// Непринятые low и high.
	if _, err := db.CreateAlert(ctx, d.ID, "agent_unreachable", `{"n":2}`, ""); err != nil {
		t.Fatalf("CreateAlert low: %v", err)
	}
	if _, err := db.CreateAlert(ctx, d.ID, "forbidden_software", `{"n":3}`, ""); err != nil {
		t.Fatalf("CreateAlert high: %v", err)
	}

	got, err := db.ListAlerts(ctx, tenancy.DefaultTenantID, d.ID, 10)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ждали 3 алерта, получили %d", len(got))
	}
	if got[0].AcknowledgedAt != nil || got[1].AcknowledgedAt != nil {
		t.Fatalf("непринятые обязаны идти первыми, порядок: %q(ack=%v) %q(ack=%v) %q(ack=%v)",
			got[0].Severity, got[0].AcknowledgedAt != nil,
			got[1].Severity, got[1].AcknowledgedAt != nil,
			got[2].Severity, got[2].AcknowledgedAt != nil)
	}
	if got[0].Severity != string(alerting.SeverityHigh) || got[1].Severity != string(alerting.SeverityLow) {
		t.Errorf("внутри непринятых ожидали high, затем low; получили %q, %q", got[0].Severity, got[1].Severity)
	}
	if got[2].Severity != string(alerting.SeverityCritical) {
		t.Errorf("принятый critical обязан быть последним, получили %q", got[2].Severity)
	}
}

// TestTakeEscalations проверяет захват напоминаний: порог по критичности, порог по
// возрасту и — главное — что повторный вызов НЕ забирает те же строки снова. Именно
// это отличает эскалацию от бесконечной рассылки одного и того же алерта.
func TestTakeEscalations(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	d := mustCreateDevice(t, db, fmt.Sprintf("host-escal-%s", uniq(t)), "macos")

	if _, err := db.CreateAlert(ctx, d.ID, "lock_tamper", `{"n":1}`, ""); err != nil {
		t.Fatalf("CreateAlert critical: %v", err)
	}
	if _, err := db.CreateAlert(ctx, d.ID, "agent_unreachable", `{"n":2}`, ""); err != nil {
		t.Fatalf("CreateAlert low: %v", err)
	}
	// Состариваем оба: TakeEscalations смотрит на created_at.
	if _, err := db.Pool().Exec(ctx,
		`UPDATE alerts SET created_at = now() - interval '2 hours' WHERE device_id = $1`, d.ID); err != nil {
		t.Fatalf("состаривание алертов: %v", err)
	}

	// repeatMinutes=0 → напомнить ровно один раз.
	due, err := db.TakeEscalations(ctx, "critical", 30, 0)
	if err != nil {
		t.Fatalf("TakeEscalations: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("ждали 1 эскалацию (только critical), получили %d", len(due))
	}
	if due[0].Severity != string(alerting.SeverityCritical) {
		t.Errorf("эскалирован %q, а порог был critical", due[0].Severity)
	}
	// Hostname обязан приезжать: напоминание без имени машины бесполезно.
	if due[0].DeviceHostname == "" {
		t.Error("в эскалации пустой hostname")
	}

	again, err := db.TakeEscalations(ctx, "critical", 30, 0)
	if err != nil {
		t.Fatalf("повторный TakeEscalations: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("повторный вызов забрал %d строк — напоминание уйдёт дважды", len(again))
	}

	// Понижение порога подхватывает low, который в первый раз не прошёл.
	low, err := db.TakeEscalations(ctx, "low", 30, 0)
	if err != nil {
		t.Fatalf("TakeEscalations(low): %v", err)
	}
	if len(low) != 1 || low[0].Severity != string(alerting.SeverityLow) {
		t.Fatalf("ждали 1 low-эскалацию, получили %+v", low)
	}
}

// TestTakeEscalations_RespectsAge: свежий алерт не эскалируется, даже критичный.
func TestTakeEscalations_RespectsAge(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	d := mustCreateDevice(t, db, fmt.Sprintf("host-escfresh-%s", uniq(t)), "macos")

	if _, err := db.CreateAlert(ctx, d.ID, "lock_tamper", `{}`, ""); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}
	due, err := db.TakeEscalations(ctx, "critical", 30, 0)
	if err != nil {
		t.Fatalf("TakeEscalations: %v", err)
	}
	for _, a := range due {
		if a.DeviceID == d.ID {
			t.Fatal("свежий алерт эскалирован раньше порога возраста")
		}
	}
}

// TestTakeEscalations_SkipsAcknowledged: принятый алерт напоминаний не порождает —
// иначе разобранный инцидент продолжал бы будить дежурного.
func TestTakeEscalations_SkipsAcknowledged(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	d := mustCreateDevice(t, db, fmt.Sprintf("host-escack-%s", uniq(t)), "macos")

	if _, err := db.CreateAlert(ctx, d.ID, "lock_tamper", `{}`, ""); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}
	list, _ := db.ListAlerts(ctx, tenancy.DefaultTenantID, d.ID, 10)
	if err := db.AcknowledgeAlert(ctx, tenancy.DefaultTenantID, list[0].ID); err != nil {
		t.Fatalf("AcknowledgeAlert: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`UPDATE alerts SET created_at = now() - interval '2 hours' WHERE device_id = $1`, d.ID); err != nil {
		t.Fatalf("состаривание: %v", err)
	}

	due, err := db.TakeEscalations(ctx, "critical", 30, 0)
	if err != nil {
		t.Fatalf("TakeEscalations: %v", err)
	}
	for _, a := range due {
		if a.DeviceID == d.ID {
			t.Fatal("принятый алерт попал в эскалацию")
		}
	}
}

// TestTakeEscalations_RejectsUnknownSeverity: опечатка в ALERT_ESCALATE_MIN_SEVERITY
// обязана быть громкой ошибкой. Ранг неизвестного значения равен 0, и без явной
// проверки предикат пропустил бы КАЖДЫЙ алерт — то есть опечатка в конфиге
// превратилась бы в рассылку напоминаний по всему парку.
func TestTakeEscalations_RejectsUnknownSeverity(t *testing.T) {
	db := newDB(t)
	if _, err := db.TakeEscalations(tenantCtx(), "sev1", 30, 0); err == nil {
		t.Fatal("неизвестный уровень принят без ошибки")
	}
}

// TestTakeEscalations_DisabledByZero: afterMinutes<=0 выключает эскалацию целиком.
func TestTakeEscalations_DisabledByZero(t *testing.T) {
	db := newDB(t)
	due, err := db.TakeEscalations(tenantCtx(), "critical", 0, 0)
	if err != nil {
		t.Fatalf("TakeEscalations: %v", err)
	}
	if len(due) != 0 {
		t.Errorf("эскалация выключена, но вернулось %d строк", len(due))
	}
}

// TestNotifyMinSeverity_RoundTrip: порог сохраняется и читается, а строка, не
// прошедшая миграцию, читается как 'low' («всё как раньше»), а не как тишина.
func TestNotifyMinSeverity_RoundTrip(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	u := mustCreateUser(t, db, fmt.Sprintf("sev-%s@example.com", uniq(t)))

	got, err := db.GetUserNotifyMinSeverity(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserNotifyMinSeverity: %v", err)
	}
	if got != string(alerting.SeverityLow) {
		t.Errorf("дефолт = %q, want %q — новый админ обязан получать всё, как до 041", got, alerting.SeverityLow)
	}

	if err := db.SetUserNotifyMinSeverity(ctx, u.ID, string(alerting.SeverityCritical)); err != nil {
		t.Fatalf("SetUserNotifyMinSeverity: %v", err)
	}
	got, err = db.GetUserNotifyMinSeverity(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserNotifyMinSeverity после записи: %v", err)
	}
	if got != string(alerting.SeverityCritical) {
		t.Errorf("после записи = %q, want critical", got)
	}
}

// TestGetTelegramRecipients_CarriesThreshold: маршрутизация читает порог вместе с
// chat_id одним запросом — иначе на каждый алерт был бы поход в БД за каждым админом.
func TestGetTelegramRecipients_CarriesThreshold(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	u := mustCreateUser(t, db, fmt.Sprintf("recip-%s@example.com", uniq(t)))

	if _, err := db.Pool().Exec(ctx,
		`UPDATE users SET role = 'it_admin' WHERE id = $1`, u.ID); err != nil {
		t.Fatalf("роль: %v", err)
	}
	chatID := fmt.Sprintf("%d", 900000000+len(u.ID))
	if err := db.SetUserTelegramChatID(ctx, u.ID, chatID); err != nil {
		t.Fatalf("SetUserTelegramChatID: %v", err)
	}
	if err := db.SetUserNotifyMinSeverity(ctx, u.ID, string(alerting.SeverityHigh)); err != nil {
		t.Fatalf("SetUserNotifyMinSeverity: %v", err)
	}

	recipients, err := db.GetTelegramRecipients(ctx)
	if err != nil {
		t.Fatalf("GetTelegramRecipients: %v", err)
	}
	var found bool
	for _, r := range recipients {
		if r.ChatID == chatID {
			found = true
			if r.MinSeverity != string(alerting.SeverityHigh) {
				t.Errorf("порог получателя = %q, want high", r.MinSeverity)
			}
		}
	}
	if !found {
		t.Fatalf("получатель с chat_id %s не найден среди %d", chatID, len(recipients))
	}
}
