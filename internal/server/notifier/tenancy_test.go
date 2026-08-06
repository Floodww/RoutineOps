package notifier

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/alerting"
	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// uniqTenantName — имя тенанта, уникальное в пределах общей тестовой БД пакета.
func uniqTenantName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// twoTenants поднимает два тенанта, в каждом по it_admin'у с привязанным Telegram,
// и отдаёт их контексты вместе с chat_id. Порог доставки обоим ставится low, чтобы
// фильтр критичности не мешал проверять маршрутизацию.
func twoTenants(t *testing.T, db *storage.DB) (ctxA, ctxB context.Context, chatA, chatB string) {
	t.Helper()
	root := context.Background()

	tA, err := db.CreateTenant(root, uniqTenantName("notify-a"))
	if err != nil {
		t.Fatalf("CreateTenant A: %v", err)
	}
	tB, err := db.CreateTenant(root, uniqTenantName("notify-b"))
	if err != nil {
		t.Fatalf("CreateTenant B: %v", err)
	}

	ctxA = storage.WithTenantID(root, tA.ID)
	ctxB = storage.WithTenantID(root, tB.ID)

	// chat_id разведены по диапазонам и содержат наносекунды: подстрока одного не
	// должна случайно найтись в теле сообщения другому.
	now := time.Now().UnixNano() % 1_000_000
	chatA = fmt.Sprintf("81%06d", now)
	chatB = fmt.Sprintf("82%06d", now)

	adminA, err := db.CreateUser(ctxA, tA.ID, "Admin A", uniqEmail("tenant-a"), "hash", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser A: %v", err)
	}
	adminB, err := db.CreateUser(ctxB, tB.ID, "Admin B", uniqEmail("tenant-b"), "hash", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser B: %v", err)
	}
	if err := db.SetUserTelegramChatID(ctxA, adminA.ID, chatA); err != nil {
		t.Fatalf("chat id A: %v", err)
	}
	if err := db.SetUserTelegramChatID(ctxB, adminB.ID, chatB); err != nil {
		t.Fatalf("chat id B: %v", err)
	}
	if err := db.SetUserNotifyMinSeverity(ctxA, adminA.ID, string(alerting.SeverityLow)); err != nil {
		t.Fatalf("порог A: %v", err)
	}
	if err := db.SetUserNotifyMinSeverity(ctxB, adminB.ID, string(alerting.SeverityLow)); err != nil {
		t.Fatalf("порог B: %v", err)
	}
	return ctxA, ctxB, chatA, chatB
}

// Алерт, рождённый в одном тенанте, уходит администраторам ТОЛЬКО этого тенанта.
//
// Проверяются оба направления одним прогоном намеренно: «чужой не получил» в
// одиночку зелёный и при полностью сломанной рассылке, а «свой получил» в одиночку
// не отличает адресную рассылку от веерной.
func TestNotifyAlert_StaysInsideTenant(t *testing.T) {
	db := newDB(t)
	cs := newCaptureServer(t)
	bot := newBot(db, cs.URL)

	ctxA, ctxB, chatA, chatB := twoTenants(t, db)

	bot.NotifyAlert(ctxA, alerting.SeverityCritical, "инцидент на устройстве подразделения A")
	msgs := cs.messages()
	if !containsSub(msgs, chatA) {
		t.Errorf("админ своего тенанта не получил алерт (chat %s), сообщения: %v", chatA, msgs)
	}
	if containsSub(msgs, chatB) {
		t.Errorf("админ ЧУЖОГО тенанта получил алерт (chat %s), сообщения: %v", chatB, msgs)
	}

	// Зеркально: тот же бот, тот же код, другой тенант — иначе проверка выше
	// доказывала бы лишь то, что тенанту B рассылка сломана целиком.
	bot.NotifyAlert(ctxB, alerting.SeverityCritical, "инцидент на устройстве подразделения B")
	after := cs.messages()
	if !containsSub(after[len(msgs):], chatB) {
		t.Errorf("админ тенанта B не получил свой алерт (chat %s), сообщения: %v", chatB, after[len(msgs):])
	}
	if containsSub(after[len(msgs):], chatA) {
		t.Errorf("алерт тенанта B ушёл админу тенанта A (chat %s), сообщения: %v", chatA, after[len(msgs):])
	}
}

// То же для NotifyITAdmins: у него своя выборка получателей, и тенантность в ней
// может разойтись с NotifyAlert независимо.
func TestNotifyITAdmins_StaysInsideTenant(t *testing.T) {
	db := newDB(t)
	cs := newCaptureServer(t)
	bot := newBot(db, cs.URL)

	ctxA, ctxB, chatA, chatB := twoTenants(t, db)

	bot.NotifyITAdmins(ctxA, "заявка на права администратора в подразделении A")
	msgs := cs.messages()
	if !containsSub(msgs, chatA) {
		t.Errorf("админ своего тенанта не получил сообщение (chat %s), сообщения: %v", chatA, msgs)
	}
	if containsSub(msgs, chatB) {
		t.Errorf("админ ЧУЖОГО тенанта получил сообщение (chat %s), сообщения: %v", chatB, msgs)
	}

	bot.NotifyITAdmins(ctxB, "заявка на права администратора в подразделении B")
	after := cs.messages()
	if !containsSub(after[len(msgs):], chatB) {
		t.Errorf("админ тенанта B не получил своё сообщение (chat %s), сообщения: %v", chatB, after[len(msgs):])
	}
	if containsSub(after[len(msgs):], chatA) {
		t.Errorf("сообщение тенанта B ушло админу тенанта A (chat %s), сообщения: %v", chatA, after[len(msgs):])
	}
}

// Контекст без тенанта — отказ, а не веерная рассылка.
//
// Это и есть та самая точка, ради которой обход всех тенантов убран: забытый вызов
// обязан замолчать и оставить след в логе, а не разослать событие одного
// подразделения администраторам всех остальных.
func TestNotify_WithoutTenant_SendsNothing(t *testing.T) {
	db := newDB(t)
	cs := newCaptureServer(t)
	bot := newBot(db, cs.URL)

	ctxA, _, chatA, _ := twoTenants(t, db)

	bot.NotifyAlert(context.Background(), alerting.SeverityCritical, "алерт без скоупа")
	bot.NotifyITAdmins(context.Background(), "сообщение без скоупа")
	if msgs := cs.messages(); len(msgs) != 0 {
		t.Fatalf("непривязанный контекст всё-таки разослал %d сообщений: %v", len(msgs), msgs)
	}

	// Обратная половина: бот и получатели рабочие — молчание выше вызвано именно
	// отсутствием скоупа, а не сломанным ботом или пустой выборкой.
	bot.NotifyAlert(ctxA, alerting.SeverityCritical, "алерт со скоупом")
	if !containsSub(cs.messages(), chatA) {
		t.Fatalf("со скоупом рассылка тоже молчит (chat %s) — тест выше ничего не доказывает: %v",
			chatA, cs.messages())
	}
}

// DetachTenant переносит тенанта в контекст, переживающий запрос, и НЕ тащит с собой
// транзакцию запроса: рассылка обязана открыть свою.
func TestDetachTenant_CarriesTenantNotTx(t *testing.T) {
	db := newDB(t)
	cs := newCaptureServer(t)
	bot := newBot(db, cs.URL)

	ctxA, _, chatA, chatB := twoTenants(t, db)

	// Скоуп «как в хендлере»: настоящая транзакция с выставленным GUC.
	tenantID, _ := storage.TenantIDFrom(ctxA)
	scoped, finish, err := db.BindTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	detached := storage.DetachTenant(scoped)
	// Транзакция хендлера закрывается ДО отправки — ровно как в бою, где гоурутина
	// доходит до базы уже после возврата из хендлера.
	finish(true)

	if _, ok := storage.TxFrom(detached); ok {
		t.Fatal("DetachTenant перенёс транзакцию запроса — она к моменту отправки уже закрыта")
	}
	if id, _ := storage.TenantIDFrom(detached); id != tenantID {
		t.Fatalf("DetachTenant потерял тенанта: %q вместо %q", id, tenantID)
	}

	bot.NotifyAlert(detached, alerting.SeverityCritical, "алерт из detached-гоурутины")
	msgs := cs.messages()
	if !containsSub(msgs, chatA) {
		t.Errorf("рассылка по detached-контексту не дошла (chat %s), сообщения: %v", chatA, msgs)
	}
	if containsSub(msgs, chatB) {
		t.Errorf("рассылка по detached-контексту ушла в чужой тенант (chat %s), сообщения: %v", chatB, msgs)
	}
}
