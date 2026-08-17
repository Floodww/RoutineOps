package api_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"

	"github.com/Floodww/RoutineOps/internal/server/api"
	"github.com/Floodww/RoutineOps/internal/server/mailer"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"github.com/Floodww/RoutineOps/internal/server/uninstall"
)

// Пути ОТКАЗА createHandler. Счастливый путь и отказы по данным (409/400/403) уже
// покрыты в uninstall_routes_test.go; здесь — то, что происходит, когда ломается
// не запрос, а сама машинерия: база, журнал, очередь.
//
// Эти ветки дешевле всего оставить непроверенными и дороже всего получить в поле:
// каждая срабатывает ровно тогда, когда что-то УЖЕ идёт не так, и ошибка в обработке
// отказа не проявляется до этого момента.

// ownerConn — соединение под ВЛАДЕЛЬЦЕМ тестовой БД (а не под mdm_app, под которым
// ходят тесты). Нужно, чтобы менять права роли приложения: сам mdm_app своих грантов
// не выдаёт и не отбирает.
//
// Владелец во всех трёх раскладках один и тот же (mdm): и у сервиса postgres в CI, и у
// локального compose, и у своего контейнера с trust-аутентификацией. Берём DSN тестовой
// БД и подменяем в нём только пользователя — имя базы там уже уникальное для пакета.
func ownerConn(t *testing.T) *pgx.Conn {
	t.Helper()
	u, err := url.Parse(sharedDSN)
	if err != nil {
		t.Fatalf("разбор DSN: %v", err)
	}
	u.User = url.UserPassword("mdm", "mdm")
	conn, err := pgx.Connect(context.Background(), u.String())
	if err != nil {
		t.Fatalf("подключение владельцем: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// Устройства нет — 500, и задача не заводится.
//
// Код здесь фиксируется как ЕСТЬ, а не как «правильно»: тенант устройства резолвится
// раньше всех проверок, и его отсутствие приходит в общую ветку err != nil. По-хорошему
// это 404, но менять код ответа — отдельное решение, а не побочный эффект теста.
func TestUninstallUnknownDeviceIsInternalError(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterWithUninstall(t, db)
	tok := authToken(t, rtr, db)

	for _, tc := range []struct{ name, id string }{
		{"несуществующий", "00000000-0000-4000-8000-000000000000"},
		{"не uuid", "не-похоже-на-uuid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := authedDo(t, rtr, http.MethodPost, uninstallPath(tc.id),
				uninstallBody(t, "Skype", "skype-id", "тест"), tok)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("код %d, ожидался 500: %s", w.Code, w.Body)
			}
			// Тело не должно нести подробностей БД: 22P02 и имена функций наружу не идут.
			if b := w.Body.String(); b != "internal error\n" {
				t.Errorf("наружу утекла диагностика: %q", b)
			}
		})
	}
}

// 🔴 Отказ журнала обязан ОТМЕНИТЬ удаление, а не только вернуть 500.
//
// Комментарий у самой ветки говорит: «Аудит ДО постановки в очередь и fail-closed:
// удаление ПО — деструктивная операция на живой машине, и она не должна уезжать, если
// запись о ней не сохранилась». Проверяем именно это обещание, а не код ответа: задача
// уже лежит в БД со статусом pending к моменту записи в журнал, а pending-задачи агенту
// раздаёт gateway.Connect по одному лишь статусу. То есть «вернули 500» и «удаление не
// уедет» — РАЗНЫЕ утверждения, и второе не следует из первого само собой.
//
// Отказ журнала вызывается настоящей его причиной — у роли приложения отбирается право
// писать в audit_log. Это та же граница, на которой он падает в бою (права, недоступная
// таблица), а не подсунутая заглушка.
func TestUninstallFailedAuditDoesNotShipTask(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterWithUninstall(t, db)
	tok := authToken(t, rtr, db)
	deviceID, _ := createDevice(t, rtr, tok, "uninstall-audit-fail", "windows")
	markEnrolled(t, db, deviceID, true)
	insertSoftware(t, db, deviceID, "Skype", "skype-id", "msiexec")

	owner := ownerConn(t)
	ctx := context.Background()
	if _, err := owner.Exec(ctx, `REVOKE INSERT ON audit_log FROM mdm_app`); err != nil {
		t.Fatalf("отобрать право на журнал: %v", err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(context.Background(), `GRANT INSERT ON audit_log TO mdm_app`); err != nil {
			t.Fatalf("вернуть право на журнал: %v", err)
		}
	})

	w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID),
		uninstallBody(t, "Skype", "skype-id", "журнал недоступен"), tok)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("отказ журнала: код %d, ожидался 500: %s", w.Code, w.Body)
	}

	// Главная проверка: агенту нечего забрать. Смотрим тем же путём, каким задачи
	// достаются на Connect, — по статусу pending, без оглядки на журнал.
	pending := pendingTaskCount(t, db, deviceID)
	if pending != 0 {
		t.Fatalf("после отказа журнала у устройства осталось %d pending-задач: удаление уедет "+
			"на машину при следующем Connect, а записи о нём не существует", pending)
	}
}

// pendingTaskCount — сколько задач устройство заберёт на следующем Connect.
func pendingTaskCount(t *testing.T, db *storage.DB, deviceID string) int {
	t.Helper()
	ctx, finish, err := db.BindTenant(context.Background(), tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	defer finish(true)
	var n int
	if err := db.Scoped(ctx).QueryRow(ctx,
		`SELECT count(*) FROM tasks WHERE device_id = $1 AND status = 'pending'`, deviceID).Scan(&n); err != nil {
		t.Fatalf("подсчёт pending-задач: %v", err)
	}
	return n
}

// Мёртвая очередь НЕ терминальна: задача уже в БД, её добьёт реконсайлер.
//
// Обратная по смыслу проверка к предыдущей, и обе нужны: отказ журнала обязан отменить
// операцию, отказ очереди — нет. Спутать их легко (оба «внутренняя ошибка после
// создания задачи»), а последствия противоположные: лишняя отмена теряет законное
// удаление, лишний пропуск отправляет неучтённое.
func TestUninstallSurvivesBrokenQueue(t *testing.T) {
	db := newTestDB(t)

	// Клиент указывает в заведомо мёртвый адрес: Enqueue вернёт ошибку соединения.
	dead := asynq.NewClient(asynq.RedisClientOpt{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = dead.Close() })

	svc := uninstall.NewService(db, dead,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	rtr := api.NewRouter(db, nil, []byte("test-secret"), nil, "https://test.local", t.TempDir(),
		mailer.New("", "", "", "", "", false), false, uninstall.Routes(svc))

	tok := authToken(t, rtr, db)
	deviceID, _ := createDevice(t, rtr, tok, "uninstall-dead-queue", "windows")
	markEnrolled(t, db, deviceID, true)
	insertSoftware(t, db, deviceID, "Skype", "skype-id", "msiexec")

	w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID),
		uninstallBody(t, "Skype", "skype-id", "очередь мертва"), tok)
	if w.Code != http.StatusAccepted {
		t.Fatalf("мёртвая очередь: код %d, ожидался 202 — отказ очереди не терминален: %s", w.Code, w.Body)
	}
	if n := pendingTaskCount(t, db, deviceID); n != 1 {
		t.Fatalf("pending-задач %d, ожидалась 1: реконсайлеру нечего будет доставить", n)
	}
}

// Неопознанный отказ БД на поиске цели → 500, а не 409 и не паника.
//
// Свитч по ошибке CreateUninstallTask разбирает четыре именованные причины (нет в
// инвентаре, снять нечем, устройство не active, агент слишком стар) и всё остальное сводит
// в общую ветку `err != nil`. Три первые уже покрыты в uninstall_routes_test.go, а вот
// эта общая ветка — нет: она срабатывает на СЛОМ инфраструктуры (недоступная таблица,
// разорванное соединение), и именно тогда легче всего вернуть не тот код. 409 здесь был бы
// ложью — «обновите инвентарь» не поможет, читать инвентарь нечем; правильный ответ 500.
//
// Отказ вызывается настоящей его причиной — у роли приложения отбирается право читать
// device_software, ту самую таблицу, из которой сервер собирает селектор. Это граница, на
// которой запрос падает в бою, а не подставленная заглушка. ErrAgentTooOld для типа
// uninstall в этот свитч не приходит вовсе: тип намеренно не гейчен по версии агента
// (storage/capability.go), ветка defensive на случай будущего гейта — её проверять здесь
// нечем без подмены хранилища, которую этот код осознанно не заводит.
func TestUninstallGenericStorageErrorIsInternalError(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterWithUninstall(t, db)
	tok := authToken(t, rtr, db)
	deviceID := activeDeviceID(t, rtr, db, tok, "uninstall-broken-inventory")
	insertSoftware(t, db, deviceID, "Skype", "skype-id", "msiexec")

	owner := ownerConn(t)
	ctx := context.Background()
	if _, err := owner.Exec(ctx, `REVOKE SELECT ON device_software FROM mdm_app`); err != nil {
		t.Fatalf("отобрать чтение инвентаря: %v", err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(context.Background(), `GRANT SELECT ON device_software TO mdm_app`); err != nil {
			t.Fatalf("вернуть чтение инвентаря: %v", err)
		}
	})

	w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID),
		uninstallBody(t, "Skype", "skype-id", "инвентарь недоступен"), tok)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("слом БД: код %d, ожидался 500: %s", w.Code, w.Body)
	}
	// Диагностика БД (42501, имя таблицы) наружу не идёт: общая ветка отдаёт голое
	// «internal error», как и остальные 500 этого хендлера.
	if b := w.Body.String(); b != "internal error\n" {
		t.Errorf("наружу утекла диагностика: %q", b)
	}
	// Задача не заведена: отказ случился ДО вставки строки.
	if n := pendingTaskCount(t, db, deviceID); n != 0 {
		t.Fatalf("после слома поиска цели осталось %d pending-задач, ожидался 0", n)
	}
}
