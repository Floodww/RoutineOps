package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Очередь энроллмента — входная дверь в парк: пока устройство в ней, оно ничего не
// исполняет, а после одобрения получает всё. До этих тестов ни одна ручка очереди
// (approve/reject, поштучно и пачкой) не была покрыта вовсе.

// queueDevice заводит устройство и ставит ему статус очереди.
//
// CreatePendingDevice кладёт 'pending' — это ДРУГОЙ статус: в очередь на одобрение
// устройство попадает при энроллменте, а здесь нужен именно он, потому что все четыре
// ручки гардированы точным сравнением status = 'pending_approval'.
func queueDevice(t *testing.T, db *storage.DB, tenantID, hostname string) string {
	t.Helper()
	ctx := context.Background()
	dev, err := db.CreatePendingDevice(ctx, tenantID, hostname, "linux")
	if err != nil {
		t.Fatalf("CreatePendingDevice: %v", err)
	}
	setDeviceStatus(t, db, tenantID, dev.ID, "pending_approval")
	return dev.ID
}

func setDeviceStatus(t *testing.T, db *storage.DB, tenantID, deviceID, status string) {
	t.Helper()
	ctx := context.Background()
	scoped, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("bind %s: %v", tenantID, err)
	}
	defer finish(true)
	if _, err := db.Q(scoped).Exec(scoped,
		`UPDATE devices SET status = $2 WHERE id = $1`, deviceID, status); err != nil {
		t.Fatalf("статус устройства %s: %v", deviceID, err)
	}
}

func deviceStatus(t *testing.T, db *storage.DB, tenantID, deviceID string) string {
	t.Helper()
	ctx := context.Background()
	scoped, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("bind %s: %v", tenantID, err)
	}
	defer finish(true)
	var status string
	if err := db.Q(scoped).QueryRow(scoped,
		`SELECT status FROM devices WHERE id = $1`, deviceID).Scan(&status); err != nil {
		t.Fatalf("чтение статуса %s: %v", deviceID, err)
	}
	return status
}

// Одобрение работает один раз и только из очереди.
//
// Гард стоит на точном статусе, а не на «не active»: повторное одобрение и одобрение
// устройства, которого в очереди нет, обязаны отвечать 409, а не 200. Тихое «ок» на
// повторе означало бы, что кнопка «одобрить» может вернуть в строй отклонённую машину.
func TestApproveDevice_OnlyFromQueueAndOnlyOnce(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := authToken(t, rtr, db)

	id := queueDevice(t, db, tenancy.DefaultTenantID, "host-approve-"+t.Name())

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+id+"/approve", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("одобрение = %d, want 200 (body=%s)", w.Code, w.Body)
	}
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["status"] != "active" {
		t.Fatalf("ответ = %v, want status=active", out)
	}
	if got := deviceStatus(t, db, tenancy.DefaultTenantID, id); got != "active" {
		t.Fatalf("статус в БД = %q, want active", got)
	}

	// Повтор: устройства в очереди больше нет.
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+id+"/approve", nil, token); w.Code != http.StatusConflict {
		t.Fatalf("повторное одобрение = %d, want 409", w.Code)
	}

	// Устройство в 'pending' в очереди НЕ стоит — это другой статус.
	other := "host-pending-" + t.Name()
	dev, err := db.CreatePendingDevice(context.Background(), tenancy.DefaultTenantID, other, "linux")
	if err != nil {
		t.Fatalf("CreatePendingDevice: %v", err)
	}
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+dev.ID+"/approve", nil, token); w.Code != http.StatusConflict {
		t.Fatalf("одобрение устройства вне очереди = %d, want 409 (body=%s)", w.Code, w.Body)
	}
}

// Отклонение терминально для очереди: после него одобрить машину уже нельзя.
// Иначе «отклонил» было бы обратимо одной кнопкой, а gateway режет именно rejected.
func TestRejectDevice_IsTerminalForQueue(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := authToken(t, rtr, db)

	id := queueDevice(t, db, tenancy.DefaultTenantID, "host-reject-"+t.Name())

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+id+"/reject", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("отклонение = %d, want 200 (body=%s)", w.Code, w.Body)
	}
	if got := deviceStatus(t, db, tenancy.DefaultTenantID, id); got != "rejected" {
		t.Fatalf("статус = %q, want rejected", got)
	}
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+id+"/approve", nil, token); w.Code != http.StatusConflict {
		t.Fatalf("одобрение отклонённого = %d, want 409", w.Code)
	}
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+id+"/reject", nil, token); w.Code != http.StatusConflict {
		t.Fatalf("повторное отклонение = %d, want 409", w.Code)
	}
}

// 🔴 Пачка обязана видеть ТОЛЬКО свой тенант.
//
// Ручка берёт тенанта из claims и не принимает его снаружи, но проверять надо
// последствие, а не сигнатуру: «одобрить всю очередь» у администратора одного
// подразделения не должно впускать в парк машины другого. Регресс смотрит на ЧУЖОЙ
// скоуп — «работает ли вообще» здесь ничего не доказывает.
func TestApprovePendingBulk_IsTenantScoped(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := authToken(t, rtr, db)

	mustTenant(t, db, tenantB, "B-tenant")
	mine := queueDevice(t, db, tenancy.DefaultTenantID, "host-bulk-mine-"+t.Name())
	foreign := queueDevice(t, db, tenantB, "host-bulk-foreign-"+t.Name())

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/enrollment-queue/approve", []byte(`{}`), token)
	if w.Code != http.StatusOK {
		t.Fatalf("пакетное одобрение = %d, want 200 (body=%s)", w.Code, w.Body)
	}
	var out map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["approved"] < 1 {
		t.Fatalf("одобрено %d, want ≥1", out["approved"])
	}

	if got := deviceStatus(t, db, tenancy.DefaultTenantID, mine); got != "active" {
		t.Fatalf("своё устройство = %q, want active", got)
	}
	if got := deviceStatus(t, db, tenantB, foreign); got != "pending_approval" {
		t.Fatalf("🔴 устройство ЧУЖОГО тенанта стало %q — пачка вышла за скоуп", got)
	}
}

// Фильтр по группе: пачка с group_id трогает только членов группы. Без фильтра
// ручка одобряет всю очередь, поэтому промах фильтра = впустить в парк всё подряд.
func TestApprovePendingBulk_GroupFilter(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	ctx := context.Background()
	token := authToken(t, rtr, db)

	inGroup := queueDevice(t, db, tenancy.DefaultTenantID, "host-grp-in-"+t.Name())
	outGroup := queueDevice(t, db, tenancy.DefaultTenantID, "host-grp-out-"+t.Name())

	group, err := db.CreateDeviceGroup(ctx, tenancy.DefaultTenantID, "Канарейка-"+t.Name(), "#aabbcc", "stable")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	if err := db.AddDeviceToGroup(ctx, tenancy.DefaultTenantID, inGroup, group.ID); err != nil {
		t.Fatalf("AddDeviceToGroup: %v", err)
	}

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/enrollment-queue/approve",
		[]byte(`{"group_id":"`+group.ID+`"}`), token)
	if w.Code != http.StatusOK {
		t.Fatalf("пакетное одобрение по группе = %d (body=%s)", w.Code, w.Body)
	}
	var out map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["approved"] != 1 {
		t.Fatalf("одобрено %d, want ровно 1 (только член группы)", out["approved"])
	}
	if got := deviceStatus(t, db, tenancy.DefaultTenantID, inGroup); got != "active" {
		t.Fatalf("член группы = %q, want active", got)
	}
	if got := deviceStatus(t, db, tenancy.DefaultTenantID, outGroup); got != "pending_approval" {
		t.Fatalf("устройство вне группы = %q — фильтр не сработал", got)
	}
}

// Пакетное отклонение симметрично одобрению и тоже в границах тенанта.
func TestRejectPendingBulk_RejectsQueue(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	token := authToken(t, rtr, db)

	id := queueDevice(t, db, tenancy.DefaultTenantID, "host-bulkrej-"+t.Name())

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/enrollment-queue/reject", []byte(`{}`), token)
	if w.Code != http.StatusOK {
		t.Fatalf("пакетное отклонение = %d, want 200 (body=%s)", w.Code, w.Body)
	}
	var out map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["rejected"] < 1 {
		t.Fatalf("отклонено %d, want ≥1", out["rejected"])
	}
	if got := deviceStatus(t, db, tenancy.DefaultTenantID, id); got != "rejected" {
		t.Fatalf("статус = %q, want rejected", got)
	}
}

// 🔴 Асимметрия гардов сделана СОЗНАТЕЛЬНО и легко «причёсывается» обратно:
// одобрение — решение о членстве в парке, только человек; отклонение — защитное
// действие, и запрещать его автоматике вредно (тот же принцип, что у отзыва
// admin-запроса). Тест держит именно это различие: если кто-то навесит requireHuman
// на reject «для единообразия», автоматическая защита от чужих машин умрёт молча.
func TestEnrollmentQueue_HumanGateOnApproveOnly(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	ctx := context.Background()

	svcUser, err := db.CreateUser(ctx, tenancy.DefaultTenantID,
		"Queue Svc", "queue-svc-"+t.Name()+"@test.local", "x", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	secret := "rops_" + strings.Repeat("d", 40)
	if _, err := db.CreateAPIToken(ctx, tenancy.DefaultTenantID,
		"queue", "it_admin", "", svcUser.ID, secret, nil); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	svc := "Bearer " + secret

	id := queueDevice(t, db, tenancy.DefaultTenantID, "host-humangate-"+t.Name())

	// Одобрение — только человек.
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+id+"/approve", nil, svc); w.Code != http.StatusForbidden {
		t.Fatalf("сервисный токен одобрил устройство: %d %s — на ручке нет requireHuman", w.Code, w.Body)
	}
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/enrollment-queue/approve", []byte(`{}`), svc); w.Code != http.StatusForbidden {
		t.Fatalf("сервисный токен одобрил очередь пачкой: %d %s", w.Code, w.Body)
	}

	// Отклонение автоматике разрешено намеренно.
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+id+"/reject", nil, svc); w.Code != http.StatusOK {
		t.Fatalf("сервисный токен не смог отклонить устройство: %d %s — защитное действие закрыли", w.Code, w.Body)
	}
	if got := deviceStatus(t, db, tenancy.DefaultTenantID, id); got != "rejected" {
		t.Fatalf("статус = %q, want rejected", got)
	}
}
