package api_test

import (
	"context"
	"encoding/json"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"net/http"
	"testing"
)

// rebootResp — тело ответа одиночной перезагрузки.
type rebootResp struct {
	TaskID       string `json:"task_id"`
	DelaySeconds int32  `json:"delay_seconds"`
}

func postReboot(t *testing.T, rtr http.Handler, tok, path string, body map[string]any) (*rebootResp, int) {
	t.Helper()
	b, _ := json.Marshal(body)
	w := authedDo(t, rtr, http.MethodPost, path, b, tok)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		return nil, w.Code
	}
	var resp rebootResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal reboot response %q: %v", w.Body.String(), err)
	}
	return &resp, w.Code
}

// Повторный клик оператора обязан попадать в ТУ ЖЕ задачу. Новый task_id для того же
// намерения = вторая перезагрузка: агент дедуплицирует durably по task_id и переживает
// перезагрузку, поэтому чужой id для него — новая команда, и машина уходит в цикл.
func TestRebootDevice_SecondRequestReusesPendingTask(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)
	ctx := context.Background()

	deviceID, _ := createDevice(t, rtr, tok, "reboot-idem", "windows")
	if err := db.UpdateDeviceStatus(ctx, tenancy.DefaultTenantID, deviceID, "active"); err != nil {
		t.Fatalf("set active: %v", err)
	}

	first, code := postReboot(t, rtr, tok, "/api/v1/devices/"+deviceID+"/reboot",
		map[string]any{"reason": "обновления", "delay_seconds": 300})
	if code != http.StatusOK {
		t.Fatalf("первая перезагрузка: got %d, want 200", code)
	}
	second, code := postReboot(t, rtr, tok, "/api/v1/devices/"+deviceID+"/reboot",
		map[string]any{"reason": "обновления", "delay_seconds": 300})
	if code != http.StatusOK {
		t.Fatalf("повтор: got %d, want 200", code)
	}
	if first.TaskID != second.TaskID {
		t.Errorf("повтор создал НОВУЮ задачу (%s ≠ %s) — устройство перезагрузится дважды",
			second.TaskID, first.TaskID)
	}
}

// delay_seconds = 0 означает «дефолт агента» (60 с), а не «сейчас», и таким доезжает
// до задачи. Значение между нулём и минимумом поднимается до минимума: агент меньше
// не примет, а молча растянуть просьбу «побыстрее» до минуты значило бы соврать в UI.
func TestRebootDevice_DelayNormalization(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		given any
		want  int32
	}{
		{"ноль = дефолт агента", 0, 0},
		{"меньше минимума поднимается", 3, 10},
		{"отрицательное = дефолт агента", -5, 0},
		{"обычное значение как есть", 900, 900},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deviceID, _ := createDevice(t, rtr, tok, "reboot-delay-"+tc.name, "linux")
			if err := db.UpdateDeviceStatus(ctx, tenancy.DefaultTenantID, deviceID, "active"); err != nil {
				t.Fatalf("set active: %v", err)
			}
			resp, code := postReboot(t, rtr, tok, "/api/v1/devices/"+deviceID+"/reboot",
				map[string]any{"delay_seconds": tc.given})
			if code != http.StatusOK {
				t.Fatalf("got %d, want 200", code)
			}
			if resp.DelaySeconds != tc.want {
				t.Errorf("отсрочка в ответе = %d, want %d", resp.DelaySeconds, tc.want)
			}
			task, err := db.GetTask(ctx, resp.TaskID)
			if err != nil || task == nil {
				t.Fatalf("GetTask: %v", err)
			}
			if task.RebootDelaySeconds != tc.want {
				t.Errorf("отсрочка в задаче = %d, want %d", task.RebootDelaySeconds, tc.want)
			}
			if task.TaskType != "reboot" || task.Priority != "high" {
				t.Errorf("тип/приоритет задачи = %q/%q, want reboot/high (control-plane не ждёт скриптов)",
					task.TaskType, task.Priority)
			}
		})
	}
}

// Не-active устройство Connect не примет: задача висела бы pending до свипа, а
// оператор считал бы команду отданной.
func TestRebootDevice_RefusesNonActive(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)
	ctx := context.Background()

	for _, st := range []string{"blocked", "decommissioned", "pending_approval"} {
		deviceID, _ := createDevice(t, rtr, tok, "reboot-"+st, "windows")
		if err := db.UpdateDeviceStatus(ctx, tenancy.DefaultTenantID, deviceID, st); err != nil {
			t.Fatalf("set %s: %v", st, err)
		}
		_, code := postReboot(t, rtr, tok, "/api/v1/devices/"+deviceID+"/reboot", map[string]any{})
		if code != http.StatusConflict {
			t.Errorf("перезагрузка %s: got %d, want 409", st, code)
		}
	}
}

func TestRebootDevice_ViewerForbidden(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	admin := authToken(t, rtr, db)
	viewer := tokenForRole(t, rtr, db, "viewer", "viewer_")

	deviceID, _ := createDevice(t, rtr, admin, "reboot-rbac", "windows")
	if err := db.UpdateDeviceStatus(context.Background(), tenancy.DefaultTenantID, deviceID, "active"); err != nil {
		t.Fatalf("set active: %v", err)
	}
	_, code := postReboot(t, rtr, viewer, "/api/v1/devices/"+deviceID+"/reboot", map[string]any{})
	if code != http.StatusForbidden {
		t.Errorf("viewer перезагружает устройство: got %d, want 403", code)
	}
}

// Групповая перезагрузка — самая крупнокалиберная кнопка после вывода из
// эксплуатации. Проверяем сверку масштаба: если группа изменилась между показом в
// панели и кликом, подтверждали не тот масштаб.
func TestRebootGroup_ConfirmsScope(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)
	ctx := context.Background()

	groupID := createGroup(t, rtr, tok, "reboot-group-"+t.Name())
	var deviceIDs []string
	for _, name := range []string{"g1", "g2"} {
		id, _ := createDevice(t, rtr, tok, "reboot-"+name, "windows")
		if err := db.UpdateDeviceStatus(ctx, tenancy.DefaultTenantID, id, "active"); err != nil {
			t.Fatalf("set active: %v", err)
		}
		body, _ := json.Marshal(map[string]string{"device_id": id})
		if w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/members", body, tok); w.Code >= 300 {
			t.Fatalf("add member: %d %s", w.Code, w.Body)
		}
		deviceIDs = append(deviceIDs, id)
	}

	// Оператор подтвердил другое число машин — команда не уходит.
	body, _ := json.Marshal(map[string]any{"reason": "окно обслуживания", "delay_seconds": 600, "expected_devices": 1})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/reboot", body, tok); w.Code != http.StatusConflict {
		t.Fatalf("несовпадение масштаба: got %d, want 409", w.Code)
	}

	body, _ = json.Marshal(map[string]any{"reason": "окно обслуживания", "delay_seconds": 600, "expected_devices": len(deviceIDs)})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/reboot", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("групповая перезагрузка: got %d %s, want 201", w.Code, w.Body)
	}
	var resp struct {
		Created int `json:"created"`
		InScope int `json:"in_scope"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Created != len(deviceIDs) || resp.InScope != len(deviceIDs) {
		t.Errorf("created=%d in_scope=%d, want %d/%d", resp.Created, resp.InScope, len(deviceIDs), len(deviceIDs))
	}

	// Повтор по той же группе не заводит вторую перезагрузку тем, кто первую ещё не получил.
	w = authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/reboot", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("повтор по группе: got %d, want 201", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Created != 0 {
		t.Errorf("повтор создал %d задач — часть машин перезагрузится дважды", resp.Created)
	}
}
