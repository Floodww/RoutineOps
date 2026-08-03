package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"net/http"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// createDevice — хелпер для создания pending device через API.
func createDevice(t *testing.T, rtr http.Handler, tok, hostname, os string) (deviceID, enrollToken string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"hostname": hostname, "os": os})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("createDevice %s: %d %s", hostname, w.Code, w.Body)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	dev := resp["device"].(map[string]any)
	return dev["id"].(string), resp["enrollment_token"].(string)
}

func TestListDevices_Empty_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var devices []any
	json.NewDecoder(w.Body).Decode(&devices)
	// может быть non-nil пустой слайс
	if devices == nil {
		t.Error("expected non-nil array (even empty)")
	}
}

func TestListDevices_WithDevice_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	// createDevice returns a pending device; the list excludes pending — promote to active.
	deviceID, _ := createDevice(t, rtr, tok, "host-list-devices", "macos")
	statusBody, _ := json.Marshal(map[string]string{"status": "active"})
	sw := authedDo(t, rtr, http.MethodPut, fmt.Sprintf("/api/v1/devices/%s/status", deviceID), statusBody, tok)
	if sw.Code != http.StatusOK {
		t.Fatalf("promote to active: %d %s", sw.Code, sw.Body)
	}

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var devices []map[string]any
	json.NewDecoder(w.Body).Decode(&devices)
	if len(devices) == 0 {
		t.Error("expected at least one device in list")
	}
}

func TestGetDevice_NotFound_Returns404(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices/00000000-0000-0000-0000-000000000000", nil, tok)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestGetDevice_Found_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-get-device", "windows")

	w := authedDo(t, rtr, http.MethodGet, fmt.Sprintf("/api/v1/devices/%s", deviceID), nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	dev, ok := resp["device"].(map[string]any)
	if !ok {
		t.Fatal("expected 'device' key in response")
	}
	if dev["id"].(string) != deviceID {
		t.Errorf("device.id = %q, want %q", dev["id"], deviceID)
	}
}

func TestUpdateDeviceStatus_Block_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-block", "macos")

	body, _ := json.Marshal(map[string]string{"status": "blocked"})
	w := authedDo(t, rtr, http.MethodPut, fmt.Sprintf("/api/v1/devices/%s/status", deviceID), body, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "blocked" {
		t.Errorf("status = %q, want blocked", resp["status"])
	}
}

func TestUpdateDeviceStatus_Unblock_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-unblock", "windows")

	body, _ := json.Marshal(map[string]string{"status": "active"})
	w := authedDo(t, rtr, http.MethodPut, fmt.Sprintf("/api/v1/devices/%s/status", deviceID), body, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
}

func TestUpdateDeviceStatus_InvalidStatus_Returns400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-invalid-status", "macos")

	body, _ := json.Marshal(map[string]string{"status": "deleted"})
	w := authedDo(t, rtr, http.MethodPut, fmt.Sprintf("/api/v1/devices/%s/status", deviceID), body, tok)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

func TestUpdateDeviceStatus_Unauthenticated_Returns401(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-unauth", "macos")
	body, _ := json.Marshal(map[string]string{"status": "blocked"})
	w := authedDo(t, rtr, http.MethodPut, fmt.Sprintf("/api/v1/devices/%s/status", deviceID), body, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

// ====== Фильтр по группе + бейджи групп (миграция 027) ======

// activateDevice поднимает pending-устройство до active: createDevice отдаёт pending,
// а /devices показывает только не-pending (ListEnrolledDevices).
func activateDevice(t *testing.T, db *storage.DB, id string) {
	t.Helper()
	if err := db.UpdateDeviceStatus(context.Background(), tenancy.DefaultTenantID, id, "active"); err != nil {
		t.Fatalf("UpdateDeviceStatus %s: %v", id, err)
	}
}

// listDeviceIDs возвращает id устройств из ответа /devices.
func listDeviceIDs(t *testing.T, rtr http.Handler, tok, path string) []string {
	t.Helper()
	w := authedDo(t, rtr, http.MethodGet, path, nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: got %d, want 200; body: %s", path, w.Code, w.Body)
	}
	var devices []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&devices); err != nil {
		t.Fatalf("GET %s: decode: %v", path, err)
	}
	ids := make([]string, len(devices))
	for i, d := range devices {
		ids[i] = d.ID
	}
	return ids
}

func TestListDevices_GroupFilter(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	groupID := createGroup(t, rtr, tok, "grp-devfilter")
	inID, _ := createDevice(t, rtr, tok, "host-in-group", "windows")
	outID, _ := createDevice(t, rtr, tok, "host-out-group", "windows")
	activateDevice(t, db, inID)
	activateDevice(t, db, outID)

	mb, _ := json.Marshal(map[string]string{"device_id": inID})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/members", mb, tok); w.Code != http.StatusNoContent {
		t.Fatalf("add member: got %d, want 204; body: %s", w.Code, w.Body)
	}

	// Без фильтра видны оба устройства.
	all := listDeviceIDs(t, rtr, tok, "/api/v1/devices")
	var sawIn, sawOut bool
	for _, id := range all {
		sawIn = sawIn || id == inID
		sawOut = sawOut || id == outID
	}
	if !sawIn || !sawOut {
		t.Errorf("без фильтра: sawIn=%v sawOut=%v, ожидали оба устройства", sawIn, sawOut)
	}

	// С фильтром — только член группы.
	filtered := listDeviceIDs(t, rtr, tok, "/api/v1/devices?group_id="+groupID)
	if len(filtered) != 1 || filtered[0] != inID {
		t.Errorf("фильтр по группе вернул %v, ожидали [%s]", filtered, inID)
	}

	// Мусор вместо UUID — пустой список и 200, а не 500 от 22P02.
	if got := listDeviceIDs(t, rtr, tok, "/api/v1/devices?group_id=не-uuid"); len(got) != 0 {
		t.Errorf("кривой group_id вернул %v, ожидали пустой список", got)
	}
}

// Устройство несёт свои группы с цветом: без этого фронт красил бы рамку только после
// второго запроса за /device-groups.
func TestListDevices_IncludesGroups(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	body, _ := json.Marshal(map[string]string{"name": "grp-devbadge", "color": "#0f0f0f"})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("create group: got %d, want 201; body: %s", w.Code, w.Body)
	}
	var group map[string]any
	json.NewDecoder(w.Body).Decode(&group)
	groupID := group["id"].(string)

	memberID, _ := createDevice(t, rtr, tok, "host-badge", "windows")
	loneID, _ := createDevice(t, rtr, tok, "host-nobadge", "windows")
	activateDevice(t, db, memberID)
	activateDevice(t, db, loneID)

	mb, _ := json.Marshal(map[string]string{"device_id": memberID})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/members", mb, tok); w.Code != http.StatusNoContent {
		t.Fatalf("add member: got %d, want 204; body: %s", w.Code, w.Body)
	}

	w = authedDo(t, rtr, http.MethodGet, "/api/v1/devices", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("list devices: got %d, want 200; body: %s", w.Code, w.Body)
	}
	var devices []struct {
		ID     string `json:"id"`
		Groups []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Color string `json:"color"`
		} `json:"groups"`
	}
	json.NewDecoder(w.Body).Decode(&devices)

	var checkedMember, checkedLone bool
	for _, d := range devices {
		switch d.ID {
		case memberID:
			checkedMember = true
			if len(d.Groups) != 1 {
				t.Fatalf("groups устройства в группе = %+v, ожидали одну", d.Groups)
			}
			if d.Groups[0].ID != groupID || d.Groups[0].Name != "grp-devbadge" || d.Groups[0].Color != "#0f0f0f" {
				t.Errorf("groups[0] = %+v, want {%s grp-devbadge #0f0f0f}", d.Groups[0], groupID)
			}
		case loneID:
			checkedLone = true
			// [] , а не null: фронт итерируется по groups без проверки на nil.
			if d.Groups == nil || len(d.Groups) != 0 {
				t.Errorf("groups устройства без групп = %#v, want []", d.Groups)
			}
		}
	}
	if !checkedMember || !checkedLone {
		t.Errorf("не нашли оба устройства в выдаче: member=%v lone=%v", checkedMember, checkedLone)
	}
}
