package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// РЕГРЕСС (адверс-ревью 20.07): PUT /devices/{id}/status — это ручка block/unblock,
// НЕ бэкдор в approve. Иначе сервисный токен (не requireHuman) флипнул бы
// pending_approval→active в обход человеческого одобрения (и получил бы скрипт-канал),
// либо воскресил rejected/decommissioned.
func TestUpdateDeviceStatus_RefusesManagedStatuses(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)
	ctx := context.Background()

	for _, src := range []string{"pending_approval", "rejected", "decommissioned"} {
		deviceID, _ := createDevice(t, rtr, tok, "mng-"+src, "windows")
		if err := db.UpdateDeviceStatus(ctx, deviceID, src); err != nil {
			t.Fatalf("set %s: %v", src, err)
		}
		body, _ := json.Marshal(map[string]string{"status": "active"})
		w := authedDo(t, rtr, http.MethodPut, "/api/v1/devices/"+deviceID+"/status", body, tok)
		if w.Code != http.StatusConflict {
			t.Errorf("PUT status=active на %s: got %d, want 409 (не бэкдор в approve)", src, w.Code)
		}
		if st, _ := db.GetDeviceStatusByID(ctx, deviceID); st != src {
			t.Errorf("%s изменён backdoor'ом на %q", src, st)
		}
	}

	// Штатный block/unblock (active↔blocked) по-прежнему работает.
	deviceID, _ := createDevice(t, rtr, tok, "normal-block", "windows")
	if err := db.UpdateDeviceStatus(ctx, deviceID, "active"); err != nil {
		t.Fatalf("set active: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"status": "blocked"})
	w := authedDo(t, rtr, http.MethodPut, "/api/v1/devices/"+deviceID+"/status", body, tok)
	if w.Code != http.StatusOK {
		t.Errorf("block active-устройства: got %d, want 200", w.Code)
	}
	if st, _ := db.GetDeviceStatusByID(ctx, deviceID); st != "blocked" {
		t.Errorf("статус = %q, want blocked", st)
	}
}
