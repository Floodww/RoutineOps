package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestCreatePendingDevice_Returns201(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	body := []byte(`{"hostname":"host-create-test","os":"macos"}`)
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices", body, tok)

	if w.Code != http.StatusCreated {
		t.Fatalf("got %d, want 201; body: %s", w.Code, w.Body)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["enrollment_token"] == "" {
		t.Error("expected enrollment_token in response")
	}
	dev, ok := resp["device"].(map[string]any)
	if !ok || dev["id"] == "" {
		t.Error("expected device.id in response")
	}
}

func TestCreatePendingDevice_MissingHostname_Returns400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices", []byte(`{"os":"macos"}`), tok)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

func TestCreatePendingDevice_Unauthenticated_Returns401(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices", []byte(`{"hostname":"h"}`), "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

func TestGetEnrollmentToken_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	// создаём устройство → получаем device.id
	body := []byte(`{"hostname":"host-tok-test","os":"windows"}`)
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("createPendingDevice: %d %s", w.Code, w.Body)
	}
	var created map[string]any
	json.NewDecoder(w.Body).Decode(&created)
	dev := created["device"].(map[string]any)
	deviceID := dev["id"].(string)

	w2 := authedDo(t, rtr, http.MethodGet, fmt.Sprintf("/api/v1/devices/%s/enrollment-token", deviceID), nil, tok)
	if w2.Code != http.StatusOK {
		t.Fatalf("getEnrollmentToken: %d %s", w2.Code, w2.Body)
	}
	var tokResp map[string]any
	json.NewDecoder(w2.Body).Decode(&tokResp)
	// N6: эндпоинт re-display больше не отдаёт plaintext-токен (хранится хешированным),
	// только срок активного токена.
	if tokResp["expires_at"] == nil || tokResp["expires_at"] == "" {
		t.Error("expected expires_at in response")
	}
	if _, leaked := tokResp["token"]; leaked {
		t.Error("plaintext token must NOT be returned by re-display endpoint (N6)")
	}
}

func TestGetEnrollmentToken_NoToken_Returns404(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices/00000000-0000-0000-0000-000000000000/enrollment-token", nil, tok)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestEnroll_HappyPath_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtrAuth := newRouterFull(t, db) // без CA — для логина и создания устройства
	tok := authToken(t, rtrAuth, db)

	// создаём устройство и получаем enrollment token
	body := []byte(`{"hostname":"host-enroll","os":"macos"}`)
	w := authedDo(t, rtrAuth, http.MethodPost, "/api/v1/devices", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("createPendingDevice: %d %s", w.Code, w.Body)
	}
	var created map[string]any
	json.NewDecoder(w.Body).Decode(&created)
	enrollToken := created["enrollment_token"].(string)

	// роутер с CA для самого enrollment
	rtrCA := newRouterWithCA(t, db)
	csrPEM := makeCSR(t)
	enrollBody, _ := json.Marshal(map[string]string{
		"enrollment_token": enrollToken,
		"csr_pem":          string(csrPEM),
		"hostname":         "host-enroll",
		"os":               "macos",
	})
	w2 := authedDo(t, rtrCA, http.MethodPost, "/api/v1/enroll", enrollBody, "")
	if w2.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w2.Code, w2.Body)
	}
	var enrollResp map[string]string
	json.NewDecoder(w2.Body).Decode(&enrollResp)
	if enrollResp["cert_pem"] == "" {
		t.Error("expected cert_pem in enroll response")
	}
	if enrollResp["device_id"] == "" {
		t.Error("expected device_id in enroll response")
	}
}

func TestEnroll_ExpiredToken_Returns401(t *testing.T) {
	// CA nil → 503 раньше, чем мы проверяем токен. Используем роутер с CA.
	db := newTestDB(t)
	rtr := newRouterWithCA(t, db)

	csrPEM := makeCSR(t)
	body, _ := json.Marshal(map[string]string{
		"enrollment_token": "nonexistent-token",
		"csr_pem":          string(csrPEM),
	})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/enroll", body, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

func TestEnroll_MissingFields_Returns400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterWithCA(t, db)

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/enroll", []byte(`{"enrollment_token":"tok"}`), "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

func TestReenroll_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	// создаём устройство
	body := []byte(`{"hostname":"host-reenroll","os":"windows"}`)
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("createPendingDevice: %d %s", w.Code, w.Body)
	}
	var created map[string]any
	json.NewDecoder(w.Body).Decode(&created)
	dev := created["device"].(map[string]any)
	deviceID := dev["id"].(string)

	w2 := authedDo(t, rtr, http.MethodPost, fmt.Sprintf("/api/v1/devices/%s/reenroll", deviceID), nil, tok)
	if w2.Code != http.StatusOK {
		t.Fatalf("reenroll: %d %s", w2.Code, w2.Body)
	}
	var reenrollResp map[string]any
	json.NewDecoder(w2.Body).Decode(&reenrollResp)
	if reenrollResp["enrollment_token"] == "" {
		t.Error("expected enrollment_token in reenroll response")
	}
}
