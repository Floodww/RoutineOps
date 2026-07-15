package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// seedAgentUser создаёт пользователя-агента (без пароля) и возвращает его ID.
func seedAgentUser(t *testing.T, db *storage.DB, email string) string {
	t.Helper()
	u, err := db.CreateUser(context.Background(), "Agent", email, "x", "user")
	if err != nil {
		t.Fatalf("seedAgentUser: %v", err)
	}
	return u.ID
}

// seedAdminRequest создаёт admin access request через storage напрямую.
func seedAdminRequest(t *testing.T, db *storage.DB, deviceID, requestedByUserID string) string {
	t.Helper()
	req, err := db.CreateAdminAccessRequest(
		context.Background(),
		deviceID,
		requestedByUserID,
		"need admin for update",
		time.Now(),
		time.Now().Add(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("seedAdminRequest: %v", err)
	}
	return req.ID
}

func TestListAdminAccessRequests_Empty_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/admin-access-requests", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var rows []any
	json.NewDecoder(w.Body).Decode(&rows)
	if rows == nil {
		t.Error("expected non-nil array")
	}
}

func TestListAdminAccessRequests_WithRequest_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-admin-req-list", "macos")
	agentUserID := seedAgentUser(t, db, "agent-list@test.com")
	seedAdminRequest(t, db, deviceID, agentUserID)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/admin-access-requests", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var rows []map[string]any
	json.NewDecoder(w.Body).Decode(&rows)
	if len(rows) == 0 {
		t.Error("expected at least one admin access request")
	}
}

func TestListAdminAccessRequests_FilterPending_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-admin-req-filter", "windows")
	agentUserID := seedAgentUser(t, db, "agent-filter@test.com")
	seedAdminRequest(t, db, deviceID, agentUserID)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/admin-access-requests?status=pending", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var rows []map[string]any
	json.NewDecoder(w.Body).Decode(&rows)
	for _, row := range rows {
		if row["status"].(string) != "pending" {
			t.Errorf("got status %q, want pending", row["status"])
		}
	}
}

func TestRespondAdminRequest_Approve_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-admin-approve", "macos")
	agentUserID := seedAgentUser(t, db, "agent-approve@test.com")
	reqID := seedAdminRequest(t, db, deviceID, agentUserID)

	body, _ := json.Marshal(map[string]any{"decision": "approved", "duration_seconds": 3600})
	w := authedDo(t, rtr, http.MethodPost, fmt.Sprintf("/api/v1/admin-access-requests/%s/respond", reqID), body, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "approved" {
		t.Errorf("status = %q, want approved", resp["status"])
	}
}

func TestRespondAdminRequest_Reject_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-admin-reject", "windows")
	agentUserID := seedAgentUser(t, db, "agent-reject@test.com")
	reqID := seedAdminRequest(t, db, deviceID, agentUserID)

	body, _ := json.Marshal(map[string]string{"decision": "rejected"})
	w := authedDo(t, rtr, http.MethodPost, fmt.Sprintf("/api/v1/admin-access-requests/%s/respond", reqID), body, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "rejected" {
		t.Errorf("status = %q, want rejected", resp["status"])
	}
}

func TestRespondAdminRequest_InvalidDecision_Returns400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-admin-baddecision", "macos")
	agentUserID := seedAgentUser(t, db, "agent-baddecision@test.com")
	reqID := seedAdminRequest(t, db, deviceID, agentUserID)

	body, _ := json.Marshal(map[string]string{"decision": "maybe"})
	w := authedDo(t, rtr, http.MethodPost, fmt.Sprintf("/api/v1/admin-access-requests/%s/respond", reqID), body, tok)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

func TestRevokeAdminRequest_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-admin-revoke", "macos")
	agentUserID := seedAgentUser(t, db, "agent-revoke@test.com")
	reqID := seedAdminRequest(t, db, deviceID, agentUserID)

	w := authedDo(t, rtr, http.MethodPost, fmt.Sprintf("/api/v1/admin-access-requests/%s/revoke", reqID), nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "revoked" {
		t.Errorf("status = %q, want revoked", resp["status"])
	}
}

func TestAdminAccessRequests_Unauthenticated_Returns401(t *testing.T) {
	rtr := newRouter(t)
	w := authedDo(t, rtr, http.MethodGet, "/api/v1/admin-access-requests", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

// Выдача в минутах — легальный сценарий; ниже минуты и выше 30 суток — нет.
// Нижняя граница не случайна: агент опрашивает статус раз в 30с (ROUTINEOPS_ADMIN_POLL),
// и грант короче минуты истёк бы раньше, чем доехал до устройства.
func TestRespondAdminRequest_DurationBounds(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	cases := []struct {
		name     string
		duration int
		want     int
	}{
		{"пять минут", 300, http.StatusOK},
		{"ровно минута", 60, http.StatusOK},
		{"тридцать суток", 30 * 24 * 3600, http.StatusOK},
		{"меньше минуты", 30, http.StatusBadRequest},
		{"больше тридцати суток", 31 * 24 * 3600, http.StatusBadRequest},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deviceID, _ := createDevice(t, rtr, tok, fmt.Sprintf("host-dur-%d", i), "macos")
			agentUserID := seedAgentUser(t, db, fmt.Sprintf("agent-dur-%d@test.com", i))
			reqID := seedAdminRequest(t, db, deviceID, agentUserID)

			body, _ := json.Marshal(map[string]any{"decision": "approved", "duration_seconds": tc.duration})
			w := authedDo(t, rtr, http.MethodPost, fmt.Sprintf("/api/v1/admin-access-requests/%s/respond", reqID), body, tok)
			if w.Code != tc.want {
				t.Errorf("duration=%ds: got %d, want %d; body: %s", tc.duration, w.Code, tc.want, w.Body)
			}
		})
	}
}
