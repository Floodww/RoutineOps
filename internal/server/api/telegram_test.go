package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

func TestGetTelegramStatus_NotLinked_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/profile/telegram", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if linked, ok := resp["linked"].(bool); !ok || linked {
		t.Errorf("expected linked false, got %v", resp["linked"])
	}
	if resp["link_token"] != nil && resp["link_token"] != "" {
		t.Errorf("expected link_token empty, got %v", resp["link_token"])
	}
}

func TestGetTelegramStatus_Linked_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	// Set telegram_chat_id for the user created by authToken
	email := "admin_" + t.Name() + "@test.com"
	user, err := db.GetUserByEmailInTenant(context.Background(), tenancy.DefaultTenantID, email)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	err = db.SetUserTelegramChatID(context.Background(), user.ID, "12345")
	if err != nil {
		t.Fatalf("set chat id: %v", err)
	}

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/profile/telegram", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if linked, _ := resp["linked"].(bool); !linked {
		t.Errorf("expected linked true, got false")
	}
}

func TestGenerateTelegramLinkToken_Returns200AndTokenSavedInDB(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	w := authedDo(t, rtr, http.MethodPost, "/api/v1/profile/telegram-link", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	token := resp["token"]
	if len(token) != 24 {
		t.Errorf("expected 24 char token, got %d", len(token))
	}

	w2 := authedDo(t, rtr, http.MethodGet, "/api/v1/profile/telegram", nil, tok)
	var status map[string]any
	json.NewDecoder(w2.Body).Decode(&status)
	if status["link_token"] != token {
		t.Errorf("expected link_token %s, got %v", token, status["link_token"])
	}
}
