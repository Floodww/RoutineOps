package storage_test

import (
	"context"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"
)

func TestCreateUser_ReturnsUserWithID(t *testing.T) {
	db := newDB(t)
	email := fmt.Sprintf("create-%s@test.com", uniq(t))
	u, err := db.CreateUser(context.Background(), tenancy.DefaultTenantID, "Alice", email, "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == "" {
		t.Error("expected non-empty ID")
	}
	if u.Email != email {
		t.Errorf("email = %q, want %q", u.Email, email)
	}
	if u.Role != "user" {
		t.Errorf("role = %q, want user", u.Role)
	}
}

func TestGetUserByEmail_Found(t *testing.T) {
	db := newDB(t)
	email := fmt.Sprintf("getbyemail-%s@test.com", uniq(t))
	created := mustCreateUser(t, db, email)

	got, err := db.GetUserByEmailInTenant(context.Background(), tenancy.DefaultTenantID, email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got == nil {
		t.Fatal("got nil, want user")
	}
	if got.ID != created.ID {
		t.Errorf("id = %q, want %q", got.ID, created.ID)
	}
}

func TestGetUserByEmail_NotFound_ReturnsNil(t *testing.T) {
	db := newDB(t)
	got, err := db.GetUserByEmailInTenant(context.Background(), tenancy.DefaultTenantID, "nobody@nowhere.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestSetAndGetUserTelegramChatID(t *testing.T) {
	db := newDB(t)
	u := mustCreateUser(t, db, fmt.Sprintf("tg-%s@test.com", uniq(t)))

	if err := db.SetUserTelegramChatID(context.Background(), u.ID, "chat-123"); err != nil {
		t.Fatalf("SetUserTelegramChatID: %v", err)
	}

	chatID, _, err := db.GetUserTelegramStatus(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("GetUserTelegramStatus: %v", err)
	}
	if chatID == nil || *chatID != "chat-123" {
		t.Errorf("chatID = %v, want chat-123", chatID)
	}
}

func TestSetAndGetUserLinkToken(t *testing.T) {
	db := newDB(t)
	u := mustCreateUser(t, db, fmt.Sprintf("link-%s@test.com", uniq(t)))

	// Уникальный токен: telegram_link_token — UNIQUE, общая БД переживает -count.
	token := "tok-" + uniq(t)
	if err := db.SetUserLinkToken(context.Background(), u.ID, token); err != nil {
		t.Fatalf("SetUserLinkToken: %v", err)
	}

	got, err := db.GetUserByLinkToken(context.Background(), token)
	if err != nil {
		t.Fatalf("GetUserByLinkToken: %v", err)
	}
	if got == nil || got.ID != u.ID {
		t.Errorf("got %v, want user %s", got, u.ID)
	}
}

func TestSetUserLinkToken_Clear(t *testing.T) {
	db := newDB(t)
	u := mustCreateUser(t, db, fmt.Sprintf("linkclear-%s@test.com", uniq(t)))

	_ = db.SetUserLinkToken(context.Background(), u.ID, "tok-clear")
	// clear it
	if err := db.SetUserLinkToken(context.Background(), u.ID, ""); err != nil {
		t.Fatalf("SetUserLinkToken (clear): %v", err)
	}

	got, err := db.GetUserByLinkToken(context.Background(), "tok-clear")
	if err != nil {
		t.Fatalf("GetUserByLinkToken: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after clear, got %+v", got)
	}
}
