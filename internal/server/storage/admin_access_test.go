package storage_test

import (
	"context"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

func mustCreateAdminRequest(t *testing.T, db *storage.DB, deviceID, userID string) *storage.AdminAccessRequest {
	t.Helper()
	req, err := db.CreateAdminAccessRequest(
		context.Background(), deviceID, userID, "need admin",
		time.Now(), time.Now().Add(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}
	return req
}

func TestCreateAdminAccessRequest_ReturnsPending(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-aar-%s", uniq(t)), "macos")
	u := mustCreateUser(t, db, fmt.Sprintf("aar-%s@test.com", uniq(t)))

	req := mustCreateAdminRequest(t, db, d.ID, u.ID)
	if req.ID == "" {
		t.Error("expected non-empty request ID")
	}
	if req.Status != "pending" {
		t.Errorf("status = %q, want pending", req.Status)
	}
}

func TestFetchActiveAdminRequest_Pending(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-fetch-%s", uniq(t)), "windows")
	u := mustCreateUser(t, db, fmt.Sprintf("fetch-%s@test.com", uniq(t)))
	req := mustCreateAdminRequest(t, db, d.ID, u.ID)

	got, err := db.FetchActiveAdminRequest(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("FetchActiveAdminRequest: %v", err)
	}
	if got == nil {
		t.Fatal("got nil, want active request")
	}
	if got.ID != req.ID {
		t.Errorf("id = %q, want %q", got.ID, req.ID)
	}
}

func TestFetchActiveAdminRequest_NoActive_ReturnsNil(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-noactive-%s", uniq(t)), "macos")

	got, err := db.FetchActiveAdminRequest(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("FetchActiveAdminRequest: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestRespondToAdminRequest_Approve(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-approve-%s", uniq(t)), "macos")
	u := mustCreateUser(t, db, fmt.Sprintf("approve-%s@test.com", uniq(t)))
	req := mustCreateAdminRequest(t, db, d.ID, u.ID)

	expires := time.Now().Add(1 * time.Hour)
	if err := db.RespondToAdminRequest(context.Background(), req.ID, "approved", u.ID, &expires); err != nil {
		t.Fatalf("RespondToAdminRequest: %v", err)
	}

	// FetchActive should still return it (approved is still "active")
	got, _ := db.FetchActiveAdminRequest(context.Background(), d.ID)
	if got == nil || got.Status != "approved" {
		t.Errorf("status = %v, want approved", got)
	}
}

func TestRespondToAdminRequest_Reject(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-reject-%s", uniq(t)), "windows")
	u := mustCreateUser(t, db, fmt.Sprintf("reject-%s@test.com", uniq(t)))
	req := mustCreateAdminRequest(t, db, d.ID, u.ID)

	if err := db.RespondToAdminRequest(context.Background(), req.ID, "rejected", u.ID, nil); err != nil {
		t.Fatalf("RespondToAdminRequest (reject): %v", err)
	}

	// FetchActive should return nil — rejected is not active
	got, _ := db.FetchActiveAdminRequest(context.Background(), d.ID)
	if got != nil {
		t.Errorf("expected nil after rejection, got %+v", got)
	}
}

func TestRevokeAdminAccessRequest(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-revoke-%s", uniq(t)), "macos")
	u := mustCreateUser(t, db, fmt.Sprintf("revoke-%s@test.com", uniq(t)))
	req := mustCreateAdminRequest(t, db, d.ID, u.ID)

	// approve first (revoke only works on approved)
	expires := time.Now().Add(1 * time.Hour)
	_ = db.RespondToAdminRequest(context.Background(), req.ID, "approved", u.ID, &expires)

	if err := db.RevokeAdminAccessRequest(context.Background(), tenancy.DefaultTenantID, req.ID); err != nil {
		t.Fatalf("RevokeAdminAccessRequest: %v", err)
	}

	got, _ := db.FetchActiveAdminRequest(context.Background(), d.ID)
	if got != nil {
		t.Errorf("expected nil after revoke, got %+v", got)
	}
}

func TestExpireStaleAdminRequests(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-expire-%s", uniq(t)), "windows")
	u := mustCreateUser(t, db, fmt.Sprintf("expire-%s@test.com", uniq(t)))

	// use UTC with large offset to be safe against any TZ skew between Go and Postgres
	_, err := db.CreateAdminAccessRequest(
		context.Background(), d.ID, u.ID, "expired request",
		time.Now().UTC().Add(-26*time.Hour), time.Now().UTC().Add(-25*time.Hour),
	)
	if err != nil {
		t.Fatalf("CreateAdminAccessRequest: %v", err)
	}

	n, err := db.ExpireStaleAdminRequests(context.Background())
	if err != nil {
		t.Fatalf("ExpireStaleAdminRequests: %v", err)
	}
	if n == 0 {
		t.Error("expected at least one request to be expired")
	}
}

func TestListAdminAccessRequests_StatusFilter(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-listaar-%s", uniq(t)), "macos")
	u := mustCreateUser(t, db, fmt.Sprintf("listaar-%s@test.com", uniq(t)))
	mustCreateAdminRequest(t, db, d.ID, u.ID)

	rows, err := db.ListAdminAccessRequests(context.Background(), tenancy.DefaultTenantID, "pending")
	if err != nil {
		t.Fatalf("ListAdminAccessRequests: %v", err)
	}
	for _, r := range rows {
		if r.Status != "pending" {
			t.Errorf("got status %q, want pending", r.Status)
		}
	}
}
