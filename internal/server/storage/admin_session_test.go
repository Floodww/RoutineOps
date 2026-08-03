package storage_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

func TestAcceptAdminSessionWindow_AppendOnlyAndFinal(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-asc-%s", uniq(t)), "windows")
	u := mustCreateUser(t, db, fmt.Sprintf("asc-%s@test.com", uniq(t)))
	req := mustCreateAdminRequest(t, db, d.ID, u.ID)
	expires := time.Now().Add(time.Hour)
	if err := db.RespondToAdminRequest(context.Background(), req.ID, "approved", u.ID, &expires); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := db.MarkAdminBaselineCaptured(context.Background(), req.ID, d.ID, time.Now()); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	win := storage.AdminSessionWindow{
		RequestID: req.ID, DeviceID: d.ID, WindowSeq: 1,
		WindowStart: time.Now().Add(-time.Minute), WindowEnd: time.Now(),
		Changes: []storage.AdminSessionChange{{
			Kind: "software_installed", Subject: "Tool", DisplayName: "Tool",
			IdentityKey: "tool|vendor", Attribution: "human_likely",
			ObservedAt: time.Now(),
		}},
		TotalChanges: 1, Completeness: "complete", SoftwareHealth: "ok", ServicesHealth: "ok",
	}
	if err := db.AcceptAdminSessionWindow(context.Background(), win); err != nil {
		t.Fatalf("accept: %v", err)
	}
	win.Changes = nil
	win.TotalChanges = 0
	if err := db.AcceptAdminSessionWindow(context.Background(), win); err != nil {
		t.Fatalf("accept empty: %v", err)
	}
	rows, err := db.ListAdminSessionChanges(context.Background(), req.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 (append-only)", len(rows))
	}

	win.WindowSeq = 2
	win.Final = true
	win.Changes = []storage.AdminSessionChange{{
		Kind: "software_installed", Subject: "Tool", DisplayName: "Tool",
		IdentityKey: "tool|vendor", Attribution: "human_likely",
		ObservedAt: time.Now(),
	}}
	win.TotalChanges = 1
	if err := db.AcceptAdminSessionWindow(context.Background(), win); err != nil {
		t.Fatalf("final: %v", err)
	}
	ev, err := db.GetAdminAccessEvidence(context.Background(), tenancy.DefaultTenantID, req.ID)
	if err != nil || ev == nil {
		t.Fatalf("evidence: %v %#v", err, ev)
	}
	if ev.ChangesFinalAt == nil {
		t.Fatal("expected changes_final_at set")
	}
}

func TestAcceptAdminSessionWindow_SeqJumpRejected(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-seq-%s", uniq(t)), "linux")
	u := mustCreateUser(t, db, fmt.Sprintf("seq-%s@test.com", uniq(t)))
	req := mustCreateAdminRequest(t, db, d.ID, u.ID)
	win := storage.AdminSessionWindow{
		RequestID: req.ID, DeviceID: d.ID, WindowSeq: storage.MaxAdminSessionSeqJump + 1,
		WindowEnd: time.Now(), Completeness: "complete",
	}
	err := db.AcceptAdminSessionWindow(context.Background(), win)
	if !errors.Is(err, storage.ErrAdminSessionSeqJump) {
		t.Fatalf("got %v, want ErrAdminSessionSeqJump", err)
	}
}

func TestAcceptAdminSessionWindow_WrongDevice(t *testing.T) {
	db := newDB(t)
	d1 := mustCreateDevice(t, db, fmt.Sprintf("host-d1-%s", uniq(t)), "macos")
	d2 := mustCreateDevice(t, db, fmt.Sprintf("host-d2-%s", uniq(t)), "macos")
	u := mustCreateUser(t, db, fmt.Sprintf("wd-%s@test.com", uniq(t)))
	req := mustCreateAdminRequest(t, db, d1.ID, u.ID)
	win := storage.AdminSessionWindow{
		RequestID: req.ID, DeviceID: d2.ID, WindowSeq: 1,
		WindowEnd: time.Now(), Completeness: "complete",
	}
	err := db.AcceptAdminSessionWindow(context.Background(), win)
	if !errors.Is(err, storage.ErrAdminRequestNotFound) {
		t.Fatalf("got %v, want ErrAdminRequestNotFound", err)
	}
}

func TestListAdminEvidenceGaps_NeedsBaselineAndClosed(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-gap-%s", uniq(t)), "macos")
	u := mustCreateUser(t, db, fmt.Sprintf("gap-%s@test.com", uniq(t)))
	req := mustCreateAdminRequest(t, db, d.ID, u.ID)
	expires := time.Now().Add(time.Hour)
	if err := db.RespondToAdminRequest(context.Background(), req.ID, "approved", u.ID, &expires); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := db.MarkAdminBaselineCaptured(context.Background(), req.ID, d.ID, time.Now().Add(-3*time.Hour)); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := db.RevokeAdminAccessRequest(context.Background(), tenancy.DefaultTenantID, req.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := db.Pool().Exec(context.Background(),
		`UPDATE admin_access_requests SET revoked_at = now() - interval '3 hours' WHERE id = $1`, req.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	gaps, err := db.ListAdminEvidenceGaps(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("gaps: %v", err)
	}
	found := false
	for _, g := range gaps {
		if g.RequestID == req.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("expected evidence gap for revoked session with baseline")
	}
}
