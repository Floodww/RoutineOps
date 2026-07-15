package storage_test

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCreateEnrollmentToken_And_GetByToken(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-enroll-%s", uniq(t)), "macos")
	tok := fmt.Sprintf("tok-%s", uniq(t))

	if err := db.CreateEnrollmentToken(context.Background(), d.ID, tok, time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	got, err := db.GetEnrollmentToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("GetEnrollmentToken: %v", err)
	}
	if got == nil {
		t.Fatal("got nil token")
	}
	if got.DeviceID != d.ID {
		t.Errorf("device_id = %q, want %q", got.DeviceID, d.ID)
	}
	if got.UsedAt != nil {
		t.Error("token should not be used yet")
	}
}

func TestGetEnrollmentToken_NotFound_ReturnsNil(t *testing.T) {
	db := newDB(t)
	got, err := db.GetEnrollmentToken(context.Background(), "nonexistent-token")
	if err != nil {
		t.Fatalf("GetEnrollmentToken: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestGetActiveEnrollmentToken_AfterExpiry_ReturnsNil(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-exptok-%s", uniq(t)), "windows")
	tok := fmt.Sprintf("tok-exp-%s", uniq(t))

	// use 25h to be safe against any timezone offset between Go and Postgres
	if err := db.CreateEnrollmentToken(context.Background(), d.ID, tok, time.Now().UTC().Add(-25*time.Hour)); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	got, err := db.GetActiveEnrollmentToken(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("GetActiveEnrollmentToken: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for expired token, got %+v", got)
	}
}

func TestEnrollDevice_MarksTokenUsedAndDeviceEnrolled(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-enrolldev-%s", uniq(t)), "macos")
	tok := fmt.Sprintf("tok-enroll-%s", uniq(t))
	_ = db.CreateEnrollmentToken(context.Background(), d.ID, tok, time.Now().Add(1*time.Hour))

	tokenRec, _ := db.GetEnrollmentToken(context.Background(), tok)

	const fp = "abc123fingerprintdeadbeef"
	if err := db.EnrollDevice(context.Background(), tokenRec.ID, d.ID, "CERT-SERIAL-123", fp); err != nil {
		t.Fatalf("EnrollDevice: %v", err)
	}

	// token should now be marked used
	used, _ := db.GetEnrollmentToken(context.Background(), tok)
	if used.UsedAt == nil {
		t.Error("token used_at should be set after enroll")
	}

	// device should be enrolled
	got, _, _ := db.GetDevice(context.Background(), d.ID)
	if got.Status != "enrolled" {
		t.Errorf("device status = %q, want enrolled", got.Status)
	}

	// fingerprint must be persisted so the first heartbeat updates THIS row (БАГ 4):
	// поиск устройства по отпечатку должен вернуть статус enrolled.
	st, err := db.GetDeviceStatusByFingerprint(context.Background(), fp)
	if err != nil {
		t.Fatalf("GetDeviceStatusByFingerprint: %v", err)
	}
	if st != "enrolled" {
		t.Errorf("по отпечатку статус = %q, want enrolled (отпечаток не сохранён при enroll)", st)
	}
}

func TestResetDeviceForReenroll_GeneratesNewToken(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-reenroll-%s", uniq(t)), "windows")
	oldTok := fmt.Sprintf("tok-old-%s", uniq(t))
	_ = db.CreateEnrollmentToken(context.Background(), d.ID, oldTok, time.Now().Add(1*time.Hour))

	newTok := fmt.Sprintf("tok-new-%s", uniq(t))
	if err := db.ResetDeviceForReenroll(context.Background(), d.ID, newTok, time.Now().Add(2*time.Hour)); err != nil {
		t.Fatalf("ResetDeviceForReenroll: %v", err)
	}

	// old token should be invalidated (marked used)
	oldRec, _ := db.GetEnrollmentToken(context.Background(), oldTok)
	if oldRec == nil || oldRec.UsedAt == nil {
		t.Error("old token should be marked used after reenroll")
	}

	// new token must be the active one and resolvable by its plaintext (hash match, N6)
	active, _ := db.GetActiveEnrollmentToken(context.Background(), d.ID)
	if active == nil {
		t.Fatal("expected new active token")
	}
	newRec, _ := db.GetEnrollmentToken(context.Background(), newTok)
	if newRec == nil || newRec.ID != active.ID {
		t.Errorf("new token not resolvable by plaintext or does not match active row")
	}

	// device status should be pending again
	got, _, _ := db.GetDevice(context.Background(), d.ID)
	if got.Status != "pending" {
		t.Errorf("device status = %q, want pending", got.Status)
	}
}
