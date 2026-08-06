package storage_test

import (
	"context"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"github.com/jackc/pgx/v5"
)

func TestRLS_BindTenantIsolatesDevices(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	tenantA := tenancy.DefaultTenantID
	tenantB := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'B') ON CONFLICT DO NOTHING`, tenantB,
	); err != nil {
		t.Fatalf("tenant B: %v", err)
	}

	dA := mustCreateActiveDevice(t, db, "rls-a-"+uniq(t), "linux")
	ctxB, finishB, err := db.BindTenant(ctx, tenantB)
	if err != nil {
		t.Fatalf("bind B: %v", err)
	}
	defer finishB(true)
	var dBID string
	if err := db.Scoped(ctxB).QueryRow(ctxB, `
		INSERT INTO devices (tenant_id, hostname, os, status)
		VALUES ($1, $2, 'linux', 'active')
		RETURNING id::text`, tenantB, "rls-b-"+uniq(t),
	).Scan(&dBID); err != nil {
		t.Fatalf("device B: %v", err)
	}
	finishB(true)

	ctxA, finishA, err := db.BindTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("bind A: %v", err)
	}
	defer finishA(true)
	gotA, _, err := db.GetDevice(ctxA, tenantA, dA.ID)
	if err != nil || gotA == nil {
		t.Fatalf("GetDevice own: %v, %v", gotA, err)
	}
	gotB, _, err := db.GetDevice(ctxA, tenantA, dBID)
	if err != nil {
		t.Fatalf("GetDevice foreign: %v", err)
	}
	if gotB != nil {
		t.Fatalf("tenant A saw tenant B device %+v", gotB)
	}
	// Pool-запрос без явного set_config получает дефолтный GUC (ALTER ROLE SET
	// routineops.tenant_id в testutil). Проверяем: устройство dB (tenant B)
	// через RLS невидимо, т.к. скоуп ограничен DefaultTenantID (Q-14).
	var poolGot string
	err = db.Pool().QueryRow(ctx, `SELECT id::text FROM devices WHERE id = $1`, dBID).Scan(&poolGot)
	if err == nil {
		t.Fatalf("pool query with default GUC returned tenant B device: %s", poolGot)
	}
	if err != pgx.ErrNoRows {
		t.Fatalf("expected ErrNoRows due to RLS, got: %v", err)
	}
}
