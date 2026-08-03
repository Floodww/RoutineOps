package storage_test

import (
	"context"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// TestCrossTenant_ListAndGetHideForeignRows — два тенанта, устройство в каждом:
// list/get одного не видит чужое (контракт §5 слой 3, без RLS — пока предикат в SQL).
func TestCrossTenant_ListAndGetHideForeignRows(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	other := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'Other') ON CONFLICT DO NOTHING`, other,
	); err != nil {
		t.Fatalf("other tenant: %v", err)
	}

	a := mustCreateActiveDevice(t, db, "host-a-"+uniq(t), "linux")
	var bID string
	otherCtx, finish, err := db.BindTenant(ctx, other)
	if err != nil {
		t.Fatalf("bind other tenant: %v", err)
	}
	if err := db.Q(otherCtx).QueryRow(otherCtx, `
		INSERT INTO devices (hostname, os, status, tenant_id)
		VALUES ($1, 'linux', 'active', $2)
		RETURNING id::text`, "host-b-"+uniq(t), other,
	).Scan(&bID); err != nil {
		finish(false)
		t.Fatalf("device B: %v", err)
	}
	finish(true)

	list, total, err := db.ListEnrolledDevices(ctx, tenancy.DefaultTenantID, "", "", 0, 0)
	if err != nil {
		t.Fatalf("list default: %v", err)
	}
	if total < 1 {
		t.Fatal("default tenant list empty")
	}
	for _, d := range list {
		if d.ID == bID {
			t.Fatalf("default list leaked device from other tenant: %s", bID)
		}
	}
	got, _, err := db.GetDevice(ctx, tenancy.DefaultTenantID, bID)
	if err != nil {
		t.Fatalf("get foreign: %v", err)
	}
	if got != nil {
		t.Fatalf("GetDevice across tenants returned row %+v", got)
	}
	gotA, _, err := db.GetDevice(ctx, tenancy.DefaultTenantID, a.ID)
	if err != nil || gotA == nil {
		t.Fatalf("GetDevice own = %v, %v", gotA, err)
	}

	listB, _, err := db.ListEnrolledDevices(ctx, other, "", "", 0, 0)
	if err != nil {
		t.Fatalf("list other: %v", err)
	}
	foundB := false
	for _, d := range listB {
		if d.ID == a.ID {
			t.Fatal("other list leaked default device")
		}
		if d.ID == bID {
			foundB = true
		}
	}
	if !foundB {
		t.Fatal("other list missing its device")
	}
}

// TestCrossTenant_MutationsRefuseForeignIDs — delete/update чужого id не трогает строку.
func TestCrossTenant_MutationsRefuseForeignIDs(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	other := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'Other2') ON CONFLICT DO NOTHING`, other,
	); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	s, err := db.CreateScript(ctx, other, "foreign-"+uniq(t), "Linux", "echo 1")
	if err != nil {
		t.Fatalf("create foreign script: %v", err)
	}
	if err := db.DeleteScript(ctx, tenancy.DefaultTenantID, s.ID); err != nil {
		t.Fatalf("delete as default: %v", err)
	}
	got, err := db.GetScript(ctx, other, s.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("foreign script deleted via wrong tenant")
	}
}

func TestListDevicesAcrossTenants_SeesBoth(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	other := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'Cross') ON CONFLICT DO NOTHING`, other,
	); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	a := mustCreateActiveDevice(t, db, "cross-a-"+uniq(t), "linux")
	var bID string
	otherCtx, finish, err := db.BindTenant(ctx, other)
	if err != nil {
		t.Fatalf("bind other tenant: %v", err)
	}
	if err := db.Q(otherCtx).QueryRow(otherCtx, `
		INSERT INTO devices (hostname, os, status, tenant_id)
		VALUES ($1, 'linux', 'active', $2)
		RETURNING id::text`, "cross-b-"+uniq(t), other,
	).Scan(&bID); err != nil {
		finish(false)
		t.Fatalf("device B: %v", err)
	}
	finish(true)
	list, total, err := db.ListDevicesAcrossTenants(ctx, "", "", 500, 0)
	if err != nil {
		t.Fatalf("ListDevicesAcrossTenants: %v", err)
	}
	if total < 2 {
		t.Fatalf("total = %d, want >= 2", total)
	}
	foundA, foundB := false, false
	for _, d := range list {
		if d.ID == a.ID {
			foundA = true
			if d.TenantID != tenancy.DefaultTenantID {
				t.Errorf("device A tenant = %q", d.TenantID)
			}
		}
		if d.ID == bID {
			foundB = true
			if d.TenantID != other {
				t.Errorf("device B tenant = %q", d.TenantID)
			}
		}
	}
	if !foundA || !foundB {
		t.Fatalf("foundA=%v foundB=%v in %d rows", foundA, foundB, len(list))
	}
}
