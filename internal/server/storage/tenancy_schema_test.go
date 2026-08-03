package storage_test

import (
	"context"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// TestTenantBackfill_DefaultCoversExistingRows — после 045 одно-тенантная
// инсталляция: default tenant есть, новые строки получают его DEFAULT'ом,
// два тенанта могут иметь одинаковый email.
func TestTenantBackfill_DefaultCoversExistingRows(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	var name string
	err := db.Pool().QueryRow(ctx,
		`SELECT name FROM tenants WHERE id = $1`, tenancy.DefaultTenantID,
	).Scan(&name)
	if err != nil {
		t.Fatalf("default tenant missing: %v", err)
	}
	if name != "Default" {
		t.Fatalf("default tenant name = %q", name)
	}

	u := mustCreateUser(t, db, "alice-"+uniq(t)+"@example.com")
	var tid string
	if err := db.Pool().QueryRow(ctx,
		`SELECT tenant_id::text FROM users WHERE id = $1`, u.ID,
	).Scan(&tid); err != nil {
		t.Fatalf("user tenant: %v", err)
	}
	if tid != tenancy.DefaultTenantID {
		t.Fatalf("user tenant_id = %q, want default", tid)
	}

	// ADR-7 (052): один e-mail — одна ЛИЧНОСТЬ, а участие в двух тенантах выражается
	// двумя членствами этой личности. До 052 тут проверялась пер-тенантная
	// уникальность e-mail; она и породила Q-22 (логин резолвится до тенанта и на
	// дубле становился неоднозначным), поэтому смысл проверки изменился вместе со
	// схемой: дублируется не человек, а его членство.
	other := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'Other')`, other,
	); err != nil {
		t.Fatalf("insert other tenant: %v", err)
	}
	email := "shared-" + uniq(t) + "@example.com"
	identityID, created, err := db.EnsureIdentity(ctx, email, "h")
	if err != nil || !created {
		t.Fatalf("EnsureIdentity = %q, created=%v, err=%v", identityID, created, err)
	}
	// Тот же e-mail второй раз — НЕ новая личность, а та же самая.
	againID, created, err := db.EnsureIdentity(ctx, email, "other-hash")
	if err != nil {
		t.Fatalf("EnsureIdentity#2: %v", err)
	}
	if created || againID != identityID {
		t.Fatalf("повторный e-mail завёл вторую личность: %q != %q (created=%v)", againID, identityID, created)
	}

	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO users (name, email, role, tenant_id, identity_id)
		VALUES ('A', $1, 'viewer', $2, $3)`, email, tenancy.DefaultTenantID, identityID); err != nil {
		t.Fatalf("членство в default: %v", err)
	}
	otherCtx, finish, err := db.BindTenant(ctx, other)
	if err != nil {
		t.Fatalf("bind other: %v", err)
	}
	if _, err := db.Q(otherCtx).Exec(otherCtx, `
		INSERT INTO users (name, email, role, tenant_id, identity_id)
		VALUES ('B', $1, 'viewer', $2, $3)`, email, other, identityID); err != nil {
		finish(false)
		t.Fatalf("членство той же личности в другом тенанте должно быть разрешено: %v", err)
	}
	finish(true)

	// Два членства одной личности в ОДНОМ тенанте — конфликт: было бы две роли сразу.
	_, err = db.Pool().Exec(ctx, `
		INSERT INTO users (name, email, role, tenant_id, identity_id)
		VALUES ('C', $1, 'viewer', $2, $3)`, email, tenancy.DefaultTenantID, identityID)
	if err == nil {
		t.Fatal("второе членство той же личности в том же тенанте должно падать")
	}

	// Личность видит оба своих тенанта — это источник данных для селектора.
	ms, err := db.ListMemberships(ctx, identityID)
	if err != nil {
		t.Fatalf("ListMemberships: %v", err)
	}
	if len(ms) != 2 {
		t.Fatalf("членств = %d, want 2: %+v", len(ms), ms)
	}
}
