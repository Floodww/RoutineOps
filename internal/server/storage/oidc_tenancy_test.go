package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"github.com/jackc/pgx/v5"
)

// Q-20: oidc_providers до 051 жила вне мультитенантности — без tenant_id, вне RLS и
// мимо BindTenant. Тесты ниже фиксируют обе половины дыры: чужой IdP не читается и не
// правится из соседнего тенанта, а матч пользователя по e-mail не уходит за границу
// тенанта провайдера (иначе IdP тенанта A выдавал бы вход в одноимённую учётку B).

const oidcOtherTenant = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

func TestOIDCProvider_CrossTenantHidden(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'OIDC Other') ON CONFLICT DO NOTHING`, oidcOtherTenant,
	); err != nil {
		t.Fatalf("other tenant: %v", err)
	}

	name := "IdP-" + uniq(t)
	id, err := db.CreateOIDCProvider(ctx, tenancy.DefaultTenantID,
		name, "client-a", "enc-a", "https://idp.test.local", "https://panel.test.local/cb")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	if got, err := db.GetOIDCProvider(ctx, oidcOtherTenant, id); err != nil || got != nil {
		t.Fatalf("GetOIDCProvider across tenants = %+v, %v; want nil, nil", got, err)
	}

	list, err := db.ListOIDCProviders(ctx, oidcOtherTenant)
	if err != nil {
		t.Fatalf("list other: %v", err)
	}
	for _, p := range list {
		if p.ID == id {
			t.Fatalf("ListOIDCProviders leaked foreign provider %s", id)
		}
	}

	// Правка и удаление из чужого тенанта не должны находить строку — и обязаны сказать
	// об этом (Q-29): молчаливый nil уходил наружу как 204, то есть «применено».
	if err := db.UpdateOIDCProvider(ctx, oidcOtherTenant, id,
		"hijacked", "client-b", "enc-b", "https://evil.test.local", "https://evil.test.local/cb", false); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("update from other tenant = %v; want pgx.ErrNoRows", err)
	}
	if err := db.DeleteOIDCProvider(ctx, oidcOtherTenant, id); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("delete from other tenant = %v; want pgx.ErrNoRows", err)
	}

	own, err := db.GetOIDCProvider(ctx, tenancy.DefaultTenantID, id)
	if err != nil {
		t.Fatalf("get own: %v", err)
	}
	if own == nil {
		t.Fatal("provider deleted from another tenant")
	}
	if own.Name != name || !own.Enabled {
		t.Fatalf("provider modified from another tenant: %+v", own)
	}
}

// AuthOIDCProvider — пре-авторизационный резолв: тенанта в контексте нет (callback
// анонимный), строка обязана находиться и приносить свой tenant_id.
func TestAuthOIDCProvider_ResolvesTenantWithoutScope(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	id, err := db.CreateOIDCProvider(ctx, tenancy.DefaultTenantID,
		"IdP-"+uniq(t), "client", "enc", "https://idp.test.local", "https://panel.test.local/cb")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	p, err := db.AuthOIDCProvider(ctx, id)
	if err != nil {
		t.Fatalf("AuthOIDCProvider: %v", err)
	}
	if p == nil {
		t.Fatal("AuthOIDCProvider returned nil for existing provider")
	}
	if p.TenantID != tenancy.DefaultTenantID {
		t.Fatalf("tenant = %q, want %q", p.TenantID, tenancy.DefaultTenantID)
	}

	missing, err := db.AuthOIDCProvider(ctx, "00000000-0000-4000-8000-0000000000ff")
	if err != nil || missing != nil {
		t.Fatalf("AuthOIDCProvider(missing) = %+v, %v; want nil, nil", missing, err)
	}
}

// Матч по e-mail не пересекает границу тенанта: та же почта в соседнем тенанте —
// другой человек, и IdP тенанта провайдера не имеет к нему отношения.
func TestGetUserByEmailInTenant_DoesNotCrossTenants(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	if _, err := db.Pool().Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, 'OIDC Other') ON CONFLICT DO NOTHING`, oidcOtherTenant,
	); err != nil {
		t.Fatalf("other tenant: %v", err)
	}

	email := "sso-" + uniq(t) + "@example.com"
	own := mustCreateUser(t, db, email)

	got, err := db.GetUserByEmailInTenant(ctx, tenancy.DefaultTenantID, email)
	if err != nil {
		t.Fatalf("lookup own tenant: %v", err)
	}
	if got == nil || got.ID != own.ID {
		t.Fatalf("own tenant lookup = %+v, want user %s", got, own.ID)
	}

	foreign, err := db.GetUserByEmailInTenant(ctx, oidcOtherTenant, email)
	if err != nil {
		t.Fatalf("lookup other tenant: %v", err)
	}
	if foreign != nil {
		t.Fatalf("e-mail matched across tenants: %+v", foreign)
	}
}
