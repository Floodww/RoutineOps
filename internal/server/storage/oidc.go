package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// OIDCProvider — OIDC-провайдер для SSO (enterprise). client_secret хранится в
// зашифрованном виде — шифрование/дешифрование выполняет вызывающий (oidc.Service).
type OIDCProvider struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"-"` // тенант, которому принадлежит IdP (051)
	Name            string    `json:"name"`
	ClientID        string    `json:"client_id"`
	ClientSecretEnc string    `json:"-"` // зашифровано, наружу не отдаётся
	IssuerURL       string    `json:"issuer_url"`
	RedirectURI     string    `json:"redirect_uri"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
}

// CreateOIDCProvider создаёт нового OIDC-провайдера в тенанте. clientSecretEnc должен
// быть зашифрован перед передачей — storage хранит непрозрачный blob.
func (db *DB) CreateOIDCProvider(ctx context.Context, tenantID, name, clientID, clientSecretEnc, issuerURL, redirectURI string) (string, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return "", err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return "", err
		}
		defer finish(true)
	}
	var id string
	err = db.Q(ctx).QueryRow(ctx, `
		INSERT INTO oidc_providers (tenant_id, name, client_id, client_secret, issuer_url, redirect_uri)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`,
		tenantID, name, clientID, clientSecretEnc, issuerURL, redirectURI,
	).Scan(&id)
	return id, err
}

// GetOIDCProvider возвращает провайдера тенанта по ID. Возвращает nil, nil если не найден.
func (db *DB) GetOIDCProvider(ctx context.Context, tenantID, id string) (*OIDCProvider, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	p := &OIDCProvider{}
	err = db.Q(ctx).QueryRow(ctx, `
		SELECT id, tenant_id, name, client_id, client_secret, issuer_url, redirect_uri, enabled, created_at
		FROM oidc_providers
		WHERE tenant_id = $1 AND id = $2`, tenantID, id,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.ClientID, &p.ClientSecretEnc, &p.IssuerURL, &p.RedirectURI, &p.Enabled, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// AuthOIDCProvider резолвит провайдера по id ДО входа (begin/callback): тенанта в
// контексте ещё нет, поэтому идём через SECURITY DEFINER (051) — как auth_user_by_email.
// Тенант вызывающий берёт из TenantID вернувшейся строки. Возвращает nil, nil если нет.
func (db *DB) AuthOIDCProvider(ctx context.Context, id string) (*OIDCProvider, error) {
	p := &OIDCProvider{}
	err := db.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, client_id, client_secret, issuer_url, redirect_uri, enabled, created_at
		FROM auth_oidc_provider($1)`, id,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.ClientID, &p.ClientSecretEnc, &p.IssuerURL, &p.RedirectURI, &p.Enabled, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// ListOIDCProviders возвращает провайдеров тенанта, отсортированных по created_at.
func (db *DB) ListOIDCProviders(ctx context.Context, tenantID string) ([]OIDCProvider, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	rows, err := db.Q(ctx).Query(ctx, `
		SELECT id, tenant_id, name, client_id, client_secret, issuer_url, redirect_uri, enabled, created_at
		FROM oidc_providers
		WHERE tenant_id = $1
		ORDER BY created_at ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []OIDCProvider
	for rows.Next() {
		var p OIDCProvider
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.ClientID, &p.ClientSecretEnc,
			&p.IssuerURL, &p.RedirectURI, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	if providers == nil {
		providers = []OIDCProvider{}
	}
	return providers, rows.Err()
}

// UpdateOIDCProvider обновляет провайдера тенанта. Если clientSecretEnc == "", секрет
// не трогается. Чужой провайдер не найдётся: предикат по tenant_id + RLS.
func (db *DB) UpdateOIDCProvider(ctx context.Context, tenantID, id, name, clientID, clientSecretEnc, issuerURL, redirectURI string, enabled bool) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	var tag pgconn.CommandTag
	if clientSecretEnc != "" {
		tag, err = db.Q(ctx).Exec(ctx, `
			UPDATE oidc_providers
			SET name=$3, client_id=$4, client_secret=$5, issuer_url=$6, redirect_uri=$7, enabled=$8
			WHERE tenant_id=$1 AND id=$2`,
			tenantID, id, name, clientID, clientSecretEnc, issuerURL, redirectURI, enabled)
	} else {
		tag, err = db.Q(ctx).Exec(ctx, `
			UPDATE oidc_providers
			SET name=$3, client_id=$4, issuer_url=$5, redirect_uri=$6, enabled=$7
			WHERE tenant_id=$1 AND id=$2`,
			tenantID, id, name, clientID, issuerURL, redirectURI, enabled)
	}
	if err != nil {
		return err
	}
	// Ноль строк — это «не найдено» (чужой или несуществующий id), а не успех: наружу
	// уходило 204, и правка чужого IdP выглядела применённой.
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// DeleteOIDCProvider удаляет провайдера тенанта по ID.
func (db *DB) DeleteOIDCProvider(ctx context.Context, tenantID, id string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	tag, err := db.Q(ctx).Exec(ctx, `DELETE FROM oidc_providers WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
