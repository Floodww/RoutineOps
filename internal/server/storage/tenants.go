package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

type Tenant struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	RequireMFA bool      `json:"require_mfa"`
	CreatedAt  time.Time `json:"created_at"`
}

func (db *DB) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := db.pool.Query(ctx, `SELECT id::text, name, require_mfa, created_at FROM tenants WHERE deleted_at IS NULL ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.RequireMFA, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	var t Tenant
	err := db.pool.QueryRow(ctx, `SELECT id::text, name, require_mfa, created_at FROM tenants WHERE id = $1::uuid AND deleted_at IS NULL`, id).
		Scan(&t.ID, &t.Name, &t.RequireMFA, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

func (db *DB) CreateTenant(ctx context.Context, name string) (*Tenant, error) {
	var t Tenant
	err := db.pool.QueryRow(ctx, `
		INSERT INTO tenants (id, name) VALUES (gen_random_uuid(), $1)
		RETURNING id::text, name, require_mfa, created_at
	`, name).Scan(&t.ID, &t.Name, &t.RequireMFA, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (db *DB) SetTenantMFA(ctx context.Context, tenantID string, requireMFA bool) error {
	tag, err := db.pool.Exec(ctx, `UPDATE tenants SET require_mfa = $2 WHERE id = $1::uuid AND deleted_at IS NULL`, tenantID, requireMFA)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (db *DB) RenameTenant(ctx context.Context, id, name string) error {
	tag, err := db.pool.Exec(ctx, `UPDATE tenants SET name = $2 WHERE id = $1::uuid AND deleted_at IS NULL`, id, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (db *DB) CountTenants(ctx context.Context) (int, error) {
	var n int
	err := db.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE deleted_at IS NULL`).Scan(&n)
	return n, err
}

// ErrTenantUndeletable — попытка удалить тенант по умолчанию.
var ErrTenantUndeletable = errors.New("tenant: удалить тенант по умолчанию нельзя")

// DeleteTenant переносит содержимое тенанта в Default и помечает его удалённым.
//
// Вся работа делается одной DEFINER-функцией admin_reparent_tenant (056), а не
// набором UPDATE'ов отсюда: перенос затрагивает ДВА тенанта сразу — строки читаются
// предикатом исходного, пишутся под WITH CHECK целевого, — и одним значением GUC обе
// половины предиката RLS не удовлетворить. Первая версия пыталась и падала 22P02.
func (db *DB) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == tenancy.DefaultTenantID {
		return ErrTenantUndeletable
	}
	var exists bool
	if err := db.pool.QueryRow(ctx,
		`SELECT true FROM tenants WHERE id = $1::uuid AND deleted_at IS NULL`, tenantID,
	).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return pgx.ErrNoRows
		}
		return err
	}
	if _, err := db.pool.Exec(ctx,
		`SELECT admin_reparent_tenant($1::uuid, $2::uuid)`, tenantID, tenancy.DefaultTenantID,
	); err != nil {
		return fmt.Errorf("перенос содержимого тенанта: %w", err)
	}
	return nil
}

// MoveDeviceToTenant переносит устройство в другой тенант.
//
// Работа делается DEFINER-функцией (057) по той же причине, что и перенос тенанта:
// операция затрагивает два тенанта, а GUC — одно значение. Членство в группах при
// переносе снимается, владелец отвязывается: и то и другое принадлежит покинутому
// тенанту (обоснование — в комментарии миграции).
func (db *DB) MoveDeviceToTenant(ctx context.Context, deviceID, dstTenantID string) error {
	_, err := db.pool.Exec(ctx,
		`SELECT admin_move_device_tenant($1::uuid, $2::uuid)`, deviceID, dstTenantID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "P0002" {
			return pgx.ErrNoRows
		}
		return fmt.Errorf("перенос устройства в тенант: %w", err)
	}
	return nil
}
