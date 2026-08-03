package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ADR-7 (docs/multitenancy-contract.md §11): личность — человек, членство — его
// строка в тенанте. Пароль принадлежит личности, роль — членству.
//
// Все запросы этого файла идут либо к глобальной таблице identities (RLS на ней
// нет — §3.3), либо через SECURITY DEFINER функции 052. Причина одна и та же:
// вход и переключение тенанта происходят ДО того, как активный тенант известен,
// поэтому тенантного скоупа в этот момент ещё не существует.

// Identity — человек: глобально уникальный e-mail, пароль, признак надзора.
type Identity struct {
	ID                string    `json:"id"`
	Email             string    `json:"email"`
	PasswordHash      string    `json:"-"`
	PasswordChangedAt time.Time `json:"-"`
	IsProviderAdmin   bool      `json:"is_provider_admin"`
	CreatedAt         time.Time `json:"created_at"`
	MfaEnabled        bool      `json:"mfa_enabled"`
	MfaSecret         *string   `json:"-"`
	RecoveryCodes     []string  `json:"-"`
}

// Membership — членство личности в тенанте. UserID — та самая строка users, чей
// идентификатор уезжает в JWT: активный тенант определяется ею, а не отдельным
// полем токена (ADR-6 остаётся в силе).
type Membership struct {
	UserID     string `json:"user_id"`
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	Role       string `json:"role"`
}

// GetIdentityByEmail резолвит личность по e-mail до входа. nil, nil если нет.
func (db *DB) GetIdentityByEmail(ctx context.Context, email string) (*Identity, error) {
	var i Identity
	err := db.pool.QueryRow(ctx, `
		SELECT id::text, email, password_hash, password_changed_at, is_provider_admin, created_at,
		       mfa_enabled, mfa_secret, recovery_codes
		FROM auth_identity_by_email($1)`, email,
	).Scan(&i.ID, &i.Email, &i.PasswordHash, &i.PasswordChangedAt, &i.IsProviderAdmin, &i.CreatedAt,
		&i.MfaEnabled, &i.MfaSecret, &i.RecoveryCodes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// ListMemberships возвращает тенанты, в которых состоит личность, отсортированные
// по имени тенанта. Порядок детерминирован намеренно: первый элемент — тенант, в
// который человек попадает сразу после входа, и он не должен «прыгать» между
// входами.
func (db *DB) ListMemberships(ctx context.Context, identityID string) ([]Membership, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT user_id::text, tenant_id::text, tenant_name, role
		FROM auth_identity_memberships($1::uuid)`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.UserID, &m.TenantID, &m.TenantName, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if out == nil {
		out = []Membership{}
	}
	return out, rows.Err()
}

// FindMembership ищет членство личности в конкретном тенанте. nil, nil = человек в
// этот тенант не входит. Это и есть проверка при переключении: тенант, которого нет
// в списке, недоступен, сколько бы его ни просили.
func (db *DB) FindMembership(ctx context.Context, identityID, tenantID string) (*Membership, error) {
	all, err := db.ListMemberships(ctx, identityID)
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.TenantID == tenantID {
			return &m, nil
		}
	}
	return nil, nil
}

// UpdateIdentityPassword меняет пароль личности и двигает password_changed_at=now()
// (token-epoch): все ранее выпущенные JWT становятся недействительны — во ВСЕХ
// тенантах сразу, потому что пароль у человека один.
func (db *DB) UpdateIdentityPassword(ctx context.Context, identityID, passwordHash string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE identities SET password_hash = $2, password_changed_at = now() WHERE id = $1`,
		identityID, passwordHash)
	return err
}

// PromoteBootstrapProviderAdmin выдаёт надзор над инсталляцией личности с этим
// e-mail — но ТОЛЬКО если она в инсталляции единственная. Возвращает, выдан ли флаг.
//
// Зачем условие. После ADR-7 надзор — признак личности, а не роль в тенанте, и ставить
// его стало неоткуда: сид-админ заводится обычным it_admin в Default, а создание тенанта
// уже требует requireProviderAdmin. На чистой установке мультитенантность оказывалась
// недостижима без ручного UPDATE в БД (найдено полевым e2e 30.07).
//
// Дефолт `true` для всех личностей был бы неверным ответом: тогда любой приглашённый
// viewer получал бы надзор над всей инсталляцией. Здесь работает тот же принцип, что уже
// действует для роли первого админа, — права получает ТОЛЬКО бутстрап-личность. Счётчик
// личностей и есть определение бутстрапа: на живой инсталляции повторный запуск с
// SEED_ADMIN_* надзор молча не выдаст.
func (db *DB) PromoteBootstrapProviderAdmin(ctx context.Context, email string) (bool, error) {
	var granted bool
	err := db.pool.QueryRow(ctx, `
		UPDATE identities SET is_provider_admin = true
		WHERE lower(email) = lower($1)
		  AND (SELECT count(*) FROM identities) = 1
		RETURNING is_provider_admin`, email).Scan(&granted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return granted, err
}

// EnsureIdentity возвращает id личности с этим e-mail, создавая её при отсутствии.
// Используется при заведении пользователя: если человек уже состоит в другом
// тенанте, новая учётка НЕ создаётся — добавляется членство к существующей личности,
// и пароль остаётся прежним (один человек — один пароль).
func (db *DB) EnsureIdentity(ctx context.Context, email, passwordHash string) (string, bool, error) {
	if existing, err := db.GetIdentityByEmail(ctx, email); err != nil {
		return "", false, err
	} else if existing != nil {
		return existing.ID, false, nil
	}
	var id string
	err := db.pool.QueryRow(ctx, `
		INSERT INTO identities (email, password_hash) VALUES ($1, $2)
		RETURNING id::text`, email, passwordHash).Scan(&id)
	return id, true, err
}

// SetMFA обновляет состояние MFA для личности.
func (db *DB) SetMFA(ctx context.Context, identityID string, enabled bool, secret *string, recoveryCodes []string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE identities
		SET mfa_enabled = $2, mfa_secret = $3, recovery_codes = $4
		WHERE id = $1`, identityID, enabled, secret, recoveryCodes)
	return err
}
