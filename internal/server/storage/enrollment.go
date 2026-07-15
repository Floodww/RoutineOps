package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type EnrollmentToken struct {
	ID        string
	DeviceID  string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// hashEnrollToken — SHA-256(hex) enrollment-токена для хранения и поиска (N6).
// Токен высокоэнтропийный (UUID v4 / rand hex), поэтому детерминированный хеш без
// соли безопасен и позволяет искать по равенству. Plaintext в БД не хранится.
func hashEnrollToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ErrEnrollTokenAlreadyUsed — enrollment-токен уже погашен. Guarded UPDATE
// (WHERE used_at IS NULL) + проверка RowsAffected закрывают гонку single-use:
// два параллельных redeem больше не выдают два серта на один токен (E/TOCTOU).
var ErrEnrollTokenAlreadyUsed = errors.New("enrollment token already used")

func (db *DB) CreatePendingDevice(ctx context.Context, hostname, os string) (*Device, error) {
	var d Device
	err := db.pool.QueryRow(ctx, `
		INSERT INTO devices (hostname, os, status)
		VALUES ($1, $2, 'pending')
		RETURNING id, hostname, os, COALESCE(os_version, ''), COALESCE(ip_address, ''),
		          status, last_seen_at, created_at
	`, hostname, os).Scan(&d.ID, &d.Hostname, &d.OS, &d.OSVersion,
		&d.IPAddress, &d.Status, &d.LastSeenAt, &d.CreatedAt)
	return &d, err
}

func (db *DB) CreateEnrollmentToken(ctx context.Context, deviceID, token string, expiresAt time.Time) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO enrollment_tokens (device_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, deviceID, hashEnrollToken(token), expiresAt)
	return err
}

func (db *DB) GetEnrollmentToken(ctx context.Context, token string) (*EnrollmentToken, error) {
	var t EnrollmentToken
	err := db.pool.QueryRow(ctx, `
		SELECT id, device_id, expires_at, used_at, created_at
		FROM enrollment_tokens WHERE token_hash = $1
	`, hashEnrollToken(token)).Scan(&t.ID, &t.DeviceID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

func (db *DB) GetActiveEnrollmentToken(ctx context.Context, deviceID string) (*EnrollmentToken, error) {
	var t EnrollmentToken
	err := db.pool.QueryRow(ctx, `
		SELECT id, device_id, expires_at, used_at, created_at
		FROM enrollment_tokens
		WHERE device_id = $1 AND used_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC LIMIT 1
	`, deviceID).Scan(&t.ID, &t.DeviceID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// EnrollDevice помечает токен использованным и переводит устройство в 'enrolled'.
// certFingerprint (sha256 выданного серта) сохраняется здесь, чтобы первый
// heartbeat (UpsertDeviceHeartbeat, ON CONFLICT по certificate_fingerprint) обновил
// ЭТУ же строку, а не создал дубль устройства (БАГ 4). Пустой отпечаток не трогает
// колонку — обратная совместимость со старыми вызовами.
func (db *DB) EnrollDevice(ctx context.Context, tokenID, deviceID, certSerial, certFingerprint string) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	ct, err := tx.Exec(ctx,
		`UPDATE enrollment_tokens SET used_at = now() WHERE id = $1 AND used_at IS NULL`, tokenID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		// Токен уже погашен (в т.ч. параллельным redeem) — единоразовость (E/TOCTOU).
		return ErrEnrollTokenAlreadyUsed
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET status = 'enrolled', cert_serial = $2, enrolled_at = now(),
		    certificate_fingerprint = COALESCE(NULLIF($3, ''), certificate_fingerprint)
		WHERE id = $1
	`, deviceID, certSerial, certFingerprint); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (db *DB) UpdatePendingDeviceInfo(ctx context.Context, deviceID, hostname, os string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE devices SET
		  hostname = CASE WHEN $2 != '' THEN $2 ELSE hostname END,
		  os       = CASE WHEN $3 != '' THEN $3 ELSE os END
		WHERE id = $1 AND status = 'pending'
	`, deviceID, hostname, os)
	return err
}

func (db *DB) ResetDeviceForReenroll(ctx context.Context, deviceID, newToken string, expiresAt time.Time) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`UPDATE enrollment_tokens SET used_at = now() WHERE device_id = $1 AND used_at IS NULL`,
		deviceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE devices SET status = 'pending', cert_serial = NULL, enrolled_at = NULL WHERE id = $1`,
		deviceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO enrollment_tokens (device_id, token_hash, expires_at) VALUES ($1, $2, $3)
	`, deviceID, hashEnrollToken(newToken), expiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
