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
	ID              string
	DeviceID        string // "" для bulk-токена (device_id NULL — не привязан к устройству)
	GroupID         string // "" если партия без группы
	MaxUses         *int   // nil = безлимит до ExpiresAt
	Uses            int
	RequireApproval bool
	ExpiresAt       time.Time
	UsedAt          *time.Time
	CreatedAt       time.Time
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

// ErrDeviceNotReenrollable — реенролл запрошен для устройства в статусе, из которого
// возврат в строй обязан идти через выделенную ручку, а не в обход неё.
var ErrDeviceNotReenrollable = errors.New("device status forbids reenroll")

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
	// device_id теперь nullable (bulk-токен): COALESCE(::text,'') → "" для bulk.
	err := db.pool.QueryRow(ctx, `
		SELECT id, COALESCE(device_id::text, ''), COALESCE(group_id::text, ''),
		       max_uses, uses, require_approval, expires_at, used_at, created_at
		FROM enrollment_tokens WHERE token_hash = $1
	`, hashEnrollToken(token)).Scan(&t.ID, &t.DeviceID, &t.GroupID,
		&t.MaxUses, &t.Uses, &t.RequireApproval, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// CreateBulkEnrollmentToken выпускает многоразовый токен, НЕ привязанный к устройству
// (device_id NULL). groupID/maxUses опциональны ("" / nil). requireApproval решает
// вызывающий (дефолт политики — в ручке). Устройства создаются сами при энролле.
func (db *DB) CreateBulkEnrollmentToken(ctx context.Context, token, groupID string, maxUses *int, requireApproval bool, expiresAt time.Time) error {
	var gid *string
	if groupID != "" {
		gid = &groupID
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO enrollment_tokens (device_id, group_id, token_hash, max_uses, require_approval, expires_at)
		VALUES (NULL, $1, $2, $3, $4, $5)
	`, gid, hashEnrollToken(token), maxUses, requireApproval, expiresAt)
	return err
}

// BeginBulkEnroll атомарно резервирует ОДНО использование bulk-токена (проверка
// max_uses/срока — гонку закрывает guarded UPDATE ... uses+1 с RETURNING), создаёт
// устройство (status 'pending') и привязывает к группе токена. Возвращает id
// устройства и require_approval. ErrEnrollTokenAlreadyUsed = лимит исчерпан / срок
// вышел / это не bulk-токен (device_id задан).
//
// Устройство создаётся ДО подписи CSR, потому что CN серта = id устройства
// (SignCSR(csr, deviceID)); статус и серт доставляет FinalizeBulkEnroll после подписи.
// ⚠ ponytail: если SignCSR упадёт между Begin и Finalize (битый CSR — ошибка клиента),
// останется осиротевшее 'pending'-устройство + одно израсходованное использование.
// Это тот же осадок, что от любого недоведённого энролла; редко и не деструктивно.
func (db *DB) BeginBulkEnroll(ctx context.Context, tokenID, hostname, os string) (deviceID string, requireApproval bool, err error) {
	if hostname == "" {
		hostname = "unknown" // первый ReportInventory перепишет (pending_approval шлёт инвентарь)
	}
	if os == "" {
		os = "unknown"
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx)

	var groupID *string
	err = tx.QueryRow(ctx, `
		UPDATE enrollment_tokens SET uses = uses + 1
		WHERE id = $1 AND device_id IS NULL
		  AND (max_uses IS NULL OR uses < max_uses)
		  AND expires_at > now()
		RETURNING group_id::text, require_approval
	`, tokenID).Scan(&groupID, &requireApproval)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, ErrEnrollTokenAlreadyUsed
		}
		return "", false, err
	}

	if err = tx.QueryRow(ctx,
		`INSERT INTO devices (hostname, os, status) VALUES ($1, $2, 'pending') RETURNING id`,
		hostname, os).Scan(&deviceID); err != nil {
		return "", false, err
	}

	if groupID != nil && *groupID != "" {
		if _, err = tx.Exec(ctx,
			`INSERT INTO device_group_members (device_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			deviceID, *groupID); err != nil {
			return "", false, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return "", false, err
	}
	return deviceID, requireApproval, nil
}

// FinalizeBulkEnroll ставит статус и серт после подписи CSR. require_approval →
// 'pending_approval' (ждёт одобрения, gateway гейтит политики/скрипты), иначе
// 'enrolled' (обычный heartbeat поднимет в 'active'). certFingerprint — как в
// EnrollDevice: чтобы первый heartbeat обновил ЭТУ строку, а не создал дубль.
func (db *DB) FinalizeBulkEnroll(ctx context.Context, deviceID, certSerial, certFingerprint string, requireApproval bool) error {
	status := "enrolled"
	if requireApproval {
		status = "pending_approval"
	}
	_, err := db.pool.Exec(ctx, `
		UPDATE devices SET status = $2, cert_serial = $3, enrolled_at = now(),
		    certificate_fingerprint = COALESCE(NULLIF($4, ''), certificate_fingerprint)
		WHERE id = $1
	`, deviceID, status, certSerial, certFingerprint)
	return err
}

// ApproveDevice одобряет устройство из очереди: pending_approval → active. Возвращает
// false, если устройство не было в очереди (guarded — идемпотентно, не трогает чужие статусы).
func (db *DB) ApproveDevice(ctx context.Context, deviceID string) (bool, error) {
	ct, err := db.pool.Exec(ctx,
		`UPDATE devices SET status = 'active' WHERE id = $1 AND status = 'pending_approval'`, deviceID)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// RejectDevice отклоняет устройство из очереди: pending_approval → rejected (терминальный,
// gateway режет Connect/heartbeat/все RPC как blocked). false = не было в очереди.
func (db *DB) RejectDevice(ctx context.Context, deviceID string) (bool, error) {
	ct, err := db.pool.Exec(ctx,
		`UPDATE devices SET status = 'rejected' WHERE id = $1 AND status = 'pending_approval'`, deviceID)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// ApprovePendingDevices — batch-одобрение: все pending_approval (groupID "" ) или только
// члены группы (groupID = uuid). Возвращает число одобренных.
func (db *DB) ApprovePendingDevices(ctx context.Context, groupID string) (int64, error) {
	ct, err := db.pool.Exec(ctx, `
		UPDATE devices SET status = 'active'
		WHERE status = 'pending_approval'
		  AND ($1 = '' OR id IN (SELECT device_id FROM device_group_members WHERE group_id::text = $1))
	`, groupID)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// RejectPendingDevices — batch-отклонение (симметрично ApprovePendingDevices).
func (db *DB) RejectPendingDevices(ctx context.Context, groupID string) (int64, error) {
	ct, err := db.pool.Exec(ctx, `
		UPDATE devices SET status = 'rejected'
		WHERE status = 'pending_approval'
		  AND ($1 = '' OR id IN (SELECT device_id FROM device_group_members WHERE group_id::text = $1))
	`, groupID)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
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
	// 🔴 Гейт по статусу — здесь, а не в хендлере: реенролл ставит 'pending', а хартбит
	// поднимает 'pending' → 'active' (UpsertDeviceHeartbeat), причём сертификат остаётся
	// валидным (обнуляем только cert_serial). Без этого условия реенролл был обходной
	// дверью в managed-статусы: отклонённое устройство возвращалось в строй БЕЗ повторного
	// одобрения, заблокированное — в обход kill-switch, стоящее в очереди — мимо approve.
	// Ровно то, что запрещает гейт в updateDeviceStatus (handler.go), только там дверь
	// закрыли, а эту забыли. В storage, чтобы закрыть для всех вызывающих сразу.
	ct, err := tx.Exec(ctx,
		`UPDATE devices SET status = 'pending', cert_serial = NULL, enrolled_at = NULL
		 WHERE id = $1 AND status NOT IN ('pending_approval', 'rejected', 'decommissioned', 'blocked')`,
		deviceID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrDeviceNotReenrollable
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO enrollment_tokens (device_id, token_hash, expires_at) VALUES ($1, $2, $3)
	`, deviceID, hashEnrollToken(newToken), expiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
