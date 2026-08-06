package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Улики сессии админ-прав. Контракт с агентской стороной зафиксирован во внутреннем
// документе (в публичный срез он не едет — ссылку сюда не возвращать).
// Таблица append-only (K-1): ON CONFLICT DO NOTHING, никаких DELETE на пути приёма.

const (
	// MaxAdminSessionChanges — потолок len(changes) на одно окно. Свыше → InvalidArgument
	// у gateway (терминален у агента, очередь не отравляется).
	MaxAdminSessionChanges = 1000
	// MaxAdminSessionFieldBytes — обрезка строковых полей одной записи дельты.
	MaxAdminSessionFieldBytes = 512
	// MaxAdminSessionSeqJump — окно с seq > last_window_seq + N отвергается (K-2):
	// монотонный счётчик подотчётной стороны нельзя использовать как фильтр отбрасывания,
	// но прыжок на миллиард — явный мусор/атака.
	MaxAdminSessionSeqJump = 64
	// AdminSessionEvidenceGrace — сколько ждать финальное окно после закрытия сессии
	// (revoked_at / момент перехода в expired), прежде чем поднимать алерт.
	AdminSessionEvidenceGrace = 2 * time.Hour
)

// AdminSessionChange — одна строка дельты (ПО или служба).
type AdminSessionChange struct {
	ID                string    `json:"id,omitempty"`
	RequestID         string    `json:"request_id,omitempty"`
	DeviceID          string    `json:"device_id,omitempty"`
	WindowSeq         int32     `json:"window_seq"`
	Kind              string    `json:"kind"`
	Subject           string    `json:"subject"`
	DisplayName       string    `json:"display_name"`
	IdentityKey       string    `json:"identity_key"`
	OldValue          string    `json:"old_value"`
	NewValue          string    `json:"new_value"`
	Vendor            string    `json:"vendor"`
	Scope             string    `json:"scope"`
	Attribution       string    `json:"attribution"`
	AttributionReason string    `json:"attribution_reason"`
	ObservedAt        time.Time `json:"observed_at"`
}

// AdminSessionWindow — принятое окно улик (сводка на заявке + строки).
type AdminSessionWindow struct {
	RequestID      string
	DeviceID       string
	WindowSeq      int32
	WindowStart    time.Time
	WindowEnd      time.Time
	Changes        []AdminSessionChange
	Final          bool
	Truncated      bool
	TotalChanges   int32
	Rebooted       bool
	BaselineLost   bool
	SoftwareHealth string
	ServicesHealth string
	Completeness   string
	SnapshotAt     time.Time
}

// MarkAdminBaselineCaptured ставит baseline_captured_at при первом отчёте агента
// о выдаче прав с защёлкнутым сбором. Пустой/повторный вызов — no-op.
func (db *DB) MarkAdminBaselineCaptured(ctx context.Context, requestID, deviceID string, at time.Time) error {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return scopeErr
	}
	defer finish(true)
	_, err := db.Scoped(ctx).Exec(ctx, `
		UPDATE admin_access_requests
		SET baseline_captured_at = COALESCE(baseline_captured_at, $3)
		WHERE id = $1 AND device_id = $2
	`, requestID, deviceID, at)
	return err
}

// ErrAdminSessionSeqJump — window_seq ускакал дальше last+MaxAdminSessionSeqJump.
var ErrAdminSessionSeqJump = errors.New("admin session window_seq jump too large")

// ErrAdminSessionTooManyChanges — len(changes) > MaxAdminSessionChanges.
var ErrAdminSessionTooManyChanges = errors.New("admin session changes exceed limit")

// AcceptAdminSessionWindow пишет строки дельты (append-only) и обновляет сводку на
// заявке. Скоуп по device_id: request_id из тела сверяется на принадлежность
// вызывающему устройству. Финальное окно двигает changes_final_at один раз.
func (db *DB) AcceptAdminSessionWindow(ctx context.Context, w AdminSessionWindow) error {
	if len(w.Changes) > MaxAdminSessionChanges {
		return ErrAdminSessionTooManyChanges
	}
	tx, owned, err := db.beginScoped(ctx)
	if err != nil {
		return err
	}
	if owned {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	var lastSeq int32
	err = tx.QueryRow(ctx, `
		SELECT last_window_seq
		FROM admin_access_requests
		WHERE id = $1 AND device_id = $2
		FOR UPDATE
	`, w.RequestID, w.DeviceID).Scan(&lastSeq)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAdminRequestNotFound
		}
		return err
	}
	if w.WindowSeq > lastSeq+MaxAdminSessionSeqJump {
		return ErrAdminSessionSeqJump
	}

	for i := range w.Changes {
		c := &w.Changes[i]
		c.Subject = clipRunes(c.Subject, MaxAdminSessionFieldBytes)
		c.DisplayName = clipRunes(c.DisplayName, MaxAdminSessionFieldBytes)
		c.IdentityKey = clipRunes(c.IdentityKey, MaxAdminSessionFieldBytes)
		c.OldValue = clipRunes(c.OldValue, MaxAdminSessionFieldBytes)
		c.NewValue = clipRunes(c.NewValue, MaxAdminSessionFieldBytes)
		c.Vendor = clipRunes(c.Vendor, MaxAdminSessionFieldBytes)
		c.Scope = clipRunes(c.Scope, MaxAdminSessionFieldBytes)
		c.Attribution = clipRunes(c.Attribution, MaxAdminSessionFieldBytes)
		c.AttributionReason = clipRunes(c.AttributionReason, MaxAdminSessionFieldBytes)
		c.Kind = clipRunes(c.Kind, MaxAdminSessionFieldBytes)
		if c.Attribution == "" {
			c.Attribution = "unknown"
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO admin_session_changes (
				request_id, device_id, window_seq, kind, subject, display_name,
				identity_key, old_value, new_value, vendor, scope,
				attribution, attribution_reason, observed_at
			) VALUES (
				$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
			)
			ON CONFLICT (request_id, window_seq, kind, identity_key) DO NOTHING
		`, w.RequestID, w.DeviceID, w.WindowSeq, c.Kind, c.Subject, c.DisplayName,
			c.IdentityKey, c.OldValue, c.NewValue, c.Vendor, c.Scope,
			c.Attribution, c.AttributionReason, c.ObservedAt)
		if err != nil {
			return fmt.Errorf("insert change: %w", wrapFKViolation(err))
		}
	}

	summary := map[string]any{
		"total_changes":  w.TotalChanges,
		"stored_changes": len(w.Changes),
		"window_seq":     w.WindowSeq,
		"baseline_lost":  w.BaselineLost,
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	completeness := w.Completeness
	if completeness == "" {
		completeness = "unspecified"
	}

	// last_window_seq двигает ТОЛЬКО сводку (K-2): строки уже вставлены всегда.
	_, err = tx.Exec(ctx, `
		UPDATE admin_access_requests SET
			last_window_seq = GREATEST(last_window_seq, $3),
			changes_summary = $4::jsonb,
			changes_completeness = $5,
			changes_rebooted = changes_rebooted OR $6,
			changes_truncated = changes_truncated OR $7,
			software_health = CASE WHEN $8 <> '' THEN $8 ELSE software_health END,
			services_health = CASE WHEN $9 <> '' THEN $9 ELSE services_health END,
			changes_final_at = CASE
				WHEN $10 AND changes_final_at IS NULL THEN $11
				ELSE changes_final_at
			END
		WHERE id = $1 AND device_id = $2
	`, w.RequestID, w.DeviceID, w.WindowSeq, string(raw), completeness,
		w.Rebooted, w.Truncated, w.SoftwareHealth, w.ServicesHealth,
		w.Final, w.WindowEnd)
	if err != nil {
		return err
	}
	if owned {
		if owned {
			return tx.Commit(ctx)
		}
		return nil
	}
	return nil
}

// ListAdminSessionChanges отдаёт строки дельты заявки (для карточки в панели).
func (db *DB) ListAdminSessionChanges(ctx context.Context, requestID string) ([]AdminSessionChange, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return nil, scopeErr
	}
	defer finish(true)
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT id::text, request_id::text, device_id::text, window_seq, kind, subject,
		       display_name, identity_key, old_value, new_value, vendor, scope,
		       attribution, attribution_reason, observed_at
		FROM admin_session_changes
		WHERE request_id = $1
		ORDER BY window_seq DESC, observed_at ASC, identity_key ASC
	`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminSessionChange
	for rows.Next() {
		var c AdminSessionChange
		if err := rows.Scan(&c.ID, &c.RequestID, &c.DeviceID, &c.WindowSeq, &c.Kind, &c.Subject,
			&c.DisplayName, &c.IdentityKey, &c.OldValue, &c.NewValue, &c.Vendor, &c.Scope,
			&c.Attribution, &c.AttributionReason, &c.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AdminEvidenceGap — закрытая сессия с базовой линией и без финального окна.
type AdminEvidenceGap struct {
	RequestID    string
	DeviceID     string
	Status       string
	ClosedAt     time.Time
	AgentVersion string
}

// ListAdminEvidenceGaps — кандидаты на алерт. Ждём grace после закрытия сессии.
// Сигнал защёлки — baseline_captured_at: старый агент его не ставит, поэтому
// «агент не умеет» молчит сам, без порога по agent_version.
func (db *DB) ListAdminEvidenceGaps(ctx context.Context, grace time.Duration) ([]AdminEvidenceGap, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return nil, scopeErr
	}
	defer finish(true)
	if grace <= 0 {
		grace = AdminSessionEvidenceGrace
	}
	cutoff := time.Now().Add(-grace)
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT r.id::text, r.device_id::text, r.status,
		       COALESCE(r.revoked_at, r.expires_at, r.decided_at, r.requested_at) AS closed_at,
		       COALESCE(d.agent_version, '')
		FROM admin_access_requests r
		JOIN devices d ON d.id = r.device_id
		WHERE r.baseline_captured_at IS NOT NULL
		  AND r.changes_final_at IS NULL
		  AND r.status IN ('revoked', 'expired')
		  AND COALESCE(r.revoked_at, r.expires_at, r.decided_at, r.requested_at) < $1
		ORDER BY closed_at ASC
		LIMIT 200
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminEvidenceGap
	for rows.Next() {
		var g AdminEvidenceGap
		if err := rows.Scan(&g.RequestID, &g.DeviceID, &g.Status, &g.ClosedAt, &g.AgentVersion); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// AdminAccessEvidence — сводка улик одной заявки.
type AdminAccessEvidence struct {
	BaselineCapturedAt  *time.Time      `json:"baseline_captured_at"`
	ChangesFinalAt      *time.Time      `json:"changes_final_at"`
	ChangesSummary      json.RawMessage `json:"changes_summary"`
	ChangesCompleteness string          `json:"changes_completeness"`
	ChangesRebooted     bool            `json:"changes_rebooted"`
	ChangesTruncated    bool            `json:"changes_truncated"`
	SoftwareHealth      string          `json:"software_health"`
	ServicesHealth      string          `json:"services_health"`
	LastWindowSeq       int32           `json:"last_window_seq"`
}

func (db *DB) GetAdminAccessEvidence(ctx context.Context, tenantID, requestID string) (*AdminAccessEvidence, error) {
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer finish(false)

	var e AdminAccessEvidence
	var summary []byte
	err = db.Scoped(ctx).QueryRow(ctx, `
		SELECT baseline_captured_at, changes_final_at, changes_summary,
		       changes_completeness, changes_rebooted, changes_truncated,
		       software_health, services_health, last_window_seq
		FROM admin_access_requests WHERE id = $1
	`, requestID).Scan(
		&e.BaselineCapturedAt, &e.ChangesFinalAt, &summary,
		&e.ChangesCompleteness, &e.ChangesRebooted, &e.ChangesTruncated,
		&e.SoftwareHealth, &e.ServicesHealth, &e.LastWindowSeq,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if len(summary) == 0 {
		summary = []byte("{}")
	}
	e.ChangesSummary = summary
	return &e, nil
}

func clipRunes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	var b strings.Builder
	b.Grow(max)
	for _, r := range s {
		if b.Len()+len(string(r)) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
