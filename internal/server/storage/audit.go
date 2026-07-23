package storage

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

type AuditEntry struct {
	ID         string          `json:"id"`
	UserID     *string         `json:"user_id"`
	UserEmail  string          `json:"user_email"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Details    json.RawMessage `json:"details"`
	CreatedAt  time.Time       `json:"created_at"`
}

func (db *DB) WriteAuditLog(ctx context.Context, userID, userEmail, action, targetType, targetID string, details any) error {
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	var uid *string
	if userID != "" {
		uid = &userID
	}
	_, err = db.pool.Exec(ctx, `
  INSERT INTO audit_log (user_id, user_email, action, target_type, target_id, details)
  VALUES ($1, $2, $3, $4, $5, $6)
 `, uid, userEmail, action, targetType, targetID, string(raw))
	return err
}

// AuditFilter — серверные фильтры журнала; пустое поле = фильтр выключен.
// Раньше «С / По / Кто» жили в браузере поверх последних 200 записей: интерфейс
// честно писал «Показано N из 200», но что записей вообще-то десятки тысяч, не
// сообщал никак — фильтр по позапрошлому месяцу молча возвращал пусто.
type AuditFilter struct {
	Action string     // точное совпадение
	Who    string     // подстрока по user_email (агент пишется как agent:<id>)
	From   *time.Time // включительно, nil = без нижней границы
	To     *time.Time // включительно, nil = без верхней
}

// ListAuditLog отдаёт страницу журнала и общее число записей под фильтром.
func (db *DB) ListAuditLog(ctx context.Context, f AuditFilter, limit, offset int) ([]AuditEntry, int, error) {
	limit, offset = clampPage(limit, offset)
	who := ""
	if w := strings.TrimSpace(f.Who); w != "" {
		who = "%" + likeEscaper.Replace(w) + "%"
	}
	// ORDER BY дополнен id: события пишутся пачками в одну транзакцию и делят
	// created_at до микросекунды — без тай-брейка страницы разъезжаются.
	rows, err := db.pool.Query(ctx, `
		SELECT id, user_id, user_email, action, target_type, target_id,
		       COALESCE(details::text, 'null'), created_at, COUNT(*) OVER() AS total
		FROM audit_log
		WHERE ($1 = '' OR action = $1)
		  AND ($2 = '' OR user_email ILIKE $2)
		  AND ($3::timestamptz IS NULL OR created_at >= $3)
		  AND ($4::timestamptz IS NULL OR created_at <= $4)
		ORDER BY created_at DESC, id
		LIMIT $5 OFFSET $6
	`, strings.TrimSpace(f.Action), who, f.From, f.To, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var entries []AuditEntry
	total := 0
	for rows.Next() {
		var e AuditEntry
		var detailsRaw string
		if err := rows.Scan(&e.ID, &e.UserID, &e.UserEmail, &e.Action,
			&e.TargetType, &e.TargetID, &detailsRaw, &e.CreatedAt, &total); err != nil {
			return nil, 0, err
		}
		e.Details = json.RawMessage(detailsRaw)
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}
