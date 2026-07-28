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

// auditChainLockKey — ключ advisory-лока, сериализующего выдачу номеров в
// хеш-цепочке аудита (миграция 042). Значение произвольно, важна лишь его
// уникальность в пределах инсталляции: pg_advisory_xact_lock — глобальное
// пространство имён на всю БД.
const auditChainLockKey = 0x52_4f_41_55 // "ROAU"

func (db *DB) WriteAuditLog(ctx context.Context, userID, userEmail, action, targetType, targetID string, details any) error {
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	var uid *string
	if userID != "" {
		uid = &userID
	}

	// Запись идёт в явной транзакции с advisory-локом: между «прочитать голову» и
	// «вставить голова+1» не должно вклиниться другое соединение, иначе две записи
	// получат один seq (и уникальный индекс отобьёт вторую) либо один prev_hash —
	// то есть цепочка раздвоится.
	//
	// Лок сериализует ВСЕ записи аудита между собой. Это осознанная цена: аудит
	// пишется на мутирующих действиях администратора, десятки в минуту в худшем
	// случае, и стоимость лока там неразличима. Если журнал когда-нибудь станет
	// горячим путём, правильный ответ — цепочка на тенанта (лок по tenant_id), а не
	// отказ от сериализации.
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(auditChainLockKey)); err != nil {
		return fmt.Errorf("audit: lock chain: %w", err)
	}

	// created_at вычисляется здесь и подставляется явно, а не берётся из DEFAULT:
	// хеш считается ОТ значения created_at, поэтому оно обязано быть известно до
	// вычисления хеша, а не назначаться той же вставкой.
	//
	// prev_hash пустой строкой у самой первой записи цепочки — это генезис.
	// COALESCE по MAX(seq) даёт 1 для первой записи и на инсталляции, где до 042
	// уже был журнал: до-цепочечные записи имеют seq IS NULL и в MAX не участвуют.
	_, err = tx.Exec(ctx, `
		WITH head AS (
		  SELECT seq, hash FROM audit_log WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1
		), nxt AS (
		  SELECT COALESCE((SELECT seq  FROM head), 0) + 1 AS seq,
		         COALESCE((SELECT hash FROM head), '')    AS prev_hash,
		         $1::uuid AS user_id, $2::text AS user_email, $3::text AS action,
		         $4::text AS target_type, $5::text AS target_id, $6::jsonb AS details,
		         -- now() без приведения к timestamp: колонка имеет тип TIMESTAMPTZ
		         -- (миграция 015). Промежуточное ::timestamp сбросило бы зону по
		         -- TimeZone сессии, а вставка вернула бы её обратно — момент времени
		         -- зависел бы от настройки соединения, и хеш вместе с ним.
		         now() AS created_at
		)
		INSERT INTO audit_log (user_id, user_email, action, target_type, target_id,
		                       details, created_at, seq, prev_hash, hash)
		SELECT n.user_id, n.user_email, n.action, n.target_type, n.target_id,
		       n.details, n.created_at, n.seq, n.prev_hash,
		       audit_row_hash(n.prev_hash, n.seq, n.user_id, n.user_email, n.action,
		                      n.target_type, n.target_id, n.details, n.created_at)
		FROM nxt n
	`, uid, userEmail, action, targetType, targetID, string(raw))
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
	}
	return nil
}

// AuditChainStatus — результат проверки целостности журнала.
type AuditChainStatus struct {
	// Chained — сколько записей входит в цепочку и проверено.
	Chained int64 `json:"chained"`
	// Unchained — записи, сделанные до наката миграции 042. Цепочкой НЕ покрыты;
	// поле существует, чтобы «проверка прошла» не читалось как «весь журнал цел».
	Unchained int64 `json:"unchained"`
	// FirstSeq/LastSeq — границы уцелевшего участка цепочки. FirstSeq > 1 означает,
	// что префикс усечён (штатно — retention'ом).
	FirstSeq int64 `json:"first_seq"`
	LastSeq  int64 `json:"last_seq"`
	// HeadHash — хеш последней записи. Это значение имеет смысл сверять с внешней
	// копией: пока цепочка проверяется только по самой БД, она доказывает лишь
	// внутреннюю согласованность.
	HeadHash string `json:"head_hash"`
	// OK=false → цепочка нарушена; BrokenSeq/Reason указывают, где именно.
	OK        bool   `json:"ok"`
	BrokenSeq int64  `json:"broken_seq,omitempty"`
	Reason    string `json:"reason,omitempty"`
	// AnchorMismatch — якорь есть, но запись с таким seq имеет другой хеш. Самый
	// тяжёлый случай: цепочка внутренне согласована, значит её пересчитали целиком.
	AnchorMismatch bool `json:"anchor_mismatch,omitempty"`
}

// VerifyAuditChain проверяет журнал: каждая запись против собственного хеша,
// каждая связка prev_hash против соседа, непрерывность номеров и совпадение с
// сохранёнными якорями.
//
// Три класса нарушений различаются намеренно:
//   - "hash" — поле записи изменено;
//   - "gap"  — запись удалена из СЕРЕДИНЫ (усечение префикса retention'ом номера не
//     рвёт, оно лишь сдвигает FirstSeq — и нарушением не считается);
//   - "link" — prev_hash не совпал с хешем предыдущей записи (перестановка, вставка).
func (db *DB) VerifyAuditChain(ctx context.Context) (*AuditChainStatus, error) {
	st := &AuditChainStatus{OK: true}

	err := db.pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE seq IS NOT NULL),
		       COUNT(*) FILTER (WHERE seq IS NULL),
		       COALESCE(MIN(seq), 0), COALESCE(MAX(seq), 0)
		FROM audit_log`).Scan(&st.Chained, &st.Unchained, &st.FirstSeq, &st.LastSeq)
	if err != nil {
		return nil, fmt.Errorf("audit verify: counts: %w", err)
	}
	if st.Chained == 0 {
		return st, nil
	}

	if err := db.pool.QueryRow(ctx,
		`SELECT hash FROM audit_log WHERE seq = $1`, st.LastSeq).Scan(&st.HeadHash); err != nil {
		return nil, fmt.Errorf("audit verify: head: %w", err)
	}

	// Пересчёт хеша идёт ТОЙ ЖЕ функцией audit_row_hash, что и запись, — расхождение
	// канонизации между записью и проверкой невозможно по построению.
	var brokenSeq *int64
	var reason *string
	err = db.pool.QueryRow(ctx, `
		WITH c AS (
		  SELECT seq, prev_hash, hash,
		         audit_row_hash(prev_hash, seq, user_id, user_email, action,
		                        target_type, target_id, details, created_at) AS want,
		         lag(hash) OVER (ORDER BY seq) AS prev_actual,
		         lag(seq)  OVER (ORDER BY seq) AS prev_seq
		  FROM audit_log WHERE seq IS NOT NULL
		)
		SELECT seq,
		       CASE WHEN hash IS DISTINCT FROM want THEN 'hash'
		            WHEN prev_seq IS NOT NULL AND seq <> prev_seq + 1 THEN 'gap'
		            ELSE 'link' END
		FROM c
		WHERE hash IS DISTINCT FROM want
		   OR (prev_seq IS NOT NULL AND seq <> prev_seq + 1)
		   OR (prev_actual IS NOT NULL AND prev_hash IS DISTINCT FROM prev_actual)
		ORDER BY seq LIMIT 1`).Scan(&brokenSeq, &reason)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("audit verify: scan chain: %w", err)
	}
	if brokenSeq != nil {
		st.OK = false
		st.BrokenSeq = *brokenSeq
		if reason != nil {
			st.Reason = *reason
		}
		return st, nil
	}

	// Якоря: запись, чей seq зафиксирован якорем, обязана иметь тот же хеш. Это
	// единственная проверка, которую нельзя пройти пересчётом всей цепочки, —
	// при условии, что якорь хранится не только здесь (лог сервера, Telegram).
	var mismatch int64
	if err := db.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_anchors an
		JOIN audit_log a ON a.seq = an.seq
		WHERE a.hash IS DISTINCT FROM an.hash`).Scan(&mismatch); err != nil {
		return nil, fmt.Errorf("audit verify: anchors: %w", err)
	}
	if mismatch > 0 {
		st.OK = false
		st.AnchorMismatch = true
		st.Reason = "anchor"
	}
	return st, nil
}

// WriteAuditAnchor фиксирует текущую голову цепочки. Возвращает (seq, hash) головы;
// seq=0 означает пустую цепочку — фиксировать нечего.
//
// ON CONFLICT DO NOTHING: голова не двигается, пока нет новых записей, и повторный
// якорь на тот же seq — норма, а не ошибка. Перезаписывать существующий якорь нельзя
// категорически: якорь тем и ценен, что зафиксирован однажды.
func (db *DB) WriteAuditAnchor(ctx context.Context) (int64, string, error) {
	var seq int64
	var hash string
	err := db.pool.QueryRow(ctx, `
		SELECT seq, hash FROM audit_log WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, "", nil
		}
		return 0, "", fmt.Errorf("audit anchor: head: %w", err)
	}
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO audit_anchors (seq, hash) VALUES ($1, $2) ON CONFLICT (seq) DO NOTHING`,
		seq, hash); err != nil {
		return 0, "", fmt.Errorf("audit anchor: insert: %w", err)
	}
	return seq, hash, nil
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
