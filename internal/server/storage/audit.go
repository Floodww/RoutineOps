package storage

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

type AuditEntry struct {
	ID string `json:"id"`
	// Seq — номер записи в хеш-цепочке ТЕНАНТА (миграция 042). Человекочитаемый
	// идентификатор события в панели строится из него, а не из uuid: uuid не
	// диктуется и не сверяется вслух, а «событие №1043» — диктуется. NULL у строк
	// старше цепочки — в панели такие показываются прочерком, а не нулём, потому
	// что ноль был бы неотличим от настоящего первого события.
	Seq        *int64          `json:"seq"`
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
	tx, owned, err := db.beginScoped(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	if owned {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	tenantID := tenancy.DefaultTenantID
	if tid, ok := TenantIDFrom(ctx); ok && tid != "" {
		tenantID = tid
	}
	if err := db.setTenantGUC(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("audit: set tenant: %w", err)
	}

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
	// Голова и вставка ограничены тенантом: цепочка пер-тенантная (045 / §6.1).
	_, err = tx.Exec(ctx, `
		WITH head AS (
		  SELECT seq, hash FROM audit_log
		  WHERE tenant_id = $7 AND seq IS NOT NULL
		  ORDER BY seq DESC LIMIT 1
		), nxt AS (
		  SELECT COALESCE((SELECT seq  FROM head), 0) + 1 AS seq,
		         COALESCE((SELECT hash FROM head), '')    AS prev_hash,
		         $1::uuid AS user_id, $2::text AS user_email, $3::text AS action,
		         $4::text AS target_type, $5::text AS target_id, $6::jsonb AS details,
		         $7::uuid AS tenant_id,
		         now() AS created_at
		)
		INSERT INTO audit_log (user_id, user_email, action, target_type, target_id,
		                       details, created_at, seq, prev_hash, hash, tenant_id)
		SELECT n.user_id, n.user_email, n.action, n.target_type, n.target_id,
		       n.details, n.created_at, n.seq, n.prev_hash,
		       audit_row_hash(n.prev_hash, n.seq, n.user_id, n.user_email, n.action,
		                      n.target_type, n.target_id, n.details, n.created_at),
		       n.tenant_id
		FROM nxt n
	`, uid, userEmail, action, targetType, targetID, string(raw), tenantID)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	if owned {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("audit: commit: %w", err)
		}
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
//
// Тенант обязателен: audit_log тенантский, и цепочка у каждого тенанта своя
// (см. карту tenancy и WriteAuditAnchor). Через db.pool запрос уходил на соседнее
// соединение пула, где routineops.tenant_id остался пустой строкой после
// предыдущей транзакции, — предикат RLS падал на ”::uuid, и /audit-log/verify
// отдавал 500. Тот же дефект, что поймал полевой e2e 30.07 в списке устройств.
func (db *DB) VerifyAuditChain(ctx context.Context, tenantID string) (*AuditChainStatus, error) {
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer finish(true)

	st := &AuditChainStatus{OK: true}

	err = db.Scoped(ctx).QueryRow(ctx, `
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

	if err := db.Scoped(ctx).QueryRow(ctx,
		`SELECT hash FROM audit_log WHERE seq = $1`, st.LastSeq).Scan(&st.HeadHash); err != nil {
		return nil, fmt.Errorf("audit verify: head: %w", err)
	}

	// Пересчёт хеша идёт ТОЙ ЖЕ функцией audit_row_hash, что и запись, — расхождение
	// канонизации между записью и проверкой невозможно по построению.
	var brokenSeq *int64
	var reason *string
	err = db.Scoped(ctx).QueryRow(ctx, `
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
	if err := db.Scoped(ctx).QueryRow(ctx, `
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
// Тенант берётся из привязанного скоупа, а НЕ из tenancy.DefaultTenantID: цепочка
// аудита обязана быть на тенанта (карта tenancy: у тенантов раздельный срок хранения,
// и общая цепочка дырявилась бы чужим retention'ом). Хардкод дефолтного тенанта
// означал, что якорь всей инсталляции пишется только для него, а у остальных
// tamper-evidence молча отсутствует — при живом эндпоинте /audit-log/verify.
// Вызывающий обязан обойти тенанты (ForEachTenant).
func (db *DB) WriteAuditAnchor(ctx context.Context) (int64, string, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return 0, "", scopeErr
	}
	defer finish(true)
	tenantID, ok := TenantIDFrom(ctx)
	if !ok || tenantID == "" {
		return 0, "", tenancy.ErrTenantScopeMissing
	}
	var seq int64
	var hash string
	err := db.Scoped(ctx).QueryRow(ctx, `
		SELECT seq, hash FROM audit_log
		WHERE tenant_id = $1 AND seq IS NOT NULL
		ORDER BY seq DESC LIMIT 1`, tenantID).Scan(&seq, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, "", nil
		}
		return 0, "", fmt.Errorf("audit anchor: head: %w", err)
	}
	if _, err := db.Scoped(ctx).Exec(ctx, `
		INSERT INTO audit_anchors (tenant_id, seq, hash) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, seq) DO NOTHING`,
		tenantID, seq, hash); err != nil {
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
func (db *DB) ListAuditLog(ctx context.Context, tenantID string, f AuditFilter, limit, offset int) ([]AuditEntry, int, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, 0, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, 0, err
		}
		defer finish(true)
	}
	limit, offset = clampPage(limit, offset)
	who := ""
	if w := strings.TrimSpace(f.Who); w != "" {
		who = "%" + likeEscaper.Replace(w) + "%"
	}
	// ORDER BY дополнен id: события пишутся пачками в одну транзакцию и делят
	// created_at до микросекунды — без тай-брейка страницы разъезжаются.
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT id, seq, user_id, user_email, action, target_type, target_id,
		       COALESCE(details::text, 'null'), created_at, COUNT(*) OVER() AS total
		FROM audit_log
		WHERE tenant_id = $1
		  AND ($2 = '' OR action = $2)
		  AND ($3 = '' OR user_email ILIKE $3)
		  AND ($4::timestamptz IS NULL OR created_at >= $4)
		  AND ($5::timestamptz IS NULL OR created_at <= $5)
		ORDER BY created_at DESC, id
		LIMIT $6 OFFSET $7
	`, tenantID, strings.TrimSpace(f.Action), who, f.From, f.To, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var entries []AuditEntry
	total := 0
	for rows.Next() {
		var e AuditEntry
		var detailsRaw string
		if err := rows.Scan(&e.ID, &e.Seq, &e.UserID, &e.UserEmail, &e.Action,
			&e.TargetType, &e.TargetID, &detailsRaw, &e.CreatedAt, &total); err != nil {
			return nil, 0, err
		}
		e.Details = json.RawMessage(detailsRaw)
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

// archiveAuditLogs выгружает записи журнала СТАРШЕ cutoff в сжатый файл — до того,
// как их удалит retention. Без этого tamper-evident цепочка, ради которой всё
// строилось, умирала по расписанию: единственный экземпляр улик чистился по
// AUDIT_RETENTION_DAYS, и доказать целостность прошлого было уже нечем.
//
// Вызывается ПОД скоупом тенанта (cleanup идёт через ForEachTenant), поэтому и
// выборка, и файл — пер-тенантные, как и сама цепочка хешей.
//
// Файл пишется во временное имя и переименовывается только после успешного
// закрытия: retention удаляет строки СРАЗУ после возврата отсюда, и обрыв на
// середине записи означал бы обрезанный архив плюс удалённый оригинал. По той же
// причине ошибки Close/Sync проверяются явно, а не через голый defer, — в
// gzip-потоке именно Close дописывает хвост.
func (db *DB) archiveAuditLogs(ctx context.Context, cutoff time.Time, archiveDir string) error {
	// 0700: в архиве лежит журнал целиком, включая details. Права как у бэкапов БД.
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		return err
	}

	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT id, seq, tenant_id, user_id, user_email, action, target_type, target_id,
		       COALESCE(details::text, 'null'), created_at, prev_hash, hash
		FROM audit_log
		WHERE created_at < $1
		ORDER BY created_at ASC, seq ASC NULLS FIRST
	`, cutoff)
	if err != nil {
		return err
	}
	defer rows.Close()

	var (
		records  []map[string]any
		tenantID string
	)
	for rows.Next() {
		var id, action, targetType, targetID string
		var userID, userEmail, prevHash, currHash *string
		var seq *int64
		var detailsRaw string
		var createdAt time.Time

		if err := rows.Scan(&id, &seq, &tenantID, &userID, &userEmail, &action, &targetType,
			&targetID, &detailsRaw, &createdAt, &prevHash, &currHash); err != nil {
			return err
		}
		records = append(records, map[string]any{
			"id":          id,
			"seq":         seq,
			"tenant_id":   tenantID,
			"user_id":     userID,
			"user_email":  userEmail,
			"action":      action,
			"target_type": targetType,
			"target_id":   targetID,
			"details":     json.RawMessage(detailsRaw),
			"created_at":  createdAt,
			"prev_hash":   prevHash,
			"hash":        currHash,
		})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}

	// Тенант в имени обязателен: чистка идёт по всем тенантам подряд, и без него два
	// тенанта в одну секунду писали бы в один файл — os.Create усекает, архив первого
	// исчезал бы молча.
	name := fmt.Sprintf("audit_archive_%s_%s.jsonl.gz", tenantID, time.Now().UTC().Format("20060102T150405Z"))
	final := filepath.Join(archiveDir, name)
	tmp := final + ".part"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	gw := gzip.NewWriter(f)
	writeErr := func() error {
		for _, rec := range records {
			b, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if _, err := gw.Write(append(b, '\n')); err != nil {
				return err
			}
		}
		if err := gw.Close(); err != nil {
			return err
		}
		// fsync: иначе «файл записан» означает лишь «попал в страничный кеш», а
		// строки в БД мы удаляем уже сейчас.
		if err := f.Sync(); err != nil {
			return err
		}
		return f.Close()
	}()
	if writeErr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return writeErr
	}
	return os.Rename(tmp, final)
}
