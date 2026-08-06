package storage_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Тесты пакета делят ОДНУ базу (см. TestMain), поэтому всё, что портит цепочку,
// обязано восстановить её ровно в прежнее состояние — иначе следующий тест,
// вызывающий VerifyAuditChain, упадёт по чужой вине. Восстановление ставится через
// t.Cleanup, чтобы отработать и при провале самого теста.

// mustVerify — проверка цепочки с падением на ошибке выполнения (не на нарушении).
func mustVerify(t *testing.T, db *storage.DB) *storage.AuditChainStatus {
	t.Helper()
	st, err := db.VerifyAuditChain(tenantCtx(), tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	return st
}

// TestAuditChain_BuildsAndVerifies: последовательные записи получают сквозные
// номера, связываются хешами и проходят проверку.
func TestAuditChain_BuildsAndVerifies(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	before := mustVerify(t, db)
	if !before.OK {
		t.Fatalf("цепочка нарушена ДО теста (seq %d, %s) — испортил предыдущий тест",
			before.BrokenSeq, before.Reason)
	}

	const n = 3
	for i := 0; i < n; i++ {
		if err := db.WriteAuditLog(ctx, "", fmt.Sprintf("chain-%s-%d", uniq(t), i),
			"chain_test", "test", "t1", map[string]any{"i": i}); err != nil {
			t.Fatalf("WriteAuditLog #%d: %v", i, err)
		}
	}

	after := mustVerify(t, db)
	if !after.OK {
		t.Fatalf("цепочка нарушена после записи: seq %d, причина %q", after.BrokenSeq, after.Reason)
	}
	if after.LastSeq != before.LastSeq+n {
		t.Errorf("голова сдвинулась на %d, ждали %d", after.LastSeq-before.LastSeq, n)
	}
	if after.Chained != before.Chained+n {
		t.Errorf("в цепочке +%d записей, ждали +%d", after.Chained-before.Chained, n)
	}
	if after.HeadHash == "" || after.HeadHash == before.HeadHash {
		t.Errorf("хеш головы не обновился: было %q, стало %q", before.HeadHash, after.HeadHash)
	}
}

// TestAuditChain_DetectsFieldTamper: правка поля уже записанной строки расходится
// с её собственным хешем. Это базовое обещание tamper-evident журнала.
func TestAuditChain_DetectsFieldTamper(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	if err := db.WriteAuditLog(ctx, "", "victim@example.com", "delete_device", "device", "d-1", nil); err != nil {
		t.Fatalf("WriteAuditLog: %v", err)
	}
	head := mustVerify(t, db)
	if !head.OK {
		t.Fatalf("цепочка нарушена до вмешательства: %s @ %d", head.Reason, head.BrokenSeq)
	}
	target := head.LastSeq

	var origAction string
	if err := db.Pool().QueryRow(ctx,
		`SELECT action FROM audit_log WHERE seq = $1`, target).Scan(&origAction); err != nil {
		t.Fatalf("чтение исходного action: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(tenantCtx(),
			`UPDATE audit_log SET action = $1 WHERE seq = $2`, origAction, target)
	})

	// Классическая подделка: «я не удалял устройство, я его смотрел».
	if _, err := db.Pool().Exec(ctx,
		`UPDATE audit_log SET action = 'view_device' WHERE seq = $1`, target); err != nil {
		t.Fatalf("подделка: %v", err)
	}

	st := mustVerify(t, db)
	if st.OK {
		t.Fatal("правка поля не обнаружена")
	}
	if st.BrokenSeq != target {
		t.Errorf("нарушение указано на seq %d, ждали %d", st.BrokenSeq, target)
	}
	if st.Reason != "hash" {
		t.Errorf("причина %q, ждали \"hash\"", st.Reason)
	}
}

// TestAuditChain_DetectsMiddleDelete: удаление записи из СЕРЕДИНЫ рвёт нумерацию.
// Именно этим оно отличается от легального усечения хвоста retention'ом.
func TestAuditChain_DetectsMiddleDelete(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	for i := 0; i < 3; i++ {
		if err := db.WriteAuditLog(ctx, "", "del@example.com", "chain_del", "test", "x", nil); err != nil {
			t.Fatalf("WriteAuditLog #%d: %v", i, err)
		}
	}
	head := mustVerify(t, db)
	if !head.OK {
		t.Fatalf("цепочка нарушена до вмешательства: %s @ %d", head.Reason, head.BrokenSeq)
	}
	victim := head.LastSeq - 1 // средняя из трёх

	// Снимаем полную копию строки, чтобы вернуть её байт-в-байт: восстановить
	// цепочку иначе нельзя — hash зависит от created_at с точностью до микросекунды.
	var userEmail, action, targetType, targetID, details, prevHash, hash string
	var createdAt any
	if err := db.Pool().QueryRow(ctx, `
		SELECT user_email, action, target_type, target_id, COALESCE(details::text,'null'),
		       created_at, prev_hash, hash
		FROM audit_log WHERE seq = $1`, victim).
		Scan(&userEmail, &action, &targetType, &targetID, &details, &createdAt, &prevHash, &hash); err != nil {
		t.Fatalf("снимок строки: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(tenantCtx(), `
			INSERT INTO audit_log (user_email, action, target_type, target_id, details,
			                       created_at, seq, prev_hash, hash)
			VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			userEmail, action, targetType, targetID, details, createdAt, victim, prevHash, hash)
	})

	if _, err := db.Pool().Exec(ctx, `DELETE FROM audit_log WHERE seq = $1`, victim); err != nil {
		t.Fatalf("удаление: %v", err)
	}

	st := mustVerify(t, db)
	if st.OK {
		t.Fatal("удаление из середины не обнаружено")
	}
	if st.Reason != "gap" {
		t.Errorf("причина %q, ждали \"gap\" (нарушена непрерывность номеров)", st.Reason)
	}
	if st.BrokenSeq != victim+1 {
		t.Errorf("разрыв указан на seq %d, ждали %d (первая запись после дыры)", st.BrokenSeq, victim+1)
	}
}

// TestAuditChain_PrefixTruncationIsLegal: retention удаляет САМЫЕ СТАРЫЕ записи, и
// это не нарушение — иначе штатная чистка журнала каждую ночь поднимала бы тревогу
// о подделке, и проверку целостности отключили бы через неделю.
func TestAuditChain_PrefixTruncationIsLegal(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	if err := db.WriteAuditLog(ctx, "", "trunc@example.com", "chain_trunc", "test", "x", nil); err != nil {
		t.Fatalf("WriteAuditLog: %v", err)
	}
	before := mustVerify(t, db)
	if !before.OK {
		t.Fatalf("цепочка нарушена до теста: %s @ %d", before.Reason, before.BrokenSeq)
	}
	if before.Chained < 2 {
		t.Skip("в цепочке меньше двух записей — усекать нечего")
	}
	victim := before.FirstSeq

	var userEmail, action, targetType, targetID, details, prevHash, hash string
	var createdAt any
	if err := db.Pool().QueryRow(ctx, `
		SELECT user_email, action, target_type, target_id, COALESCE(details::text,'null'),
		       created_at, prev_hash, hash
		FROM audit_log WHERE seq = $1`, victim).
		Scan(&userEmail, &action, &targetType, &targetID, &details, &createdAt, &prevHash, &hash); err != nil {
		t.Fatalf("снимок строки: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(tenantCtx(), `
			INSERT INTO audit_log (user_email, action, target_type, target_id, details,
			                       created_at, seq, prev_hash, hash)
			VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			userEmail, action, targetType, targetID, details, createdAt, victim, prevHash, hash)
	})

	if _, err := db.Pool().Exec(ctx, `DELETE FROM audit_log WHERE seq = $1`, victim); err != nil {
		t.Fatalf("усечение префикса: %v", err)
	}

	st := mustVerify(t, db)
	if !st.OK {
		t.Fatalf("усечение префикса принято за подделку: %s @ %d", st.Reason, st.BrokenSeq)
	}
	if st.FirstSeq != victim+1 {
		t.Errorf("начало цепочки = %d, ждали %d", st.FirstSeq, victim+1)
	}
}

// TestAuditChain_AnchorCatchesFullRecompute — самый важный тест пакета.
//
// Противник с правом записи в БД может пересчитать цепочку ЦЕЛИКОМ после подделки:
// внутренне она останется согласованной, и проверка «каждая строка против своего
// хеша» пройдёт. Единственное, что это ловит, — якорь, снятый раньше и хранящийся
// не только в этой же БД (лог сервера, Telegram оператора).
//
// Здесь пересчёт воспроизводится честно: подделываем поле и рекурсивно
// перевычисляем всю цепочку от неё и дальше той же функцией audit_row_hash.
func TestAuditChain_AnchorCatchesFullRecompute(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	for i := 0; i < 2; i++ {
		if err := db.WriteAuditLog(ctx, "", "anchor@example.com", "chain_anchor", "test", "x", nil); err != nil {
			t.Fatalf("WriteAuditLog #%d: %v", i, err)
		}
	}
	// Якорю нужен привязанный тенант: цепочка аудита тенантская. Коммитим сразу —
	// проверки ниже читают через Pool(), вне этой транзакции.
	anchorCtx, anchorFinish, err := db.BindTenant(ctx, tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	anchorSeq, anchorHash, err := db.WriteAuditAnchor(anchorCtx)
	anchorFinish(err == nil)
	if err != nil {
		t.Fatalf("WriteAuditAnchor: %v", err)
	}
	if anchorSeq == 0 || anchorHash == "" {
		t.Fatal("якорь не записан")
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(tenantCtx(), `DELETE FROM audit_anchors WHERE seq = $1`, anchorSeq)
	})

	// Снимок затрагиваемого участка для восстановления.
	type row struct {
		seq                    int64
		action, prevHash, hash string
	}
	var snapshot []row
	rows, err := db.Pool().Query(ctx,
		`SELECT seq, action, prev_hash, hash FROM audit_log WHERE seq IS NOT NULL ORDER BY seq`)
	if err != nil {
		t.Fatalf("снимок цепочки: %v", err)
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.seq, &r.action, &r.prevHash, &r.hash); err != nil {
			rows.Close()
			t.Fatalf("скан снимка: %v", err)
		}
		snapshot = append(snapshot, r)
	}
	rows.Close()
	t.Cleanup(func() {
		for _, r := range snapshot {
			_, _ = db.Pool().Exec(tenantCtx(),
				`UPDATE audit_log SET action = $1, prev_hash = $2, hash = $3 WHERE seq = $4`,
				r.action, r.prevHash, r.hash, r.seq)
		}
	})

	// 1. Подделка.
	if _, err := db.Pool().Exec(ctx,
		`UPDATE audit_log SET action = 'innocent_action' WHERE seq = $1`, anchorSeq); err != nil {
		t.Fatalf("подделка: %v", err)
	}
	// 2. Полный пересчёт цепочки — то, что сделал бы подготовленный противник.
	if _, err := db.Pool().Exec(ctx, `
		WITH RECURSIVE ordered AS (
		  SELECT seq, user_id, user_email, action, target_type, target_id, details, created_at,
		         row_number() OVER (ORDER BY seq) AS rn
		  FROM audit_log WHERE seq IS NOT NULL
		), chain AS (
		  SELECT o.seq, o.rn, ''::text AS prev_hash,
		         audit_row_hash('', o.seq, o.user_id, o.user_email, o.action,
		                        o.target_type, o.target_id, o.details, o.created_at) AS hash
		  FROM ordered o WHERE o.rn = 1
		  UNION ALL
		  SELECT o.seq, o.rn, c.hash,
		         audit_row_hash(c.hash, o.seq, o.user_id, o.user_email, o.action,
		                        o.target_type, o.target_id, o.details, o.created_at)
		  FROM ordered o JOIN chain c ON o.rn = c.rn + 1
		)
		UPDATE audit_log a SET prev_hash = c.prev_hash, hash = c.hash
		FROM chain c WHERE a.seq = c.seq`); err != nil {
		t.Fatalf("пересчёт цепочки: %v", err)
	}

	st := mustVerify(t, db)
	if st.OK {
		t.Fatal("полный пересчёт цепочки не обнаружен — якорь не сработал")
	}
	if !st.AnchorMismatch {
		t.Errorf("нарушение поймано как %q, а должно было — расхождением с якорем", st.Reason)
	}
}

// TestAuditChain_ConcurrentWrites: параллельные записи не должны раздваивать
// цепочку. Advisory-лок сериализует выдачу номера; без него часть записей получила
// бы один seq (и упала бы на уникальном индексе) либо один prev_hash — и цепочка
// стала бы деревом, а не цепью.
func TestAuditChain_ConcurrentWrites(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	before := mustVerify(t, db)
	if !before.OK {
		t.Fatalf("цепочка нарушена до теста: %s @ %d", before.Reason, before.BrokenSeq)
	}

	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := db.WriteAuditLog(ctx, "", fmt.Sprintf("conc-%d@example.com", i),
				"chain_concurrent", "test", "x", map[string]any{"writer": i}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("параллельная запись: %v", err)
	}

	after := mustVerify(t, db)
	if !after.OK {
		t.Fatalf("цепочка нарушена после параллельных записей: %s @ %d", after.Reason, after.BrokenSeq)
	}
	if after.Chained != before.Chained+writers {
		t.Errorf("записано %d строк, ждали %d", after.Chained-before.Chained, writers)
	}
	if after.LastSeq != before.LastSeq+writers {
		t.Errorf("голова сдвинулась на %d, ждали %d — номера выданы не подряд",
			after.LastSeq-before.LastSeq, writers)
	}
}

// TestAuditChain_SurvivesJSONBNormalization защищает главное проектное решение
// миграции 042: хеш считается В POSTGRES, а не в Go.
//
// details имеет тип JSONB и нормализуется при записи — порядок ключей меняется
// (JSONB сортирует по длине, потом побайтово; encoding/json — по алфавиту), числа
// переписываются, пробелы уходят. Хеш от того, что Go СОБИРАЛСЯ записать, не совпал
// бы с хешем от того, что Postgres реально хранит. Если кто-нибудь перенесёт
// вычисление хеша в Go, этот тест покраснеет — в отличие от всех остальных, которые
// пишут тривиальный details и разницы не заметят.
func TestAuditChain_SurvivesJSONBNormalization(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	// Ключи подобраны так, чтобы алфавитный порядок (Go) отличался от порядка JSONB
	// (сначала по длине): алфавит — a, bbb, zz; JSONB — a, zz, bbb.
	details := map[string]any{
		"zz":  1,
		"a":   2,
		"bbb": 3,
		// Число, которое JSONB перепишет в другой форме записи.
		"num": 1e3,
		// Строка с символами, требующими экранирования, — проверяем, что префикс
		// длины остаётся инъективным на непростом содержимом.
		"txt": "a:b\"c\\d\nе",
	}
	if err := db.WriteAuditLog(ctx, "", "jsonb@example.com", "chain_jsonb", "test", "x", details); err != nil {
		t.Fatalf("WriteAuditLog: %v", err)
	}

	st := mustVerify(t, db)
	if !st.OK {
		t.Fatalf("цепочка разошлась на нетривиальном details: %s @ %d — "+
			"признак того, что хеш считается не от хранимой формы JSONB", st.Reason, st.BrokenSeq)
	}
}

// TestWriteAuditAnchor_Idempotent: повторный якорь на ту же голову не ошибка и не
// перезапись. Якорь ценен именно тем, что зафиксирован однажды.
func TestWriteAuditAnchor_Idempotent(t *testing.T) {
	db := newDB(t)

	// Якорь берёт тенанта из привязанного скоупа (цепочка аудита тенантская),
	// поэтому голый tenantCtx() ему больше не годится.
	ctx, finish, err := db.BindTenant(tenantCtx(), tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	if err := db.WriteAuditLog(ctx, "", "idem@example.com", "chain_idem", "test", "x", nil); err != nil {
		finish(false)
		t.Fatalf("WriteAuditLog: %v", err)
	}
	seq1, hash1, err := db.WriteAuditAnchor(ctx)
	if err != nil {
		finish(false)
		t.Fatalf("первый якорь: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(tenantCtx(), `DELETE FROM audit_anchors WHERE seq = $1`, seq1)
	})

	seq2, hash2, err := db.WriteAuditAnchor(ctx)
	if err != nil {
		finish(false)
		t.Fatalf("повторный якорь: %v", err)
	}
	// Коммитим ДО проверки: счётчик ниже читает через Pool(), то есть вне этой
	// транзакции, и незакоммиченных якорей не увидел бы.
	finish(true)

	if seq1 != seq2 || hash1 != hash2 {
		t.Errorf("повторный якорь дал (%d, %s), ждали (%d, %s)", seq2, hash2, seq1, hash1)
	}

	var count int
	if err := db.Pool().QueryRow(tenantCtx(),
		`SELECT COUNT(*) FROM audit_anchors WHERE seq = $1`, seq1).Scan(&count); err != nil {
		t.Fatalf("подсчёт якорей: %v", err)
	}
	if count != 1 {
		t.Errorf("якорей на seq %d: %d, ждали 1", seq1, count)
	}
}
