package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

type ctxKey int

const (
	ctxKeyTx ctxKey = iota
	ctxKeyTenantID
)

// WithTx прокидывает активную транзакцию в контекст (вложенные BindTenant/beginScoped).
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, ctxKeyTx, tx)
}

// TxFrom возвращает pgx.Tx, если скоуп уже открыт выше по стеку.
func TxFrom(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(ctxKeyTx).(pgx.Tx)
	return tx, ok
}

// WithTenantID сохраняет нормализованный tenant_id для set_config при новом Begin.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, ctxKeyTenantID, tenantID)
}

// TenantIDFrom — tenant_id, который нужно выставить в GUC при старте owned-транзакции.
func TenantIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ctxKeyTenantID).(string)
	return id, ok
}

// DetachTenant отвязывает контекст от жизни запроса, СОХРАНЯЯ тенанта.
//
// Нужен отправке уведомлений: она уходит в detached-гоурутину (`go bot.NotifyAlert(...)`),
// потому что ходит в сеть и не должна задерживать ответ агенту. К моменту отправки
// контекст запроса уже отменён, а транзакция его скоупа — закрыта, поэтому передать
// туда ctx запроса нельзя. Передать context.Background() тоже нельзя: вместе с отменой
// он теряет и тенанта, а рассылка без тенанта — это рассылка по всей инсталляции.
//
// Транзакция НЕ переносится намеренно: она принадлежит запросу и будет закрыта раньше,
// чем гоурутина дойдёт до базы. Переносится ровно tenant_id — по нему scopeFor откроет
// уже в гоурутине СВОЮ транзакцию с тем же GUC.
//
// Тенанта в исходном контексте нет → возвращается голый Background: обязанность отказать
// лежит на потребителе (он один знает, законна ли для него работа без тенанта), а тихо
// подставлять сюда «какой-нибудь» тенант нельзя.
func DetachTenant(ctx context.Context) context.Context {
	if id, ok := TenantIDFrom(ctx); ok && id != "" {
		return WithTenantID(context.Background(), id)
	}
	return context.Background()
}

// Querier — общий интерфейс pool и tx. Остался ровно для таблиц БЕЗ тенанта: к
// тенантским ходят через TenantScope, и pool в тот путь не подставляется никогда.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

var (
	_ Querier = (*pgxpool.Pool)(nil)
	_ Querier = (pgx.Tx)(nil)
	_ Querier = TenantScope{}
)

// TenantScope — хэндл тенантского скоупа: доказательство того, что запрос уйдёт в
// транзакцию, где уже выполнен set_config('routineops.tenant_id'). Это ЕДИНСТВЕННЫЙ
// способ обратиться к таблице под RLS.
//
// 🔴 Зачем тип, а не прежняя развилка. Раньше Q(ctx) отдавал tx из контекста, а при его
// отсутствии — pool. Соседнее соединение из пула тенанта не знает, и для таблицы под
// FORCE RLS это значит: current_setting(...,true) → NULL, предикат не совпадает ни с
// одной строкой. SELECT отдаёт ноль, UPDATE трогает ноль строк, и вызывающий читает это
// как «нет данных». Тихо. Ровно так в июле лёг командный канал, так же терялся отчёт
// агента о выдаче локального админа (UpdateAdminAccessReport), и так же — до этой
// правки — уходил в никуда синк каталога. Локальные тесты класс не ловят: testutil
// ставит роли дефолтный routineops.tenant_id, и мимо-скоупный запрос в них «попадает».
//
// Теперь непривязанный контекст не доезжает до базы вовсе: нулевой TenantScope отдаёт
// ErrTenantScopeMissing из любого метода. Собрать его снаружи нельзя — поле
// неэкспортируемое, конструктор один (Scoped/BindTenant*), нулевое значение fail-closed.
//
// Что тип НЕ ловит: он не доказывает, что вызывающий выше по стеку вообще подумал о
// тенанте. Развилка «есть ли скоуп в ctx» осталась ровно одна — Scoped(ctx), и она
// fail-closed. Соответствие «таблица под RLS ⇒ обращение через TenantScope» проверяется
// статически: scope_gate_test.go разбирает SQL всех вызовов и сверяет с классификацией
// internal/server/tenancy.
type TenantScope struct{ tx pgx.Tx }

// Scoped — тенантский querier из контекста. Скоупа нет → нулевой хэндл, и любой запрос
// через него вернёт ErrTenantScopeMissing вместо тихого нуля строк.
func (db *DB) Scoped(ctx context.Context) TenantScope {
	tx, _ := TxFrom(ctx)
	return TenantScope{tx: tx}
}

func (s TenantScope) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if s.tx == nil {
		return nil, tenancy.ErrTenantScopeMissing
	}
	return s.tx.Query(ctx, sql, args...)
}

func (s TenantScope) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if s.tx == nil {
		return errRow{err: tenancy.ErrTenantScopeMissing}
	}
	return s.tx.QueryRow(ctx, sql, args...)
}

func (s TenantScope) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if s.tx == nil {
		return pgconn.CommandTag{}, tenancy.ErrTenantScopeMissing
	}
	return s.tx.Exec(ctx, sql, args...)
}

// Tx — транзакция скоупа для того, что не выражается тремя методами выше (pgx.Batch).
// Ошибка, а не nil: пропущенная проверка иначе даёт панику вместо внятного отказа.
func (s TenantScope) Tx() (pgx.Tx, error) {
	if s.tx == nil {
		return nil, tenancy.ErrTenantScopeMissing
	}
	return s.tx, nil
}

// errRow — pgx.Row, отдающий ошибку в Scan. Нужен, потому что QueryRow ошибку не
// возвращает: единственный способ довести отказ до вызывающего — через Scan, и он
// проверяется всегда.
type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

// Третьего пути нет намеренно. К таблице БЕЗ тенанта (tenancy.ScopeGlobal/ScopeMixed)
// ходят либо тем же TenantScope, если скоуп и так открыт (revoked_fingerprints внутри
// удаления устройства), либо прямо через db.pool — и тогда функция обязана попасть в
// поимённый список pool_bypass_test.go с причиной. Отдельный «querier без скоупа» был бы
// ровно тем фолбэком, который здесь и убирается: удобным, коротким и молчаливым.

func (db *DB) setTenantGUC(ctx context.Context, q Querier, tenantID string) error {
	_, err := q.Exec(ctx, `SELECT set_config('routineops.tenant_id', $1, true)`, tenantID)
	return err
}

// BindTenant открывает транзакцию со set_config или переиспользует tx из ctx.
// finish вызывают ровно один раз: commit=true → Commit, иначе Rollback.
func (db *DB) BindTenant(ctx context.Context, tenantID string) (context.Context, func(commit bool), error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return ctx, nil, err
	}
	if _, ok := TxFrom(ctx); ok {
		return ctx, func(bool) {}, nil
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return ctx, nil, err
	}
	if err := db.setTenantGUC(ctx, tx, tenantID); err != nil {
		_ = tx.Rollback(ctx)
		return ctx, nil, err
	}
	scoped := WithTenantID(WithTx(ctx, tx), tenantID)
	var once sync.Once
	finish := func(commit bool) {
		once.Do(func() {
			if commit {
				_ = tx.Commit(ctx)
			} else {
				_ = tx.Rollback(ctx)
			}
		})
	}
	return scoped, finish, nil
}

// scopeFor — «открыть скоуп, если его ещё нет выше по стеку», единым местом.
//
// tenantID пустой означает «взять из контекста» (WithTenantID): так тенант приезжает по
// агентским путям (gateway ставит его после резолва по отпечатку серта) и по панельным
// (jwtMiddleware — из проверенных claims). Не нашлось ни там, ни там — ошибка, а не
// «работаем без тенанта»: последнее и есть тот отказ, который потом читают как «нет
// данных».
//
// Возвращает: контекст со скоупом, finish (вызывающий обязан отложить), нормализованный
// tenantID и ошибку.
func (db *DB) scopeFor(ctx context.Context, tenantID string) (context.Context, func(bool), string, error) {
	if tenantID == "" {
		tenantID, _ = TenantIDFrom(ctx)
	}
	if _, ok := TxFrom(ctx); ok {
		// Скоуп уже открыт выше — тенант там же и зафиксирован; свой не открываем и
		// пустой tenantID здесь не ошибка (вложенный вызов его знать не обязан).
		return ctx, func(bool) {}, tenantID, nil
	}
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return ctx, nil, "", err
	}
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return ctx, nil, "", err
	}
	return ctx, finish, tenantID, nil
}

// beginScoped возвращает tx для многошагового запроса: переиспользует транзакцию из
// контекста либо открывает свою и выставляет в ней GUC. owned=true — вызывающий обязан
// Commit/Rollback.
//
// 🔴 Тенант обязателен. Раньше отсутствие TenantIDFrom означало «открыть транзакцию без
// GUC» — то есть ту же тихую дыру, что и pool-фолбэк в старом Q, только на несколько
// запросов сразу. Всеми шестью вызывающими (WriteAuditLog, UpsertInventory,
// GetPendingTasks, EnrollDevice, ResetDeviceForReenroll, AcceptAdminSessionWindow)
// трогаются таблицы под RLS, поэтому непривязанный контекст здесь — отказ, а не режим.
func (db *DB) beginScoped(ctx context.Context) (tx pgx.Tx, owned bool, err error) {
	if tx, ok := TxFrom(ctx); ok {
		return tx, false, nil
	}
	tenantID, ok := TenantIDFrom(ctx)
	if !ok {
		return nil, false, tenancy.ErrTenantScopeMissing
	}
	tx, err = db.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	if err := db.setTenantGUC(ctx, tx, tenantID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, false, err
	}
	return tx, true, nil
}

// ForEachTenant выполняет fn под скоупом каждого тенанта инсталляции.
//
// Фоновые задачи кросс-тенантные по природе: «истечь просроченные заявки на
// админ-права» относится ко всей инсталляции, а не к чьему-то одному тенанту.
// Тенанта в контексте у них нет и быть не может, а под ролью mdm_app (049) запрос
// к таблице с RLS без привязанного тенанта падает 22P02: предикат из 046 кастует
// пустой GUC в uuid, и это НАМЕРЕННО fail-closed. Под прежней ролью с rolbypassrls
// предикат не вычислялся вовсе — потому эти воркеры и работали до перевода на
// app-роль. Явный обход тенантов — единственный путь, не возвращающий им bypassrls.
//
// Ошибка одного тенанта не отменяет остальных: обход продолжается, ошибки
// склеиваются errors.Join. Иначе один битый тенант глушил бы фоновые задачи всей
// инсталляции — ровно тот отказ, который труднее всего заметить.
func (db *DB) ForEachTenant(ctx context.Context, fn func(ctx context.Context) error) error {
	tenants, err := db.ListTenants(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		tctx, finish, err := db.BindTenant(ctx, t.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("тенант %s: %w", t.ID, err))
			continue
		}
		err = fn(tctx)
		finish(err == nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("тенант %s: %w", t.ID, err))
		}
	}
	return errors.Join(errs...)
}

// BindTenantForDevice резолвит tenant_id устройства (DEFINER) и открывает скоуп.
// Экспортирована, как и BindTenantForTask: enterprise-оверлей escrow живёт в своём
// пакете, а пишет в тенантскую recovery_key_escrow — тенанта ему взять больше негде.
func (db *DB) BindTenantForDevice(ctx context.Context, deviceID string) (context.Context, func(bool), error) {
	if _, ok := TxFrom(ctx); ok {
		return ctx, func(bool) {}, nil
	}
	var tenantID string
	err := db.pool.QueryRow(ctx, `SELECT COALESCE(auth_device_tenant($1::uuid)::text, '')`, deviceID).Scan(&tenantID)
	if err != nil {
		return ctx, nil, err
	}
	if tenantID == "" {
		return ctx, nil, tenancy.ErrTenantScopeMissing
	}
	return db.BindTenant(ctx, tenantID)
}

// DeviceTenantID — тенант устройства по его id, через тот же SECURITY DEFINER, что и
// BindTenantForDevice. Нужен операциям НАД устройством, которые выполняются из-под
// надзора инсталляции и потому тенанта устройства не знают: перенос между тенантами
// обязан сначала разобраться с данными прежнего владельца. Пустая строка — устройства
// нет (не ошибка: вызывающий решает сам, 404 это или пропуск).
func (db *DB) DeviceTenantID(ctx context.Context, deviceID string) (string, error) {
	var tenantID string
	err := db.pool.QueryRow(ctx, `SELECT COALESCE(auth_device_tenant($1::uuid)::text, '')`, deviceID).Scan(&tenantID)
	if err != nil {
		return "", err
	}
	return tenantID, nil
}

// BindTenantForTask резолвит tenant_id задачи (DEFINER, миграция 054) и открывает скоуп.
//
// Нужна фоновой доставке: у asynq-обработчика на входе только task_id, тенанта в
// контексте нет и взяться ему неоткуда, а под app-ролью из 049 первый же запрос падает
// 22P02. Экспортирована, в отличие от родственных bindTenantFor*, потому что вызывающий
// живёт в пакете worker.
func (db *DB) BindTenantForTask(ctx context.Context, taskID string) (context.Context, func(bool), error) {
	if _, ok := TxFrom(ctx); ok {
		return ctx, func(bool) {}, nil
	}
	var tenantID string
	err := db.pool.QueryRow(ctx, `SELECT COALESCE(auth_task_tenant($1::uuid)::text, '')`, taskID).Scan(&tenantID)
	if err != nil {
		return ctx, nil, err
	}
	if tenantID == "" {
		return ctx, nil, tenancy.ErrTenantScopeMissing
	}
	return db.BindTenant(ctx, tenantID)
}

// bindTenantForUser резолвит tenant_id пользователя (DEFINER) и открывает скоуп.
func (db *DB) bindTenantForUser(ctx context.Context, userID string) (context.Context, func(bool), error) {
	if _, ok := TxFrom(ctx); ok {
		return ctx, func(bool) {}, nil
	}
	e, err := db.GetUserEpoch(ctx, userID)
	if err != nil {
		return ctx, nil, err
	}
	if e == nil || e.TenantID == "" {
		return ctx, nil, tenancy.ErrTenantScopeMissing
	}
	return db.BindTenant(ctx, e.TenantID)
}

// bindTenantForFingerprint резолвит tenant_id устройства по отпечатку (DEFINER).
// Пустой результат — ErrTenantScopeMissing (вызывающий сам решает: новый enroll → DefaultTenantID).
func (db *DB) bindTenantForFingerprint(ctx context.Context, fingerprint string) (context.Context, func(bool), error) {
	if _, ok := TxFrom(ctx); ok {
		return ctx, func(bool) {}, nil
	}
	_, tenantID, _, err := db.GetDeviceTenantByFingerprint(ctx, fingerprint)
	if err != nil {
		return ctx, nil, err
	}
	if tenantID == "" {
		return ctx, nil, tenancy.ErrTenantScopeMissing
	}
	return db.BindTenant(ctx, tenantID)
}
