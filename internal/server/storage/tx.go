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

// Querier — общий интерфейс pool и tx; Q() выбирает активный скоуп (контракт §5.1).
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

var (
	_ Querier = (*pgxpool.Pool)(nil)
	_ Querier = (pgx.Tx)(nil)
)

// Q — tx из контекста, иначе pool. Одиночные pool-запросы со скоупом запрещены контрактом.
func (db *DB) Q(ctx context.Context) Querier {
	if tx, ok := TxFrom(ctx); ok {
		return tx
	}
	return db.pool
}

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

// beginScoped возвращает tx для запроса: переиспользует ctx или открывает новую.
// owned=true — вызывающий обязан Commit/Rollback; при TenantIDFrom в ctx GUC уже выставлен.
func (db *DB) beginScoped(ctx context.Context) (tx pgx.Tx, owned bool, err error) {
	if tx, ok := TxFrom(ctx); ok {
		return tx, false, nil
	}
	tx, err = db.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	if tenantID, ok := TenantIDFrom(ctx); ok {
		if err := db.setTenantGUC(ctx, tx, tenantID); err != nil {
			_ = tx.Rollback(ctx)
			return nil, false, err
		}
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
