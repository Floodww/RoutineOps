package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrPersonNotManual — попытка изменить/удалить карточку, пришедшую из каталога.
// Такие правятся в AD, иначе следующий синк молча вернул бы прежние значения, и
// оператор решил бы, что панель его не слушает.
var ErrPersonNotManual = errors.New("person is managed by the directory")

// CreateManualPerson заводит карточку человека вручную (Free-путь к владельцу устройства).
//
// object_guid у каталожных строк приносит AD, а здесь его нет — генерируем свой с
// префиксом `manual:`. Префикс не косметика: он гарантирует, что синтетический ключ
// никогда не столкнётся с настоящим objectGUID из каталога, поэтому синк не перезапишет
// ручную карточку и не сочтёт её своей.
func (db *DB) CreateManualPerson(ctx context.Context, tenantID, displayName, email string) (DirectoryPerson, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return DirectoryPerson{}, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return DirectoryPerson{}, err
		}
		defer finish(true)
	}
	var p DirectoryPerson
	err = db.Q(ctx).QueryRow(ctx, `
		INSERT INTO directory_persons (tenant_id, object_guid, display_name, email, source)
		VALUES ($1, 'manual:' || uuid_generate_v4()::text, $2, NULLIF($3,''), 'manual')
		RETURNING id, object_guid, COALESCE(object_sid,''), COALESCE(sam_account,''),
		          COALESCE(user_principal,''), COALESCE(display_name,''), COALESCE(email,''),
		          COALESCE(distinguished_name,''), disabled, source
	`, tenantID, displayName, email).Scan(&p.ID, &p.ObjectGUID, &p.ObjectSID, &p.SAMAccount, &p.UserPrincipal,
		&p.DisplayName, &p.Email, &p.DistinguishedName, &p.Disabled, &p.Source)
	return p, err
}

// UpdateManualPerson правит ФИО/почту ручной карточки. Каталожные не трогает:
// ErrPersonNotManual. false = карточки с таким id нет.
func (db *DB) UpdateManualPerson(ctx context.Context, tenantID, id, displayName, email string) (bool, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return false, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return false, err
		}
		defer finish(true)
	}
	var source string
	err = db.Q(ctx).QueryRow(ctx,
		`SELECT source FROM directory_persons WHERE tenant_id = $1 AND id = $2`, tenantID, id,
	).Scan(&source)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if source != PersonSourceManual {
		return false, ErrPersonNotManual
	}
	_, err = db.Q(ctx).Exec(ctx,
		`UPDATE directory_persons SET display_name = $3, email = NULLIF($4,'') WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, displayName, email)
	return err == nil, err
}

// DeleteManualPerson удаляет ручную карточку. Устройства, где она стояла владельцем,
// просто остаются без владельца: devices.owner_directory_id объявлен ON DELETE SET NULL,
// то есть удаление человека не роняет и не скрывает саму машину.
func (db *DB) DeleteManualPerson(ctx context.Context, tenantID, id string) (bool, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return false, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return false, err
		}
		defer finish(true)
	}
	var source string
	err = db.Q(ctx).QueryRow(ctx,
		`SELECT source FROM directory_persons WHERE tenant_id = $1 AND id = $2`, tenantID, id,
	).Scan(&source)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if source != PersonSourceManual {
		return false, ErrPersonNotManual
	}
	tag, err := db.Q(ctx).Exec(ctx, `DELETE FROM directory_persons WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
