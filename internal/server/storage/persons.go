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
func (db *DB) CreateManualPerson(ctx context.Context, displayName, email string) (DirectoryPerson, error) {
	var p DirectoryPerson
	err := db.pool.QueryRow(ctx, `
		INSERT INTO directory_persons (object_guid, display_name, email, source)
		VALUES ('manual:' || uuid_generate_v4()::text, $1, NULLIF($2,''), 'manual')
		RETURNING id, object_guid, COALESCE(object_sid,''), COALESCE(sam_account,''),
		          COALESCE(user_principal,''), COALESCE(display_name,''), COALESCE(email,''),
		          COALESCE(distinguished_name,''), disabled, source
	`, displayName, email).Scan(&p.ID, &p.ObjectGUID, &p.ObjectSID, &p.SAMAccount, &p.UserPrincipal,
		&p.DisplayName, &p.Email, &p.DistinguishedName, &p.Disabled, &p.Source)
	return p, err
}

// UpdateManualPerson правит ФИО/почту ручной карточки. Каталожные не трогает:
// ErrPersonNotManual. false = карточки с таким id нет.
func (db *DB) UpdateManualPerson(ctx context.Context, id, displayName, email string) (bool, error) {
	var source string
	err := db.pool.QueryRow(ctx, `SELECT source FROM directory_persons WHERE id = $1`, id).Scan(&source)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if source != PersonSourceManual {
		return false, ErrPersonNotManual
	}
	_, err = db.pool.Exec(ctx,
		`UPDATE directory_persons SET display_name = $2, email = NULLIF($3,'') WHERE id = $1`,
		id, displayName, email)
	return err == nil, err
}

// DeleteManualPerson удаляет ручную карточку. Устройства, где она стояла владельцем,
// просто остаются без владельца: devices.owner_directory_id объявлен ON DELETE SET NULL,
// то есть удаление человека не роняет и не скрывает саму машину.
func (db *DB) DeleteManualPerson(ctx context.Context, id string) (bool, error) {
	var source string
	err := db.pool.QueryRow(ctx, `SELECT source FROM directory_persons WHERE id = $1`, id).Scan(&source)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if source != PersonSourceManual {
		return false, ErrPersonNotManual
	}
	tag, err := db.pool.Exec(ctx, `DELETE FROM directory_persons WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
