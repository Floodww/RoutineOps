package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Хранилище персон каталога (LDAP Phase 1). Это ЧИСТЫЕ DB-операции на общей таблице
// directory_persons — go-ldap и синк живут отдельно в enterprise-пакете
// (internal/server/directory, //go:build enterprise), который зовёт эти методы. В Free
// таблица пуста (синка нет), методы компилируются, но не вызываются.
//
// 🔴 Тенант здесь ПАРАМЕТР, а не умолчание внутри SQL. Так было не всегда: до перехода на
// TenantScope эти методы ходили прежним Q(ctx) с непривязанным контекстом, то есть
// соседним соединением из пула, где routineops.tenant_id не выставлен. Под FORCE RLS это
// значит «предикат не совпал ни с одной строкой»: перематч владельцев не видел ни одного
// устройства, пометка исчезнувших не трогала ни одной строки — и синк при этом рапортовал
// успех. В тестах не всплывало: testutil ставит роли дефолтный тенант, и pool-запрос в
// них «попадает» (см. scope_gate_test.go — теперь это ловится статикой).

// DirectoryPerson — персона каталога. object_guid — канон (стабилен при переименовании).
type DirectoryPerson struct {
	ID                string `json:"id"`
	ObjectGUID        string `json:"object_guid"`
	ObjectSID         string `json:"object_sid"`
	SAMAccount        string `json:"sam_account"`
	UserPrincipal     string `json:"user_principal"`
	DisplayName       string `json:"display_name"`
	Email             string `json:"email"`
	DistinguishedName string `json:"distinguished_name"`
	Disabled          bool   `json:"disabled"`
	// Source — откуда строка: "ldap" (принёс синк) или "manual" (завёл оператор).
	// UI по нему решает, можно ли карточку редактировать: каталожную правят в AD.
	Source string `json:"source"`
}

// PersonSourceManual — карточка заведена оператором вручную (Free-путь). Отличается от
// каталожной тем, что её МОЖНО править и удалять в панели, и тем, что синк каталога её
// не гасит (см. MarkDirectoryPersonsStale).
const PersonSourceManual = "manual"

// UpsertDirectoryPerson — идемпотентный upsert по object_guid. Пустой SID пишется NULL
// (частичный UNIQUE-индекс по object_sid не должен ловить пустые). synced_at → now().
func (db *DB) UpsertDirectoryPerson(ctx context.Context, tenantID string, p DirectoryPerson) error {
	ctx, finish, tenantID, err := db.scopeFor(ctx, tenantID)
	if err != nil {
		return err
	}
	defer finish(true)
	_, err = db.Scoped(ctx).Exec(ctx, `
		INSERT INTO directory_persons
		    (tenant_id, object_guid, object_sid, sam_account, user_principal, display_name, email, distinguished_name, disabled, synced_at)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, $6, $7, $8, $9, now())
		ON CONFLICT (tenant_id, object_guid) DO UPDATE SET
		    object_sid         = NULLIF($3,''),
		    sam_account        = EXCLUDED.sam_account,
		    user_principal     = EXCLUDED.user_principal,
		    display_name       = EXCLUDED.display_name,
		    email              = EXCLUDED.email,
		    distinguished_name = EXCLUDED.distinguished_name,
		    disabled           = EXCLUDED.disabled,
		    synced_at          = now()
	`, tenantID, p.ObjectGUID, p.ObjectSID, p.SAMAccount, p.UserPrincipal, p.DisplayName, p.Email, p.DistinguishedName, p.Disabled)
	return err
}

// FindDirectoryPersonForMatch — матч консольного юзера с каталогом. Сперва ТОЧНО по SID
// (rename-proof), затем fallback по sAMAccountName без регистра. Отключённые учётки не
// матчим. "" = матча нет (не ошибка). Вызывающий (enterprise-матчер) уже извлёк
// sAMAccountName из "DOMAIN\user".
func (db *DB) FindDirectoryPersonForMatch(ctx context.Context, tenantID, sid, samAccount string) (personID string, err error) {
	ctx, finish, _, err := db.scopeFor(ctx, tenantID)
	if err != nil {
		return "", err
	}
	defer finish(true)
	if sid != "" {
		err = db.Scoped(ctx).QueryRow(ctx,
			`SELECT id FROM directory_persons WHERE object_sid = $1 AND NOT disabled`, sid,
		).Scan(&personID)
		if err == nil {
			return personID, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}
	if samAccount != "" {
		err = db.Scoped(ctx).QueryRow(ctx,
			`SELECT id FROM directory_persons WHERE lower(sam_account) = lower($1) AND NOT disabled LIMIT 1`, samAccount,
		).Scan(&personID)
		if err == nil {
			return personID, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}
	return "", nil
}

// SetDeviceOwnerDirectory — проставить авто-владельца из каталога. personID == "" снимает
// привязку (owner_directory_id → NULL).
func (db *DB) SetDeviceOwnerDirectory(ctx context.Context, tenantID, deviceID, personID string) error {
	ctx, finish, _, err := db.scopeFor(ctx, tenantID)
	if err != nil {
		return err
	}
	defer finish(true)
	if personID == "" {
		_, err := db.Scoped(ctx).Exec(ctx, `UPDATE devices SET owner_directory_id = NULL WHERE id = $1`, deviceID)
		return err
	}
	_, err = db.Scoped(ctx).Exec(ctx, `UPDATE devices SET owner_directory_id = $2 WHERE id = $1`, deviceID, personID)
	return err
}

// DeviceForMatch — то, что нужно матчеру: id + доложенные агентом идентификаторы юзера.
type DeviceForMatch struct {
	DeviceID       string
	ConsoleUser    string
	ConsoleUserSid string
}

// ListDevicesForDirectoryMatch — устройства, у которых есть доложенный юзер, но авто-владелец
// ещё не проставлен. Enterprise-матчер зовёт после синка для ПЕРЕМАТЧА задним числом
// (роадмап §121-123): синк подтянул персону — привязка срабатывает без миграции.
func (db *DB) ListDevicesForDirectoryMatch(ctx context.Context, tenantID string) ([]DeviceForMatch, error) {
	ctx, finish, _, err := db.scopeFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT id, COALESCE(console_user, ''), COALESCE(console_user_sid, '')
		FROM devices
		WHERE owner_directory_id IS NULL
		  AND (COALESCE(console_user,'') <> '' OR COALESCE(console_user_sid,'') <> '')
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceForMatch
	for rows.Next() {
		var d DeviceForMatch
		if err := rows.Scan(&d.DeviceID, &d.ConsoleUser, &d.ConsoleUserSid); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListDirectoryPersons — для UI «Каталог». Сортировка по display_name.
func (db *DB) ListDirectoryPersons(ctx context.Context, tenantID string) ([]DirectoryPerson, error) {
	ctx, finish, tenantID, err := db.scopeFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT id, object_guid, COALESCE(object_sid,''), COALESCE(sam_account,''),
		       COALESCE(user_principal,''), COALESCE(display_name,''), COALESCE(email,''),
		       COALESCE(distinguished_name,''), disabled, source
		FROM directory_persons
		WHERE tenant_id = $1
		ORDER BY lower(COALESCE(display_name, sam_account, object_guid))
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryPerson
	for rows.Next() {
		var p DirectoryPerson
		if err := rows.Scan(&p.ID, &p.ObjectGUID, &p.ObjectSID, &p.SAMAccount, &p.UserPrincipal,
			&p.DisplayName, &p.Email, &p.DistinguishedName, &p.Disabled, &p.Source); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// MarkDirectoryPersonsStale — пометить disabled персон, не обновлённых последним синком
// (synced_at < cutoff): исчезли из выдачи каталога. НЕ удаляем — owner-историю не рушим,
// а disabled матч уже не берёт. Возвращает число помеченных (для отчёта синка).
func (db *DB) MarkDirectoryPersonsStale(ctx context.Context, tenantID string, syncStartedBefore int64) (int64, error) {
	ctx, finish, _, err := db.scopeFor(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	defer finish(true)
	// syncStartedBefore — unix-время начала текущего синка; всё, что не тронуто им, устарело.
	tag, err := db.Scoped(ctx).Exec(ctx,
		// source <> 'manual': ручные карточки каталог не отдаёт НИКОГДА, и без этого
		// условия первый же синк погасил бы всех, кого оператор завёл сам.
		`UPDATE directory_persons SET disabled = true
		 WHERE synced_at < to_timestamp($1) AND NOT disabled AND source <> 'manual'`,
		syncStartedBefore)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
