package storage

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Floodww/RoutineOps/internal/server/alerting"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// ErrForeignKeyViolation — INSERT ссылается на уже удалённую строку (политика/
// устройство/заявка удалены раньше, чем агент доставил отчёт). Для отчётных
// outbox-RPC это ТЕРМИНАЛЬНО: payload заморожен в outbox агента, ретрай с тем же
// содержимым не пройдёт никогда → по ack-контракту gateway отвечает Received:true
// (accept-and-drop), а не Unavailable (вечный poison pill в голове очереди).
var ErrForeignKeyViolation = errors.New("insert references deleted row")

// wrapFKViolation маппит PG 23503 (foreign_key_violation) в ErrForeignKeyViolation,
// остальные ошибки отдаёт как есть.
func wrapFKViolation(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return fmt.Errorf("%w: %s", ErrForeignKeyViolation, pgErr.ConstraintName)
	}
	return err
}

// User — ЧЛЕНСТВО человека в тенанте, а не сам человек (ADR-7, §11.2). Пароля тут
// больше нет: он принадлежит личности (storage.Identity). Один человек может иметь
// несколько таких строк — по одной на тенант, с разными ролями.
type User struct {
	ID         string    `json:"id"`
	IdentityID string    `json:"-"`
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	Role       string    `json:"role"`
	CreatedAt  time.Time `json:"created_at"`
}

// GetUserByEmailInTenant ищет пользователя по e-mail внутри одного тенанта.
//
// Отличие от GetUserByEmail принципиальное: тот резолвит ДО того, как тенант известен
// (форма логина), и потому ходит через SECURITY DEFINER мимо RLS. Здесь тенант уже
// известен — его дал не пользователь, а найденная строка (IdP в OIDC-callback), и
// e-mail уникален только в пределах тенанта (045). Глобальный поиск на этом месте
// пускал бы IdP одного тенанта в чужую учётку с тем же адресом (Q-20).
func (db *DB) GetUserByEmailInTenant(ctx context.Context, tenantID, email string) (*User, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var u User
	err = db.Scoped(ctx).QueryRow(ctx, `
		SELECT id, identity_id, name, email, role, created_at
		FROM users WHERE tenant_id = $1 AND email = $2
	`, tenantID, email).Scan(&u.ID, &u.IdentityID, &u.Name, &u.Email, &u.Role, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (db *DB) GetITAdminsWithTelegramChatID(ctx context.Context) ([]string, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return nil, scopeErr
	}
	defer finish(true)
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT telegram_chat_id FROM users
		WHERE role = 'it_admin' AND telegram_chat_id IS NOT NULL AND telegram_chat_id != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// TelegramRecipient — получатель уведомления и его порог доставки.
type TelegramRecipient struct {
	ChatID string
	// MinSeverity — минимальная критичность, которую этот администратор согласен
	// получать (users.notify_min_severity, миграция 043). Пустая строка означает
	// строку, не прошедшую миграцию; alerting.DeliverTo для неё fail-open.
	MinSeverity string
}

// GetTelegramRecipients отдаёт it_admin'ов с привязанным Telegram и их порогом
// доставки. Отдельный метод рядом с GetITAdminsWithTelegramChatID, а не замена
// его: тот используется для уведомлений, у которых критичности нет вообще
// (заявка на права администратора, служебные сообщения бота), и приделывать им
// фильтр по severity было бы неверно — заявку нельзя «отфильтровать по важности»,
// она либо рассматривается, либо истекает.
func (db *DB) GetTelegramRecipients(ctx context.Context) ([]TelegramRecipient, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return nil, scopeErr
	}
	defer finish(true)
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT telegram_chat_id, COALESCE(notify_min_severity, '')
		FROM users
		WHERE role = 'it_admin' AND telegram_chat_id IS NOT NULL AND telegram_chat_id != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TelegramRecipient
	for rows.Next() {
		var r TelegramRecipient
		if err := rows.Scan(&r.ChatID, &r.MinSeverity); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetUserNotifyMinSeverity отдаёт порог доставки уведомлений пользователя.
// Пустая строка (строка не прошла миграцию 041) нормализуется в значение по
// умолчанию — «всё как раньше», а не в тишину: см. обоснование DEFAULT 'low' в 041.
func (db *DB) GetUserNotifyMinSeverity(ctx context.Context, userID string) (string, error) {
	ctx, finish, err := db.bindTenantForUser(ctx, userID)
	if err != nil {
		return "", err
	}
	defer finish(true)
	var s string
	err = db.Scoped(ctx).QueryRow(ctx,
		`SELECT COALESCE(notify_min_severity, '') FROM users WHERE id = $1`, userID).Scan(&s)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("user %s not found", userID)
		}
		return "", err
	}
	if s == "" {
		return string(alerting.SeverityLow), nil
	}
	return s, nil
}

// SetUserNotifyMinSeverity меняет порог доставки. Значение валидируется вызывающим
// (api.setNotifyMinSeverity) и страхуется CHECK-ограничением в схеме.
func (db *DB) SetUserNotifyMinSeverity(ctx context.Context, userID, minSeverity string) error {
	ctx, finish, err := db.bindTenantForUser(ctx, userID)
	if err != nil {
		return err
	}
	defer finish(true)
	tag, err := db.Scoped(ctx).Exec(ctx,
		`UPDATE users SET notify_min_severity = $1 WHERE id = $2`, minSeverity, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s not found", userID)
	}
	return nil
}

func (db *DB) SetUserTelegramChatID(ctx context.Context, userID, chatID string) error {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return scopeErr
	}
	defer finish(true)
	_, err := db.Scoped(ctx).Exec(ctx,
		`UPDATE users SET telegram_chat_id = $1 WHERE id = $2`, chatID, userID)
	return err
}

// GetUserByLinkToken резолвит пользователя по токену привязки Telegram — ДО того, как
// тенант известен. Токен приходит от Bot API, где нашей сессии нет вовсе, поэтому это
// такой же pre-auth-резолв, как приглашение или сброс пароля: SECURITY DEFINER
// auth_user_by_link_token (миграция 069), прямо через пул.
//
// Возвращает тенанта отдельным значением: вызывающий обязан выставить его в контекст
// перед всеми последующими запросами (см. notifier.handleStart).
func (db *DB) GetUserByLinkToken(ctx context.Context, token string) (*User, string, error) {
	var u User
	var tenantID string
	err := db.pool.QueryRow(ctx, `
		SELECT id, tenant_id::text, identity_id, name, email, role, created_at
		FROM auth_user_by_link_token($1)`, token).
		Scan(&u.ID, &tenantID, &u.IdentityID, &u.Name, &u.Email, &u.Role, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", nil
		}
		return nil, "", err
	}
	return &u, tenantID, nil
}

// SetUserLinkToken ставит или снимает link-токен привязки Telegram.
//
// Скоуп по пользователю: users тенантская, а вызывающие (профиль, привязка
// Telegram) тенанта в контекст не кладут — без bind запрос уходит в пул, где на
// соединении мог остаться пустой routineops.tenant_id, и предикат RLS падает,
// пытаясь привести пустую строку к uuid.
func (db *DB) SetUserLinkToken(ctx context.Context, userID, token string) error {
	ctx, finish, err := db.bindTenantForUser(ctx, userID)
	if err != nil {
		return err
	}
	defer finish(true)

	if token == "" {
		_, err = db.Scoped(ctx).Exec(ctx, `UPDATE users SET telegram_link_token = NULL WHERE id = $1`, userID)
	} else {
		_, err = db.Scoped(ctx).Exec(ctx, `UPDATE users SET telegram_link_token = $1 WHERE id = $2`, token, userID)
	}
	return err
}

func (db *DB) GetUserTelegramStatus(ctx context.Context, userID string) (chatID *string, linkToken *string, err error) {
	ctx, finish, err := db.bindTenantForUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	defer finish(true)

	err = db.Scoped(ctx).QueryRow(ctx, `
		SELECT telegram_chat_id, telegram_link_token FROM users WHERE id = $1`, userID).
		Scan(&chatID, &linkToken)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	return chatID, linkToken, err
}

func (db *DB) UpdateUser(ctx context.Context, tenantID, id, name, email string) (bool, error) {
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

	res, err := db.Scoped(ctx).Exec(ctx, `
		UPDATE users
		SET name = $1, email = $2
		WHERE id = $3 AND tenant_id = $4
	`, name, email, id, tenantID)
	if err != nil {
		return false, err
	}
	return res.RowsAffected() > 0, nil
}

func (db *DB) GetDeviceHostname(ctx context.Context, deviceID string) (string, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		if errors.Is(err, tenancy.ErrTenantScopeMissing) {
			if len(deviceID) >= 8 {
				return deviceID[:8], nil
			}
			return deviceID, nil
		}
		return "", err
	}
	defer finish(true)
	var hostname string
	err = db.Scoped(ctx).QueryRow(ctx, `SELECT hostname FROM devices WHERE id = $1`, deviceID).Scan(&hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		if len(deviceID) >= 8 {
			return deviceID[:8], nil
		}
		return deviceID, nil
	}
	return hostname, err
}

func (db *DB) CreateUser(ctx context.Context, tenantID, name, email, passwordHash, role string) (*User, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	// ADR-7: сначала личность, потом членство. Если человек с таким e-mail уже есть
	// в другом тенанте, новая личность НЕ создаётся — к существующей добавляется
	// членство, и пароль у него остаётся прежний. Переданный passwordHash в этом
	// случае игнорируется: назначать человеку второй пароль мы не вправе.
	identityID, _, err := db.EnsureIdentity(ctx, email, passwordHash)
	if err != nil {
		return nil, err
	}
	var u User
	err = db.Scoped(ctx).QueryRow(ctx, `
		INSERT INTO users (tenant_id, identity_id, name, email, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, email, role, created_at
	`, tenantID, identityID, name, email, role).
		Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.IdentityID = identityID
	return &u, nil
}

type Device struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	OSVersion  string `json:"os_version"`
	IPAddress  string `json:"ip_address"`
	Status     string `json:"status"`
	TenantID   string `json:"tenant_id,omitempty"`
	LockStatus string `json:"lock_status"`
	// LockActualState — что агент ФАКТИЧЕСКИ доложил про лок, в отличие от
	// lock_status (желаемое). Заполняется только в GetDevice (карточка). Пусто =
	// отчётов не было. Расхождение desired/actual — единственный способ увидеть,
	// что лок выдан, но на устройстве не применился (lock_failed) либо применён
	// наполовину (filevault_revoked/filevault_revoke_failed): до этого колонка
	// писалась, но не читалась НИГДЕ, и оператор видел только «заблокировано».
	LockActualState string     `json:"lock_actual_state"`
	LockActualAt    *time.Time `json:"lock_actual_at"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	CreatedAt       time.Time  `json:"created_at"`
	CertCN          string     `json:"cert_cn"`
	EnrolledAt      *time.Time `json:"enrolled_at"`
	CPU             string     `json:"cpu"`
	RAM             int64      `json:"ram_mb"`
	Disk            string     `json:"disk"`
	MACAddress      string     `json:"mac_address"`
	SerialNumber    string     `json:"serial_number"`
	PublicIP        string     `json:"public_ip"`
	AgentVersion    string     `json:"agent_version"`
	// Расширение инвентаря (миграция 030). Заполняются в GetDevice (карточка);
	// в списках устройств пока не выбираются. Пусто/0 = агент не сообщил.
	Arch           string `json:"arch"`
	ConsoleUser    string `json:"console_user"`    // Windows: DOMAIN\user; "" = за консолью никого
	DiskEncryption string `json:"disk_encryption"` // "enabled"/"disabled"/""
	OSPatchDate    string `json:"os_patch_date"`   // ISO "2006-01-02"; "" = неизвестно
	BootTime       int64  `json:"boot_time"`       // unix-время загрузки; 0 = неизвестно
	DiskFree       string `json:"disk_free"`
	DomainJoined   string `json:"domain_joined"` // "true"/"false"/""
	TPM            string `json:"tpm"`           // "true"/"false"/""
	SecureBoot     string `json:"secure_boot"`   // "true"/"false"/""
	// Устройство может состоять в НЕСКОЛЬКИХ группах (device_group_members — m2m),
	// поэтому это список, а не одна ссылка. Первая группа задаёт цвет рамки в UI.
	Groups []DeviceGroupRef `json:"groups"`
	// Владелец — ВСЕГДА карточка человека (directory_persons), а не аккаунт панели
	// (миграция 038). В Enterprise карточку приносит синк AD, во Free оператор заводит
	// её руками; поле и смысл при этом одни и те же. Заполняются в GetDevice.
	OwnerPersonID    string `json:"owner_person_id"`    // owner_directory_id; "" = владельца нет
	OwnerPersonName  string `json:"owner_person_name"`  // ФИО для показа
	OwnerPersonEmail string `json:"owner_person_email"` // почта владельца
	// Здоровье durable-очереди агента (миграция 039). Заполняется и в списке, и в
	// карточке — в отличие от инвентарных полей выше: «какие машины сейчас слепы»
	// это вопрос к парку целиком, и заставлять оператора открывать тысячу карточек,
	// чтобы его задать, бессмысленно.
	OutboxUnavailable bool       `json:"outbox_unavailable"`
	DegradedDetail    string     `json:"degraded_detail"` // причина; пусто = агент её не назвал
	DegradedSince     *time.Time `json:"degraded_since"`  // nil = очередь жива
}

// DeviceGroupRef — компактная ссылка на группу в строке/карточке устройства. Цвет едет
// вместе с именем: без него фронту пришлось бы отдельно тянуть /device-groups, чтобы
// покрасить рамку.
type DeviceGroupRef struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

type DB struct {
	pool *pgxpool.Pool
}

func Connect(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (db *DB) Close() {
	db.pool.Close()
}

// Pool отдаёт нижележащий pgx-пул. Нужен enterprise-оверлею (escrow) для своих
// INSERT без расширения free-поверхности методов storage. Open-core сам его не зовёт.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}

// UpsertDeviceHeartbeat создаёт устройство при первом подключении или обновляет last_seen_at/ip.
// hostname = device_id (CN сертификата) до тех пор, пока не придёт ReportInventory.
// Heartbeat переводит enrolled→active И pending→active: раз пришёл heartbeat с валидным
// certificate_fingerprint — энролл фактически состоялся, значит устройство живое и должно
// быть видимым в списке (ListEnrolledDevices прячет pending). Иначе реенролл со старым
// сертификатом (fingerprint совпал, свежий токен не использован) навсегда оставлял бы
// живой девайс в pending. Прочие статусы (blocked) НЕ трогаем — иначе heartbeat молча
// снимал бы блокировку у подключённого устройства.

// Здоровье outbox пишется тем же оператором, а не отдельным UPDATE: heartbeat приходит
// раз в 30 секунд с каждого устройства парка, и второй запрос на кадр удвоил бы запись
// ради поля, которое почти всегда false. degraded_since взводится ОДИН раз (COALESCE
// на существующее) — иначе «лежит с 14:02» обнулялось бы каждым кадром и превратилось
// бы в дубль last_seen_at.

func (db *DB) UpsertDeviceHeartbeat(ctx context.Context, d HeartbeatData) error {
	ctx, finish, err := db.bindTenantForFingerprint(ctx, d.CertFingerprint)
	if errors.Is(err, tenancy.ErrTenantScopeMissing) {
		ctx, finish, err = db.BindTenant(ctx, tenancy.DefaultTenantID)
	}
	if err != nil {
		return err
	}
	defer finish(true)
	tenantID := tenancy.DefaultTenantID
	if tid, ok := TenantIDFrom(ctx); ok && tid != "" {
		tenantID = tid
	}
	_, err = db.Scoped(ctx).Exec(ctx, `
		INSERT INTO devices (hostname, os, ip_address, public_ip, status, certificate_fingerprint, cert_cn, last_seen_at,
		                     outbox_unavailable, degraded_detail, degraded_since, tenant_id)
        VALUES ($1, 'unknown', $2, NULLIF($5,''), 'active', $3, $4, now(),
                $6, CASE WHEN $6 THEN $7::text ELSE '' END, CASE WHEN $6 THEN now() END, $8)
		ON CONFLICT (certificate_fingerprint)
		DO UPDATE SET ip_address = COALESCE(NULLIF($2,''), devices.ip_address), public_ip = COALESCE(NULLIF($5,''), devices.public_ip), last_seen_at = now(), cert_cn = $4,
			status = CASE WHEN devices.status IN ('enrolled', 'pending') THEN 'active' ELSE devices.status END,
			outbox_unavailable = $6,
			degraded_detail = CASE WHEN $6 THEN $7::text ELSE '' END,
			degraded_since  = CASE WHEN $6 THEN COALESCE(devices.degraded_since, now()) END
	`, d.DeviceID, d.IPAddress, d.CertFingerprint, d.CertCN, d.PublicIP, d.OutboxUnavailable, d.DegradedDetail, tenantID)
	return err
}

type SoftwareItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Поля ниже — proto SoftwareItem 3–8 (миграция 036). Пусто = источник не отдал.
	Vendor          string `json:"vendor,omitempty"`
	InstallLocation string `json:"install_location,omitempty"`
	Arch            string `json:"arch,omitempty"`         // в диалекте источника, не нормализуется
	UninstallID     string `json:"uninstall_id,omitempty"` // машинный ключ цели для будущего удаления
	UninstallMethod string `json:"uninstall_method,omitempty"`
	Scope           string `json:"scope,omitempty"` // machine / user; user снять нечем
}

type InventoryData struct {
	CertFingerprint string
	MACAddress      string
	SerialNumber    string
	Hostname        string
	OS              string
	OSVersion       string
	CPU             string
	RAM             int64
	Disk            string
	IPAddress       string
	AgentVersion    string
	Software        []SoftwareItem

	// Расширение инвентаря (proto DeviceInfo 12–20, миграция 030). Пустая
	// строка / 0 = «агент не знает» — такие значения не затирают известное
	// (sticky-паттерн COALESCE(NULLIF(...))). Исключение — ConsoleUser: там
	// пустая строка это реальный факт «за консолью никого», пишется как есть.
	//
	// Тот же паттерн распространён на дооктябрьские поля выше (Hostname,
	// OSVersion, CPU, RAM, Disk, IPAddress): у агента нет канала «проба
	// не удалась» — collector.Collect() отдаёт нулевое значение и при
	// транзиентном сбое (WMI-икота на Windows глушит os_version+ram+disk
	// разом, Wi-Fi-переподключение — ip_address), отчёт всё равно уходит и
	// затирал карточку до следующего цикла. OS не sticky намеренно: это
	// normalizeOS(runtime.GOOS), пустым не бывает.
	Arch           string
	ConsoleUser    string
	ConsoleUserSid string // стабильный SID консольного юзера (Windows); ключ матча с каталогом
	DiskEncryption string
	OSPatchDate    string
	BootTime       int64
	DiskFree       string
	DomainJoined   string
	TPM            string
	SecureBoot     string

	// Capabilities — что УМЕЕТ бинарь на устройстве сверх своей версии (миграция 067).
	//
	// Единственное поле инвентаря, которое пишется НЕ по sticky-паттерну, и это
	// намеренно. Способности обязаны уметь СЖИМАТЬСЯ: агента могут понизить с
	// enterprise-сборки на free той же версии, и тогда удалённого стола в нём физически
	// нет (файлы вырезаны тегом сборки). Sticky-запись оставила бы `screen_session`
	// навсегда, и сервер продолжил бы ставить сеансы агенту, который их не умеет, —
	// то есть ровно тот исход, ради предотвращения которого гейт способностей и заведён
	// (§9.17 контракта удалённого стола).
	//
	// Обратная сторона названа честно: агент старее поля не присылает ничего, и его
	// список станет пустым. Это верный ответ — такой агент действительно не умеет
	// ничего из перечисляемого здесь.
	Capabilities []string
}

type HeartbeatData struct {
	CertFingerprint string
	PublicIP        string
	DeviceID        string
	CertCN          string
	IPAddress       string
	// OutboxUnavailable — durable-очередь агента не пишется/не читается. Едет в
	// heartbeat, потому что отчитаться об этом больше нечем: outbox и есть канал
	// доставки отчётов, статусов лока и security-событий (миграция 039).
	OutboxUnavailable bool
	// DegradedDetail — причина, уже обрезанная агентом до 200 Б. Значима только при
	// взведённом флаге; при снятом затирается пустой строкой, чтобы в карточке не
	// висела причина позавчерашнего сбоя.
	DegradedDetail string
}

// UpsertInventory обновляет поля устройства и заменяет список ПО атомарно.
// Устройство должно уже существовать (создаётся при первом heartbeat).
func (db *DB) UpsertInventory(ctx context.Context, d InventoryData) error {
	tx, owned, err := db.beginScoped(ctx)
	if err != nil {
		return err
	}
	if owned {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	var deviceID string
	err = tx.QueryRow(ctx, `
		UPDATE devices
		SET hostname = COALESCE(NULLIF($1,''), devices.hostname),
		    os = $2,
		    os_version = COALESCE(NULLIF($3,''), devices.os_version),
		    cpu = COALESCE(NULLIF($4,''), devices.cpu),
		    ram = COALESCE(NULLIF($5::bigint, 0), devices.ram),
		    disk = COALESCE(NULLIF($6,''), devices.disk),
		    ip_address = COALESCE(NULLIF($7,''), devices.ip_address),
		    mac_address = COALESCE(NULLIF($9,''), devices.mac_address),
		    serial_number = COALESCE(NULLIF($10,''), devices.serial_number),
		    agent_version = COALESCE(NULLIF($11,''), devices.agent_version),
		    arch = COALESCE(NULLIF($12,''), devices.arch),
		    console_user = $13,
		    console_user_sid = $21,
		    disk_encryption = COALESCE(NULLIF($14,''), devices.disk_encryption),
		    os_patch_date = COALESCE(NULLIF($15,''), devices.os_patch_date),
		    boot_time = COALESCE(NULLIF($16::bigint, 0), devices.boot_time),
		    disk_free = COALESCE(NULLIF($17,''), devices.disk_free),
		    domain_joined = COALESCE(NULLIF($18,''), devices.domain_joined),
		    tpm = COALESCE(NULLIF($19,''), devices.tpm),
		    secure_boot = COALESCE(NULLIF($20,''), devices.secure_boot),
		    capabilities = $22,
		    last_seen_at = now()
		WHERE certificate_fingerprint = $8
		RETURNING id
	`, d.Hostname, d.OS, d.OSVersion, d.CPU, d.RAM, d.Disk, d.IPAddress, d.CertFingerprint, d.MACAddress, d.SerialNumber, d.AgentVersion,
		d.Arch, d.ConsoleUser, d.DiskEncryption, d.OSPatchDate, d.BootTime, d.DiskFree, d.DomainJoined, d.TPM, d.SecureBoot, d.ConsoleUserSid,
		d.Capabilities).
		Scan(&deviceID)
	if err != nil {
		return fmt.Errorf("update device: %w", err)
	}

	if _, err = tx.Exec(ctx, `DELETE FROM device_software WHERE device_id = $1`, deviceID); err != nil {
		return fmt.Errorf("delete old software: %w", err)
	}

	// CopyFrom запрещён в Postgres при включённом RLS для не-владельцев (ERROR: 0A000).
	// Используем pgx.Batch, который решает ту же проблему (убирает round-trip'ы),
	// отправляя все INSERT'ы единым пакетом, но легален для RLS.
	batch := &pgx.Batch{}
	for _, s := range d.Software {
		batch.Queue(`INSERT INTO device_software (device_id, software_name, version, vendor, install_location, arch, uninstall_id, uninstall_method, scope)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			deviceID, s.Name, s.Version, s.Vendor, s.InstallLocation, s.Arch, s.UninstallID, s.UninstallMethod, s.Scope)
	}
	br := tx.SendBatch(ctx, batch)
	var batchErr error
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			batchErr = err
			break
		}
	}
	br.Close()
	if batchErr != nil {
		return fmt.Errorf("insert software: %w", batchErr)
	}

	if owned {
		return tx.Commit(ctx)
	}
	return nil
}

func (db *DB) GetDevice(ctx context.Context, tenantID, id string) (*Device, []SoftwareItem, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, nil, err
		}
		defer finish(true)
	}
	var d Device
	err = db.Scoped(ctx).QueryRow(ctx, `
  SELECT id, hostname, os, COALESCE(os_version, ''), COALESCE(ip_address, ''),
         status, COALESCE(lock_status, 'unlocked'), last_seen_at, created_at,
         COALESCE(cert_cn, ''), enrolled_at,
         COALESCE(cpu, ''), COALESCE(ram, 0), COALESCE(disk, ''),
       COALESCE(mac_address, ''), COALESCE(serial_number, ''), COALESCE(public_ip, ''),
       COALESCE(agent_version, ''),
       COALESCE(arch, ''), COALESCE(console_user, ''), COALESCE(disk_encryption, ''),
       COALESCE(os_patch_date, ''), COALESCE(boot_time, 0), COALESCE(disk_free, ''),
       COALESCE(domain_joined, ''), COALESCE(tpm, ''), COALESCE(secure_boot, ''),
       COALESCE(lock_actual_state, ''), lock_actual_at,
       COALESCE(d.owner_directory_id::text, ''),
       COALESCE((SELECT COALESCE(display_name, sam_account) FROM directory_persons WHERE id = d.owner_directory_id), ''),
       COALESCE((SELECT email FROM directory_persons WHERE id = d.owner_directory_id), ''),
       d.outbox_unavailable, COALESCE(d.degraded_detail, ''), d.degraded_since
  FROM devices d WHERE d.id = $1 AND d.tenant_id = $2
 `, id, tenantID).Scan(&d.ID, &d.Hostname, &d.OS, &d.OSVersion,
		&d.IPAddress, &d.Status, &d.LockStatus, &d.LastSeenAt, &d.CreatedAt,
		&d.CertCN, &d.EnrolledAt, &d.CPU, &d.RAM, &d.Disk, &d.MACAddress, &d.SerialNumber, &d.PublicIP,
		&d.AgentVersion,
		&d.Arch, &d.ConsoleUser, &d.DiskEncryption,
		&d.OSPatchDate, &d.BootTime, &d.DiskFree,
		&d.DomainJoined, &d.TPM, &d.SecureBoot,
		&d.LockActualState, &d.LockActualAt,
		&d.OwnerPersonID, &d.OwnerPersonName, &d.OwnerPersonEmail,
		&d.OutboxUnavailable, &d.DegradedDetail, &d.DegradedSince)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	d.Groups = []DeviceGroupRef{}
	groups, err := db.Scoped(ctx).Query(ctx, `
  SELECT g.id, g.name, g.color
  FROM device_group_members m
  JOIN device_groups g ON g.id = m.group_id
  WHERE m.device_id = $1
  ORDER BY g.name
 `, d.ID)
	if err != nil {
		return nil, nil, err
	}
	for groups.Next() {
		var ref DeviceGroupRef
		if err := groups.Scan(&ref.ID, &ref.Name, &ref.Color); err != nil {
			groups.Close()
			return nil, nil, err
		}
		d.Groups = append(d.Groups, ref)
	}
	groups.Close()
	if err := groups.Err(); err != nil {
		return nil, nil, err
	}

	rows, err := db.Scoped(ctx).Query(ctx, `
  SELECT software_name, COALESCE(version, ''), vendor, install_location, arch,
         uninstall_id, uninstall_method, scope
  FROM device_software WHERE device_id = $1
  ORDER BY software_name, scope, uninstall_id
 `, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var software []SoftwareItem
	for rows.Next() {
		var s SoftwareItem
		if err := rows.Scan(&s.Name, &s.Version, &s.Vendor, &s.InstallLocation, &s.Arch,
			&s.UninstallID, &s.UninstallMethod, &s.Scope); err != nil {
			return nil, nil, err
		}
		software = append(software, s)
	}
	return &d, software, rows.Err()
}

// SetDeviceOwnerPerson — привязка владельца-человека: owner_directory_id →
// directory_persons(id). personID == "" снимает владельца. Неверный uuid /
// несуществующая карточка → ошибка (parse/FK) наверх, вызывающий отдаёт 400.
// Возвращает, нашлось ли устройство.
//
// Одна ручка на оба издания намеренно: карточка может быть и ручной (Free), и принесённой
// синком AD (Enterprise) — для устройства это один и тот же владелец. Enterprise-матчер
// при этом ставит владельца ТОЛЬКО устройствам без него, поэтому назначенный здесь
// вручную владелец синком не затирается.
func (db *DB) SetDeviceOwnerPerson(ctx context.Context, tenantID, deviceID, personID string) (bool, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return false, err
	}
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return false, err
	}
	defer finish(true)
	if personID != "" {
		var personTenant string
		err = db.Scoped(ctx).QueryRow(ctx, `SELECT tenant_id::text FROM directory_persons WHERE id = $1`, personID).Scan(&personTenant)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return false, fmt.Errorf("person not found")
			}
			return false, err
		}
		if personTenant != tenantID {
			return false, fmt.Errorf("person belongs to another tenant")
		}
	}
	var tag pgconn.CommandTag
	if personID == "" {
		tag, err = db.Scoped(ctx).Exec(ctx,
			`UPDATE devices SET owner_directory_id = NULL WHERE id = $1 AND tenant_id = $2`, deviceID, tenantID)
	} else {
		tag, err = db.Scoped(ctx).Exec(ctx,
			`UPDATE devices SET owner_directory_id = $3 WHERE id = $1 AND tenant_id = $2`, deviceID, tenantID, personID)
	}
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

type Task struct {
	ID            string    `json:"id"`
	DeviceID      string    `json:"device_id"`
	ScriptContent string    `json:"script_content"`
	Platform      string    `json:"platform"`
	Priority      string    `json:"priority"`
	Status        string    `json:"status"`
	Output        *string   `json:"output"`
	ErrorLog      *string   `json:"error_log"`
	CreatedAt     time.Time `json:"created_at"`
	TaskType      string    `json:"task_type"`
	LockHash      string    `json:"lock_hash"`
	LockReason    string    `json:"lock_reason"`
	LockUnlock    bool      `json:"lock_unlock"`
	LockMode      string    `json:"lock_mode"` // 'overlay'|'filevault' (022); пусто трактуется как overlay
	// Перезагрузка (037). Delay=0 означает «дефолт агента» (60 с), а не «сейчас».
	RebootReason       string `json:"reboot_reason"`
	RebootDelaySeconds int32  `json:"reboot_delay_seconds"`
	// Удаление ПО (043). Uninstall* — СЕЛЕКТОР цели из снимка инвентаря, а не команда:
	// агент ищет по нему запись в своём свежем снимке и выполняет собственный метод.
	// Пустое поле значит «сервер этого не знает», а не «подходит любое».
	Uninstall UninstallTarget `json:"uninstall,omitzero"`
	// UninstallOutcome — машиночитаемый исход (proto UninstallOutcome), отдельно от
	// status: completed/failed не различает «снято», «уже нет», «цель разъехалась» и
	// «сносить нечем», а это разные действия оператора. Пусто — не uninstall-задача
	// либо отчёта ещё не было.
	UninstallOutcome string `json:"uninstall_outcome,omitempty"`
}

// UninstallTarget — селектор удаляемого ПО. Ровно те поля SoftwareItem, которые сервер
// получил от этого же агента.
type UninstallTarget struct {
	SoftwareName    string `json:"software_name"`
	Version         string `json:"version,omitempty"`
	UninstallID     string `json:"uninstall_id,omitempty"`
	InstallLocation string `json:"install_location,omitempty"`
	Method          string `json:"uninstall_method,omitempty"`
	Scope           string `json:"scope,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// Режимы блокировки (совпадают с CHECK-домены значений lock_mode в 022 и с
// proto LockMode). Пустая строка/unknown = overlay (fail-safe: НИКОГДА не деструктив).
const (
	LockModeOverlay   = "overlay"
	LockModeFileVault = "filevault"
)

// ErrDeviceNotActive — попытка создать скрипт-задачу для устройства не в статусе
// 'active' (pending_approval/rejected/blocked/decommissioned/pending). Скрипт-канал =
// RCE от SYSTEM/root; неодобренная/отрезанная машина не должна его получать даже
// пушем (парный гейт к FetchScriptPolicies на pull-канале).
var ErrDeviceNotActive = errors.New("device is not active")

func (db *DB) CreateTask(ctx context.Context, deviceID, scriptContent, platform, priority string) (*Task, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	if err := db.assertAgentSupports(ctx, deviceID, "script"); err != nil {
		return nil, err
	}
	var t Task
	err = db.Scoped(ctx).QueryRow(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status, tenant_id)
  SELECT $1, $2, $3, $4, 'pending', d.tenant_id FROM devices d WHERE d.id = $1 AND d.status = 'active'
  RETURNING id, device_id, script_content, platform, priority, status, created_at
 `, deviceID, scriptContent, platform, priority).
		Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDeviceNotActive // устройство не active → задачу не создаём
	}
	return &t, err
}

// ErrTaskNotOwned — задача не принадлежит вызывающему устройству (или не существует).
// Возвращается Ack/CompleteTask, когда task_id + device_id не дают строки: без скоупинга
// по device_id одно устройство могло Ack'нуть/зарепортить задачу ЧУЖОГО (BOLA/IDOR) —
// тихо подавить доставку lock/remediation-команды или подделать её «успех».
var ErrTaskNotOwned = errors.New("task not found for this device")

func (db *DB) AckTask(ctx context.Context, taskID, deviceID string) error {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	defer finish(true)
	tag, err := db.Scoped(ctx).Exec(ctx,
		`UPDATE tasks SET status = 'acked', acked_at = now() WHERE id = $1 AND device_id = $2`,
		taskID, deviceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTaskNotOwned
	}
	return nil
}

// CompleteTask записывает результат и возвращает статус, который был у задачи ДО этого.
//
// Предыдущий статус нужен из-за гонки с FailStaleAckedTasks: тот закрывает задачу как
// 'failed' по таймауту, а результат от живого агента может приехать позже (общий FIFO-outbox
// агента — одна застрявшая запись задерживает все остальные). Раньше поздний результат
// молча перетирал 'failed' на 'completed' вместе с completed_at: данные в итоге верные,
// но факт, что консоль какое-то время показывала неправду, исчезал бесследно.
//
// Результат при этом ПРИНИМАЕТСЯ, а не отвергается. Гард `AND status='acked'` был бы
// проще, но он сохранял бы ложь навсегда: задача реально выполнилась, агент это доказал,
// а мы бы оставили 'failed' только потому, что доставка опоздала. Плюс RowsAffected()==0
// вернуло бы ErrTaskNotOwned, а это по контракту Report*-RPC poison-pill — агент счёл бы
// запись безнадёжной, и в логе стояло бы «не твоя задача» вместо «опоздал».
//
// Видимым исправление делает вызывающий (аудит + WARN) — см. gateway.ReportTaskResult.
//
// Старый статус берётся самоджойном: `FROM tasks old` видит строку в снимке ДО апдейта,
// RETURNING OLD.* в Postgres не поддерживается.
// taskType возвращается вместе с prevStatus: gateway по нему решает пост-эффект
// завершения (decommission-задача с SUCCESS → пометить устройство списанным).
func (db *DB) CompleteTask(ctx context.Context, taskID, deviceID, status, output, errLog string) (prevStatus, taskType string, err error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return "", "", err
	}
	defer finish(true)
	err = db.Scoped(ctx).QueryRow(ctx, `
  UPDATE tasks t
  SET status = $3, output = $4, error_log = $5, completed_at = now()
  FROM tasks old
  WHERE t.id = $1 AND t.device_id = $2 AND old.id = t.id
  RETURNING old.status, old.task_type
 `, taskID, deviceID, status, output, errLog).Scan(&prevStatus, &taskType)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrTaskNotOwned
		}
		return "", "", err
	}
	return prevStatus, taskType, nil
}

// StaleAckedTimeoutMinutes — сколько ждать ReportTaskResult после ack, прежде чем
// считать задачу просвистевшей. Втрое больше агентского потолка выполнения скрипта
// (maxRuntime = 5 мин, internal/agent/command/executor.go): реально выполняющаяся
// задача заведомо успевает отчитаться, даже медленная.
const StaleAckedTimeoutMinutes = 15

// FailStaleAckedTasks закрывает задачи, застрявшие в 'acked': агент подтвердил
// получение, но результат так и не прислал — упал посреди выполнения либо потерял его
// при сбое отправки (у агента ReportTaskResult идёт мимо durable-очереди). Без этого
// строка висит БЕССРОЧНО: единственный выход из 'acked' — CompleteTask, а
// CleanupOldData таблицу tasks не трогает вовсе.
//
// task_type='lock' исключён НАМЕРЕННО: лок-задача отчитывается через ReportLockStatus и
// ReportTaskResult не зовёт никогда (handleLock в internal/agent/command/executor.go),
// поэтому штатно остаётся в 'acked'. Без этого условия КАЖДЫЙ лок получал бы ложный failed.
//
// Статус терминальный ('failed'), а не возврат в 'pending': передоставка бесполезна —
// агент глушит повтор персистентным seen-set'ом по task_id.
// Порог считается в SQL (now() на стороне БД), чтобы не зависеть от часов и таймзоны
// процесса: acked_at пишется тем же серверным now().
func (db *DB) FailStaleAckedTasks(ctx context.Context, timeoutMinutes int) (int64, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return 0, scopeErr
	}
	defer finish(true)
	res, err := db.Scoped(ctx).Exec(ctx, `
  UPDATE tasks
  SET status = 'failed',
      error_log = 'агент подтвердил получение, но не прислал результат (таймаут)',
      completed_at = now()
  WHERE status = 'acked'
    AND task_type <> 'lock'
    AND acked_at < now() - make_interval(mins => $1)
 `, timeoutMinutes)
	if err != nil {
		return 0, fmt.Errorf("fail stale acked tasks: %w", err)
	}
	return res.RowsAffected(), nil
}

func (db *DB) GetDeviceCN(ctx context.Context, deviceID string) (string, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return "", scopeErr
	}
	defer finish(true)
	var cn string
	err := db.Scoped(ctx).QueryRow(ctx,
		`SELECT COALESCE(cert_cn, '') FROM devices WHERE id = $1`, deviceID).Scan(&cn)
	return cn, err
}

func (db *DB) CreateLockTask(ctx context.Context, deviceID, lockHash, lockReason string, unlock bool, lockMode string) (*Task, error) {
	if lockMode == "" {
		lockMode = LockModeOverlay // fail-safe
	}
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	if err := db.assertAgentSupports(ctx, deviceID, "lock"); err != nil {
		return nil, err
	}
	var t Task
	err = db.Scoped(ctx).QueryRow(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status, task_type, lock_hash, lock_reason, lock_unlock, lock_mode, tenant_id)
  SELECT $1, '', COALESCE(d.os, 'unknown'), 'high', 'pending', 'lock', $2, $3, $4, $5, d.tenant_id
  FROM devices d WHERE d.id = $1
  RETURNING id, device_id, script_content, platform, priority, status, created_at, task_type, lock_hash, lock_reason, lock_unlock, lock_mode
 `, deviceID, lockHash, lockReason, unlock, lockMode).
		Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.CreatedAt, &t.TaskType, &t.LockHash, &t.LockReason, &t.LockUnlock, &t.LockMode)
	return &t, err
}

// ErrNoDesiredLock — подтверждение блокировки пришло на устройство, у которого
// desired-лока нет (lock_hash пуст). Так выглядит устаревший/дубликатный LOCKED из
// durable-outbox агента, доехавший ПОСЛЕ снятия: unlock чистит lock_hash
// (SetDeviceLockState), а частичный апдейт статуса воскрешал бы 'locked' без хеша.
var ErrNoDesiredLock = errors.New("desired lock absent (lock_hash empty)")

// UpdateDeviceLockStatus подтверждает статус блокировки по отчёту агента, НЕ трогая
// hash/reason/mode — их выставляет lock-эндпоинт.
//
// Перевод в 'locked' разрешён ТОЛЬКО при непустом lock_hash. Иначе получался бы
// desired 'locked' при пустом lock_hash — команда, которую агент выполнить не может
// (validateBcryptHash отвергает пустой хеш как fail-safe против офлайн-неснимаемого
// лока), то есть устройство навсегда числится заблокированным в панели, оставаясь
// полностью рабочим. Условие стоит в самом UPDATE, а не отдельным SELECT'ом: между
// чтением и записью пролез бы конкурентный unlock.
//
// Ноль затронутых строк при lockStatus='locked' → ErrNoDesiredLock. Тот же ответ
// придёт на несуществующее устройство — вызывающий (gateway) резолвит deviceID по
// сертификату до вызова, так что различать эти случаи здесь незачем.
func (db *DB) UpdateDeviceLockStatus(ctx context.Context, deviceID, lockStatus string) error {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return scopeErr
	}
	defer finish(true)
	tag, err := db.Scoped(ctx).Exec(ctx,
		`UPDATE devices SET lock_status = $2
		 WHERE id = $1 AND ($2 <> 'locked' OR COALESCE(lock_hash, '') <> '')`, deviceID, lockStatus)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 && lockStatus == "locked" {
		return ErrNoDesiredLock
	}
	return nil
}

// CreateDecommissionTask ставит задачу полного самоудаления агента (вывод устройства
// из эксплуатации). task_type='decommission'; lock_*-поля берут DEFAULT (миграция 013 —
// NOT NULL DEFAULT), поэтому их не задаём. Агент выполняет teardown и подтверждает
// ОБЫЧНЫМ ReportTaskResult(SUCCESS) — по task_type gateway флипает устройство в
// 'decommissioned' (см. gateway.ReportTaskResult, MarkDeviceDecommissioned).
//
// Статус устройства здесь НЕ трогаем: он должен остаться прежним (обычно 'active'),
// пока задача не доставлена — иначе Connect отклонил бы устройство раньше, чем оно
// получит команду сноса. Флип делает gateway по подтверждению агента.
func (db *DB) CreateDecommissionTask(ctx context.Context, deviceID string) (*Task, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	if err := db.assertAgentSupports(ctx, deviceID, "decommission"); err != nil {
		return nil, err
	}
	var t Task
	err = db.Scoped(ctx).QueryRow(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status, task_type, tenant_id)
  SELECT $1, '', COALESCE(d.os, 'unknown'), 'high', 'pending', 'decommission', d.tenant_id
  FROM devices d WHERE d.id = $1
  RETURNING id, device_id, script_content, platform, priority, status, created_at, task_type, lock_hash, lock_reason, lock_unlock, lock_mode
 `, deviceID).
		Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.CreatedAt, &t.TaskType, &t.LockHash, &t.LockReason, &t.LockUnlock, &t.LockMode)
	return &t, err
}

// RebootMinDelaySeconds — минимальная отсрочка, которую примет агент. «Немедленно» в
// панели присылает именно её, а НЕ ноль: ноль на проводе означает «дефолт агента»
// (60 с), и посылать его как «сейчас» значило бы делать нулевое значение самым
// деструктивным вариантом.
const RebootMinDelaySeconds int32 = 10

// CreateRebootTask ставит задачу перезагрузки. task_type='reboot', priority='high':
// это control-plane, за очередью скриптов ждать не должен.
//
// Идемпотентность важнее, чем у остальных команд: агент ПЕРЕЖИВАЕТ перезагрузку, и
// если отчёт не доехал до ухода машины вниз, сервер передоставит ту же задачу уже
// после загрузки — по task_id агент её отбросит. А вот НОВЫЙ task_id для того же
// намерения = вторая перезагрузка, и устройство уходит в цикл. Поэтому повторный
// вызов при живой недоставленной заявке возвращает СУЩЕСТВУЮЩУЮ задачу (гонку двух
// операторов ловит частичный уникальный индекс из 037, а не проверка-до-вставки).
func (db *DB) CreateRebootTask(ctx context.Context, deviceID, reason string, delaySeconds int32) (*Task, error) {
	if delaySeconds < 0 {
		delaySeconds = 0 // 0 = дефолт агента; отрицательное значение бессмысленно
	}
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	if err := db.assertAgentSupports(ctx, deviceID, "reboot"); err != nil {
		return nil, err
	}
	const cols = `id, device_id, script_content, platform, priority, status, created_at, task_type,
	              lock_hash, lock_reason, lock_unlock, lock_mode, reboot_reason, reboot_delay_seconds`
	scan := func(row pgx.Row, t *Task) error {
		return row.Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status,
			&t.CreatedAt, &t.TaskType, &t.LockHash, &t.LockReason, &t.LockUnlock, &t.LockMode,
			&t.RebootReason, &t.RebootDelaySeconds)
	}

	var t Task
	err = scan(db.Scoped(ctx).QueryRow(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status, task_type, reboot_reason, reboot_delay_seconds, tenant_id)
  SELECT $1, '', COALESCE(d.os, 'unknown'), 'high', 'pending', 'reboot', $2, $3, d.tenant_id
  FROM devices d WHERE d.id = $1
  ON CONFLICT DO NOTHING
  RETURNING `+cols, deviceID, reason, delaySeconds), &t)
	if err == nil {
		return &t, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	// ON CONFLICT DO NOTHING → строк не вернулось: недоставленная заявка уже есть.
	// Отдаём её, чтобы вызывающий не создал вторую перезагрузку под новым id.
	err = scan(db.Scoped(ctx).QueryRow(ctx, `
  SELECT `+cols+` FROM tasks
  WHERE device_id = $1 AND task_type = 'reboot' AND status = 'pending'`, deviceID), &t)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ErrSoftwareNotInInventory — цели нет в снимке инвентаря устройства.
//
// Отказ, а не «поставим задачу, агент разберётся»: селектор собирается ИЗ снимка, и
// если снимка нет, серверу нечего послать — уйдёт команда с пустыми полями, под
// которую на машине подойдёт что угодно с похожим именем.
var ErrSoftwareNotInInventory = errors.New("software not found in device inventory")

// ErrSoftwareNotRemovable — у записи в инвентаре нет метода снятия.
//
// Это НЕ «попробуем и посмотрим»: метод определяет коллектор агента, и пустой он там,
// где снять нечем в принципе — per-user установки под Windows (служба работает от
// LocalSystem и в чужой профиль не ходит), защищённое SIP на macOS. Ставить такую
// задачу значит гарантированно получить NOT_REMOVABLE и занять оператора ожиданием.
var ErrSoftwareNotRemovable = errors.New("software has no uninstall method")

// CreateUninstallTask ставит задачу удаления ПО. Селектор берётся ИЗ ИНВЕНТАРЯ этого
// устройства, а не из тела запроса: клиент передаёт только имя и машинный ключ, всё
// остальное сервер достаёт сам. Иначе оператор (или сервисный токен) мог бы прислать
// произвольный селектор с любым методом, и сверка метода на агенте, ради которой она
// заведена, проверяла бы присланное против присланного.
//
// priority='high': control-plane, за очередью скриптов ждать не должен.
//
// Идемпотентность как у перезагрузки: повторный вызов при живой недоставленной заявке
// возвращает СУЩЕСТВУЮЩУЮ задачу. Новый task_id для того же намерения агент считает
// новой командой и снёс бы цель дважды — на втором заходе это уже ALREADY_ABSENT, но
// оператор увидел бы две записи об одном действии.
func (db *DB) CreateUninstallTask(ctx context.Context, deviceID, softwareName, uninstallID, reason string) (*Task, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	if err := db.assertAgentSupports(ctx, deviceID, "uninstall"); err != nil {
		return nil, err
	}
	const cols = `id, device_id, script_content, platform, priority, status, created_at, task_type,
	              lock_hash, lock_reason, lock_unlock, lock_mode, reboot_reason, reboot_delay_seconds,
	              uninstall_software_name, uninstall_version, uninstall_uninstall_id,
	              uninstall_install_location, uninstall_method, uninstall_scope, uninstall_reason,
	              uninstall_outcome`
	scan := func(row pgx.Row, t *Task) error {
		return row.Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status,
			&t.CreatedAt, &t.TaskType, &t.LockHash, &t.LockReason, &t.LockUnlock, &t.LockMode,
			&t.RebootReason, &t.RebootDelaySeconds,
			&t.Uninstall.SoftwareName, &t.Uninstall.Version, &t.Uninstall.UninstallID,
			&t.Uninstall.InstallLocation, &t.Uninstall.Method, &t.Uninstall.Scope, &t.Uninstall.Reason,
			&t.UninstallOutcome)
	}

	// Статус проверяем ПЕРВЫМ и отдельно от поиска цели: инвентарь заблокированной или
	// списанной машины никуда не делся, и без этой проверки снос уехал бы на устройство,
	// которое мы намеренно отрезали. Тот же гейт, что у скрипт-канала.
	var active bool
	if err := db.Scoped(ctx).QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM devices WHERE id::text = $1 AND status = 'active')`, deviceID).Scan(&active); err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrDeviceNotActive
	}

	// Цель ищем по имени И машинному ключу: одноимённых записей у разных вендоров и
	// разных версий одного продукта в инвентаре может быть несколько. Пустой
	// uninstall_id (macOS) сверяется как есть — там ключом служит install_location.
	var tgt UninstallTarget
	err = db.Scoped(ctx).QueryRow(ctx, `
  SELECT software_name, COALESCE(version, ''), uninstall_id, install_location, uninstall_method, scope
  FROM device_software
  WHERE device_id::text = $1 AND software_name = $2 AND uninstall_id = $3
  LIMIT 1`, deviceID, softwareName, uninstallID).
		Scan(&tgt.SoftwareName, &tgt.Version, &tgt.UninstallID, &tgt.InstallLocation, &tgt.Method, &tgt.Scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSoftwareNotInInventory
	}
	if err != nil {
		return nil, err
	}
	if tgt.Method == "" {
		return nil, ErrSoftwareNotRemovable
	}

	var t Task
	err = scan(db.Scoped(ctx).QueryRow(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status, task_type,
                     uninstall_software_name, uninstall_version, uninstall_uninstall_id,
                     uninstall_install_location, uninstall_method, uninstall_scope, uninstall_reason, tenant_id)
  SELECT $1::uuid, '', COALESCE(d.os, 'unknown'), 'high', 'pending', 'uninstall',
          $2, $3, $4, $5, $6, $7, $8, d.tenant_id
  FROM devices d WHERE d.id = $1::uuid
  ON CONFLICT DO NOTHING
  RETURNING `+cols,
		deviceID, tgt.SoftwareName, tgt.Version, tgt.UninstallID,
		tgt.InstallLocation, tgt.Method, tgt.Scope, reason), &t)
	if err == nil {
		return &t, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	// ON CONFLICT DO NOTHING → строк нет: недоставленная заявка на эту цель уже есть.
	err = scan(db.Scoped(ctx).QueryRow(ctx, `
  SELECT `+cols+` FROM tasks
  WHERE device_id::text = $1 AND task_type = 'uninstall' AND status = 'pending'
    AND uninstall_software_name = $2 AND uninstall_uninstall_id = $3`,
		deviceID, tgt.SoftwareName, tgt.UninstallID), &t)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// SetTaskUninstallOutcome записывает машиночитаемый исход удаления. Скоуп по устройству —
// как у CompleteTask: иначе устройство A по чужому task_id проставило бы исход задаче B.
// Незнакомое значение сохраняется как есть: сервер, не понимающий новый исход агента,
// обязан его показать, а не отвергнуть.
func (db *DB) SetTaskUninstallOutcome(ctx context.Context, taskID, deviceID, outcome string) error {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return scopeErr
	}
	defer finish(true)
	_, err := db.Scoped(ctx).Exec(ctx, `
  UPDATE tasks SET uninstall_outcome = $3
  WHERE id::text = $1 AND device_id::text = $2 AND task_type = 'uninstall'`, taskID, deviceID, outcome)
	return err
}

// FanOutRebootToGroup ставит перезагрузку всем active-устройствам группы одной
// вставкой. Платформенного фильтра нет (в отличие от скриптов): перезагрузка
// реализована на всех трёх ОС. Устройства с уже живой недоставленной заявкой
// пропускаются (ON CONFLICT DO NOTHING) — повторный клик по группе не создаёт
// вторую перезагрузку тем, кто ещё не получил первую.
func (db *DB) FanOutRebootToGroup(ctx context.Context, groupID, reason string, delaySeconds int32) ([]Task, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return nil, scopeErr
	}
	defer finish(true)
	if delaySeconds < 0 {
		delaySeconds = 0
	}
	rows, err := db.Scoped(ctx).Query(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status, task_type, reboot_reason, reboot_delay_seconds)
  SELECT m.device_id, '', COALESCE(d.os, 'unknown'), 'high', 'pending', 'reboot', $2, $3
  FROM device_group_members m
  JOIN devices d ON d.id = m.device_id
  WHERE m.group_id = $1
    AND d.status = 'active'
  ON CONFLICT DO NOTHING
  RETURNING id, device_id, task_type, reboot_reason, reboot_delay_seconds
 `, groupID, reason, delaySeconds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.TaskType, &t.RebootReason, &t.RebootDelaySeconds); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// CountActiveDevicesInGroup — сколько машин реально получит групповую команду.
// Нужен ДО веера: массовая перезагрузка требует потолка и подтверждения по
// фактическому числу, а не по размеру группы вместе со списанными.
func (db *DB) CountActiveDevicesInGroup(ctx context.Context, groupID string) (int, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return 0, scopeErr
	}
	defer finish(true)
	var n int
	err := db.Scoped(ctx).QueryRow(ctx, `
  SELECT COUNT(*) FROM device_group_members m
  JOIN devices d ON d.id = m.device_id
  WHERE m.group_id = $1 AND d.status = 'active'`, groupID).Scan(&n)
	return n, err
}

// MarkDeviceDecommissioned переводит устройство в терминальный статус 'decommissioned'.
// Вызывается ТОЛЬКО после подтверждения агентом приёма decommission-задачи
// (ReportTaskResult SUCCESS) — до этого статус держим прежним, чтобы Connect успел
// доставить команду. Терминальный: gateway рвёт Connect/heartbeat и режет все agent-RPC
// (как 'blocked'), а UpsertDeviceHeartbeat не воскрешает (CASE поднимает только
// enrolled/pending) — списанная машина не оживает своим же прощальным heartbeat'ом.
// Безусловный UPDATE: из любого статуса (active/blocked) → decommissioned терминален.
func (db *DB) MarkDeviceDecommissioned(ctx context.Context, deviceID string) error {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return scopeErr
	}
	defer finish(true)
	_, err := db.Scoped(ctx).Exec(ctx,
		`UPDATE devices SET status = 'decommissioned' WHERE id = $1`, deviceID)
	return err
}

// GetDeviceStatusByID — статус устройства по его id (для guard'а админ-ручек).
// "" (а не ошибка) при отсутствии строки: вызывающий сам решает 404.
func (db *DB) GetDeviceStatusByID(ctx context.Context, tenantID, id string) (string, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return "", err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return "", err
		}
		defer finish(true)
	}
	var s string
	err = db.Scoped(ctx).QueryRow(ctx, `SELECT status FROM devices WHERE id = $1 AND tenant_id = $2`, id, tenantID).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return s, err
}

func (db *DB) GetDeviceLockStatus(ctx context.Context, deviceID string) (string, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return "", err
	}
	defer finish(true)

	var s string
	err = db.Scoped(ctx).QueryRow(ctx, `SELECT lock_status FROM devices WHERE id = $1`, deviceID).Scan(&s)
	return s, err
}

// SetDeviceLockState записывает ЖЕЛАЕМОЕ состояние блокировки (авторитетное намерение
// админа) — статус, bcrypt-хеш пароля, причину и режим. Вызывается эндпоинтами
// lock/unlock. Это источник правды для реконсиляции FetchLockStatus: агент поллит и
// сводит к нему локальный lock.json (переживает потерю unlock-ack и ребут — push-канал
// их терял). При unlock hash/reason очищаются, режим сбрасывается в overlay (fail-safe:
// снятый лок НИКОГДА не остаётся в filevault-намерении).
//
// lockRequestID — идентификатор ЭТОГО лока (id lock-задачи; сервер кладёт его же в
// LockCommand.RequestId). По нему ветка UNLOCKED отличает отчёт о снятии ТЕКУЩЕГО
// лока от устаревшего, доехавшего из durable-outbox после выдачи нового (см.
// миграцию 032). При снятии передаётся пустая строка вместе с hash/reason.
func (db *DB) SetDeviceLockState(ctx context.Context, tenantID, deviceID, lockStatus, lockHash, lockReason, lockMode, lockRequestID string) error {
	if lockMode == "" {
		lockMode = LockModeOverlay
	}
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	defer finish(true)
	_, err = db.Scoped(ctx).Exec(ctx,
		`UPDATE devices SET lock_status = $2, lock_hash = $3, lock_reason = $4, lock_mode = $5, lock_request_id = $6 WHERE id = $1`,
		deviceID, lockStatus, lockHash, lockReason, lockMode, lockRequestID)
	return err
}

// SetDeviceLockActualState записывает REPORTED состояние лока (что агент фактически
// сделал), НЕ трогая desired (lock_status/hash/reason). Колонка заведена в 022 ровно
// затем, чтобы filevault half-state (FILEVAULT_REVOKED: токен снят, ребут ещё не
// сделан) не портил desired — иначе реконсайлер отменил бы/повторил бы деструктив
// (класс полевого re-lock-бага).
func (db *DB) SetDeviceLockActualState(ctx context.Context, deviceID, state string) error {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return scopeErr
	}
	defer finish(true)
	_, err := db.Scoped(ctx).Exec(ctx,
		`UPDATE devices SET lock_actual_state = $2, lock_actual_at = now() WHERE id = $1`,
		deviceID, state)
	return err
}

// LockActualStateStarted — состояние, означающее НАЧАВШИЙСЯ деструктив: токен снят
// у части владельцев тома, машина полу-ревокнута и требует ручного разбора IT.
const LockActualStateStarted = "filevault_revoke_failed"

// SetDeviceLockActualStateNoDowngrade — как SetDeviceLockActualState, но НЕ затирает
// уже выставленный filevault_revoke_failed. Возвращает false, если запись подавлена.
//
// 🔴 Зачем. Выдача вооружения ОДНОРАЗОВАЯ (escrow.Vault.Take), поэтому после
// частичного ревока следующий тик реконсиляции ГАРАНТИРОВАННО получит «не вооружено»
// и пришлёт pre-mutation ABORT (NOT_ARMED либо SECRET_MISMATCH). Без этой защиты такой
// отчёт понизил бы actual_state, и полу-ревокнутая машина показалась бы в панели просто
// невооружённой — теряется ЕДИНСТВЕННОЕ состояние, означающее начавшийся деструктив.
//
// Агент глушит это своим маркером (Chain.partialReportedFor), но маркер in-memory:
// рестарт агента его теряет, и защита обязана быть durable — то есть здесь.
//
// Условие в SQL, а не чтением-и-сравнением в Go: два отчёта, доехавших одновременно,
// иначе разошлись бы на гонке read-modify-write.
//
// Липкость намеренная: filevault_revoke_failed снимается только состоянием, которое
// означает доведённый деструктив (FILEVAULT_REVOKED, LOCKED) — они идут обычным
// сеттером. Если под тем же устройством выдали НОВЫЙ лок, полу-ревокнутость от
// предыдущего никуда не делась и остаётся более важной правдой.
func (db *DB) SetDeviceLockActualStateNoDowngrade(ctx context.Context, deviceID, state string) (bool, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return false, scopeErr
	}
	defer finish(true)
	tag, err := db.Scoped(ctx).Exec(ctx,
		`UPDATE devices SET lock_actual_state = $2, lock_actual_at = now()
		 WHERE id = $1 AND COALESCE(lock_actual_state, '') <> $3`,
		deviceID, state, LockActualStateStarted)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GetDesiredLockState возвращает желаемое состояние блокировки устройства для отдачи
// агенту (FetchLockStatus). Пустой lock_status трактуется вызывающим как "unlocked".
// lockMode пустой/NULL → overlay (fail-safe). lockRequestID пустой = лок выдан до
// миграции 032, привязать отчёт о снятии к конкретному локу нельзя.
func (db *DB) GetDesiredLockState(ctx context.Context, deviceID string) (lockStatus, lockHash, lockReason, lockMode, lockRequestID string, err error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return "", "", "", "", "", err
	}
	defer finish(true)

	err = db.Scoped(ctx).QueryRow(ctx,
		`SELECT COALESCE(lock_status,''), COALESCE(lock_hash,''), COALESCE(lock_reason,''), COALESCE(NULLIF(lock_mode,''),'overlay'), COALESCE(lock_request_id,'') FROM devices WHERE id = $1`,
		deviceID).Scan(&lockStatus, &lockHash, &lockReason, &lockMode, &lockRequestID)
	return lockStatus, lockHash, lockReason, lockMode, lockRequestID, err
}

// FileVault recovery-escrow (StoreRecoveryKeyEscrow + ErrEscrowConflict) вынесено
// в enterprise-оверлей (internal/server/escrow, //go:build enterprise) — open-core
// его не содержит. Enterprise делает свой INSERT в recovery_key_escrow через DB.Pool().

func (db *DB) GetTask(ctx context.Context, taskID string) (*Task, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return nil, scopeErr
	}
	defer finish(true)
	var t Task
	err := db.Scoped(ctx).QueryRow(ctx, `
  SELECT id, device_id, script_content, platform, priority, status, output, error_log, created_at,
         task_type, lock_hash, lock_reason, lock_unlock, lock_mode, reboot_reason, reboot_delay_seconds,
         uninstall_software_name, uninstall_version, uninstall_uninstall_id,
         uninstall_install_location, uninstall_method, uninstall_scope, uninstall_reason,
         uninstall_outcome
FROM tasks WHERE id = $1
 `, taskID).Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.Output, &t.ErrorLog, &t.CreatedAt,
		&t.TaskType, &t.LockHash, &t.LockReason, &t.LockUnlock, &t.LockMode, &t.RebootReason, &t.RebootDelaySeconds,
		&t.Uninstall.SoftwareName, &t.Uninstall.Version, &t.Uninstall.UninstallID,
		&t.Uninstall.InstallLocation, &t.Uninstall.Method, &t.Uninstall.Scope, &t.Uninstall.Reason,
		&t.UninstallOutcome)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// PendingTaskRef — минимум для повторной постановки задачи в очередь доставки.
type PendingTaskRef struct {
	TaskID   string
	DeviceCN string
}

// ListPendingTasksWithDeviceCN отдаёт все задачи в статусе pending вместе с CN
// сертификата их устройства. Нужен реконсайлеру доставки: единственные точки
// ре-энкью — создание задачи и gateway.Connect, и любая потерянная постановка
// (дедуп asynq по TaskID, перезапуск redis, отказ воркера) иначе оставляла бы задачу
// в pending до следующего реконнекта устройства.
func (db *DB) ListPendingTasksWithDeviceCN(ctx context.Context, limit int) ([]PendingTaskRef, error) {
	if limit <= 0 {
		limit = 1000
	}
	tenants, err := db.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	var refs []PendingTaskRef
	for _, tenant := range tenants {
		if len(refs) >= limit {
			break
		}
		tctx, finish, err := db.BindTenant(ctx, tenant.ID)
		if err != nil {
			return nil, err
		}
		remaining := limit - len(refs)
		rows, err := db.Scoped(tctx).Query(tctx, `
		SELECT t.id, d.cert_cn
		FROM tasks t
		JOIN devices d ON d.id = t.device_id
		WHERE t.status = 'pending' AND COALESCE(d.cert_cn, '') <> ''
		ORDER BY t.created_at
		LIMIT $1
	`, remaining)
		if err != nil {
			finish(false)
			return nil, err
		}
		for rows.Next() {
			var ref PendingTaskRef
			if err := rows.Scan(&ref.TaskID, &ref.DeviceCN); err != nil {
				rows.Close()
				finish(false)
				return nil, err
			}
			refs = append(refs, ref)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			finish(false)
			return nil, err
		}
		rows.Close()
		finish(true)
	}
	return refs, nil
}

func (db *DB) GetPendingTasks(ctx context.Context, deviceID string) ([]Task, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	tx, owned, err := db.beginScoped(ctx)
	if err != nil {
		return nil, err
	}
	if owned {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	rows, err := tx.Query(ctx, `
		SELECT id, device_id, script_content, platform, priority, status, created_at,
		       task_type, lock_hash, lock_reason, lock_unlock, lock_mode
		FROM tasks
		WHERE device_id = $1 AND status = 'pending'
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.CreatedAt,
			&t.TaskType, &t.LockHash, &t.LockReason, &t.LockUnlock, &t.LockMode); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if owned {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
	}
	return tasks, nil
}

type PolicyRule struct {
	SoftwareName string
	RuleType     string
}

type PolicyResult struct {
	Rules   []PolicyRule
	Version int64
}

// policySetVersion — отпечаток эффективного набора политик/правил, который агент сравнивает
// на равенство (Unchanged). MAX(updated_at) для этого НЕ годится: снятие привязки, выключение
// toggle, удаление НЕ-новейшего правила и добавление устройства в группу со старыми правилами
// максимум не двигают — агент навсегда застревал на устаревшем наборе. Хеш зависит от состава,
// поэтому ловит любое изменение. Пустой набор даёт FNV-offset (не 0), чтобы Unchanged работал
// и для «правил нет»: gateway трактует 0 как «версии нет».
//
// Элементы и поля внутри них разделяются ДЛИНОЙ, а не байтом-разделителем: имя ПО и текст
// скрипта приходят от пользователя, и байт-разделитель в них размыл бы границы — два разных
// набора дали бы одинаковый хеш, то есть ровно ту болезнь, ради которой хеш и вводился.
func policySetVersion(items []string) int64 {
	sort.Strings(items)
	h := fnv.New64a()
	var lenBuf [8]byte
	for _, s := range items {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write([]byte(s))
	}
	return int64(h.Sum64())
}

// policySetItem склеивает поля одного элемента набора так, что границы полей однозначны
// при любом содержимом (length-prefix). См. policySetVersion.
func policySetItem(fields ...string) string {
	var b strings.Builder
	var lenBuf [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(f)))
		b.Write(lenBuf[:])
		b.WriteString(f)
	}
	return b.String()
}

func (db *DB) FetchPolicyRules(ctx context.Context, fingerprint string) (*PolicyResult, error) {
	id, tenantID, _, err := db.GetDeviceTenantByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("lookup device by fingerprint: %w", err)
	}
	var deviceID *string
	var deviceOS string
	scopeTenant := tenancy.DefaultTenantID
	if id != "" {
		scopeTenant = tenantID
		deviceID = &id
	}
	ctx, finish, err := db.BindTenant(ctx, scopeTenant)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	if deviceID != nil {
		if err := db.Scoped(ctx).QueryRow(ctx,
			`SELECT COALESCE(os, '') FROM devices WHERE id = $1`, id,
		).Scan(&deviceOS); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("lookup device os: %w", err)
			}
			deviceID = nil
		}
	}

	// Резолвинг scope: глобальные (device_id IS NULL AND group_id IS NULL) ∪
	// device-оверрайды ∪ правила групп, в которых состоит устройство (#2).
	// Когда устройство не найдено (deviceID == nil) — только глобальные, как раньше.
	query := `
		SELECT software_name, rule_type, platforms
		FROM software_policy_rules
		WHERE device_id IS NULL AND group_id IS NULL`
	args := []any{}

	if deviceID != nil {
		query = `
			SELECT software_name, rule_type, platforms
			FROM software_policy_rules
			WHERE (device_id IS NULL AND group_id IS NULL)                       -- глобальные
			   OR device_id = $1                                                 -- устройство
			   OR group_id IN (SELECT group_id FROM device_group_members          -- группы устройства
			                   WHERE device_id = $1)`
		args = append(args, *deviceID)
	}

	rows, err := db.Scoped(ctx).Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Платформенный фильтр применяем ТОЛЬКО когда ОС устройства известна: при пустой/
	// unknown ОС не фильтруем (fail-safe — forbidden-правила не должны молча выпадать).
	devicePlatform := normalizePlatform(deviceOS)
	osKnown := deviceOS != "" && !strings.EqualFold(deviceOS, "unknown")

	var result PolicyResult
	for rows.Next() {
		var name, ruleType string
		var platforms []string
		if err := rows.Scan(&name, &ruleType, &platforms); err != nil {
			return nil, err
		}
		if osKnown && !platformMatches(platforms, devicePlatform) {
			continue
		}
		result.Rules = append(result.Rules, PolicyRule{SoftwareName: name, RuleType: ruleType})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Версия считается по НАБОРУ, который реально уедет агенту (после платформенного
	// фильтра): иначе смена ОС-фильтра не долетела бы до устройства.
	fingerprints := make([]string, 0, len(result.Rules))
	for _, r := range result.Rules {
		fingerprints = append(fingerprints, policySetItem(r.SoftwareName, r.RuleType))
	}
	result.Version = policySetVersion(fingerprints)
	return &result, nil
}

func (db *DB) GetDeviceStatusByFingerprint(ctx context.Context, fingerprint string) (string, error) {
	_, _, status, err := db.GetDeviceTenantByFingerprint(ctx, fingerprint)
	if err != nil {
		return "", err
	}
	return status, nil
}

// IsFingerprintRevoked — отозван ли серт (устройство удалили из инвентаря). Connect
// режет отозванный отпечаток в ветке неизвестного fingerprint, чтобы удалённое
// устройство не воскресало через ADR-1 регистрацию из cert CN. Реэнролл берёт новый
// серт → новый fingerprint → не отозван. См. миграцию 034 и DeleteDevice.
func (db *DB) IsFingerprintRevoked(ctx context.Context, fingerprint string) (bool, error) {
	var exists bool
	err := db.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM revoked_fingerprints WHERE fingerprint = $1)`, fingerprint,
	).Scan(&exists)
	return exists, err
}

func (db *DB) UpdateDeviceStatus(ctx context.Context, tenantID, deviceID, status string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx,
		`UPDATE devices SET status = $3 WHERE id = $1 AND tenant_id = $2`, deviceID, tenantID, status)
	return err
}

// ErrDeviceHasEscrow — у устройства есть заэскроенные recovery-ключи (022, ON DELETE
// RESTRICT) — удалять нельзя, иначе теряется доступ к восстановлению шифра. В open-core
// эта таблица не наполняется, так что путь недостижим на free; на enterprise = сигнал
// оператору сначала разобраться с эскроу. Отдаётся как 409, не 500.
var ErrDeviceHasEscrow = errors.New("device has recovery-key escrow records")

// DeleteDevice удаляет устройство. Все входящие FK каскадные (alerts/tasks/script_results/
// group_members/admin_access/software/events/enroll_tokens), КРОМЕ recovery_key_escrow
// (RESTRICT) → её наличие даёт ErrDeviceHasEscrow. found=false, если строки нет (→ 404).
// ⚠️ Живой агент воскресит устройство следующим heartbeat (upsert по cert-fingerprint) —
// удаление имеет смысл только для списанных/переустановленных машин.
func (db *DB) DeleteDevice(ctx context.Context, tenantID, id string) (found bool, err error) {
	tenantID, err = requireTenant(tenantID)
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
	q := db.Scoped(ctx)

	// Тумбстоун серта ДО удаления, в ОДНОЙ транзакции с ним. Серт на машине остаётся
	// валидным; без отзыва агент по нему переподключится и Connect заведёт устройство
	// заново (ADR-1 регистрация из cert CN не отличает новое от воскресшего). Транзакция
	// критична: если DELETE упрётся в escrow-констрейнт, отзыв откатится вместе с ним —
	// иначе отрезали бы живое устройство, которое так и не удалилось (см. миграцию 034).
	var fp string
	if err = q.QueryRow(ctx,
		`SELECT COALESCE(certificate_fingerprint, '') FROM devices WHERE id = $1 AND tenant_id = $2`, id, tenantID,
	).Scan(&fp); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil // устройства нет — нечего удалять (→ 404)
		}
		return false, err
	}
	if fp != "" {
		if _, err = q.Exec(ctx,
			`INSERT INTO revoked_fingerprints (fingerprint, device_id) VALUES ($1, $2)
			 ON CONFLICT (fingerprint) DO NOTHING`, fp, id); err != nil {
			return false, err
		}
	}

	tag, err := q.Exec(ctx, `DELETE FROM devices WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		var pgErr *pgconn.PgError
		// Только escrow-констрейнт (ON DELETE RESTRICT) значит «у устройства есть эскроу».
		// Раньше сюда маппился ЛЮБОЙ 23503 — и, например, чужой alert, приколотый через
		// admin_access_request_id, давал ложное «has escrow» на удалении невиновного
		// устройства. Прочие FK-нарушения — реальная аномалия, пусть всплывают как 500.
		if errors.As(err, &pgErr) && pgErr.Code == "23503" &&
			pgErr.ConstraintName == "recovery_key_escrow_device_id_fkey" {
			return false, ErrDeviceHasEscrow
		}
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// DetectUnreachableDevices создаёт alert 'agent_unreachable' для active/enrolled устройств,
// не выходивших на связь дольше thresholdMinutes. Два анти-дубля:
//  1. эпизодный: пропускает устройство, если по нему уже есть alert 'agent_unreachable'
//     НОВЕЕ его last_seen_at (один alert на эпизод — вернулось и снова пропало → новый).
//  2. cooldown (cooldownMinutes>0): пропускает, если по устройству уже был alert
//     'agent_unreachable' за последние cooldownMinutes. Гасит дребезг modern-standby, где
//     машина просыпается ~раз в час на минуту, двигает last_seen_at → каждый краткий сон
//     иначе выглядит новым эпизодом и плодит alert каждый час. Мёртвое устройство (last_seen
//     заморожен) и так даёт ровно один alert через клоз (1), так что cooldown его не трогает.
//
// cooldownMinutes<=0 отключает второй клоз.
func (db *DB) detectUnreachableDevicesForTenant(ctx context.Context, tenantID string, thresholdMinutes, cooldownMinutes int) (int64, error) {
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	defer finish(true)
	res, err := db.Scoped(ctx).Exec(ctx, `
		INSERT INTO alerts (device_id, alert_type, details, severity, tenant_id)
		SELECT d.id, 'agent_unreachable',
		       'Не выходит на связь с ' || to_char(d.last_seen_at, 'YYYY-MM-DD HH24:MI'),
		       $3::text,
		       d.tenant_id
		FROM devices d
		WHERE d.status IN ('active', 'enrolled')
		  AND d.last_seen_at IS NOT NULL
		  AND d.last_seen_at < now() - ($1 * interval '1 minute')
		  AND NOT EXISTS (
		      SELECT 1 FROM alerts a
		      WHERE a.device_id = d.id
		        AND a.alert_type = 'agent_unreachable'
		        AND a.created_at > d.last_seen_at
		  )
		  AND ($2 <= 0 OR NOT EXISTS (
		      SELECT 1 FROM alerts a
		      WHERE a.device_id = d.id
		        AND a.alert_type = 'agent_unreachable'
		        AND a.created_at > now() - ($2 * interval '1 minute')
		  ))
	`, thresholdMinutes, cooldownMinutes, string(alerting.DefaultFor("agent_unreachable")))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// DetectUnreachableDevices — кросс-тенантный обход (ListTenants + BindTenant); суммирует созданные alerts.
func (db *DB) DetectUnreachableDevices(ctx context.Context, thresholdMinutes, cooldownMinutes int) (int64, error) {
	if thresholdMinutes <= 0 {
		return 0, nil
	}
	tenants, err := db.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, tenant := range tenants {
		n, err := db.detectUnreachableDevicesForTenant(ctx, tenant.ID, thresholdMinutes, cooldownMinutes)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// CreateAlert вставляет событие безопасности и сообщает, была ли строка РЕАЛЬНО
// создана: created=false → подавленный дубль (звонить в Telegram не нужно).
//
// Серверный дедуп (defense-in-depth к агентскому security_alerted.seen): пока по
// (device, type, details) висит НЕПРИНЯТЫЙ алерт, повтор того же события новую строку
// не создаёт. Без этого рестарт агента / потеря .seen / два агента на одном событии
// множили бы INSERT+телегу без предела (у CreateAlert исторически не было дедупа).
// Как только оператор принимает алерт, следующий репорт создаёт свежий — «проблема
// вернулась после разбора». Та же семантика, что у якоря дедупа agent_unreachable.
// ponytail: гонку двух ОДНОВРЕМЕННЫХ одинаковых INSERT-ов NOT EXISTS не закрывает
// (оба пройдут проверку) — для последовательного агентского outbox неактуально;
// строгую уникальность дал бы partial unique index, если понадобится.
func (db *DB) CreateAlert(ctx context.Context, deviceID, alertType, details, adminAccessRequestID string) (bool, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return false, err
	}
	defer finish(true)
	var adminReqID *string
	if adminAccessRequestID != "" {
		adminReqID = &adminAccessRequestID
	}
	// admin_access_request_id приходит из payload агента и НЕ проверен на владельца:
	// устройство A могло прислать заявку устройства B. Линкуем только заявку, реально
	// принадлежащую отправителю — иначе A закрепляет за собой FK на чужую заявку, и
	// последующий DELETE устройства B вечно падает 23503 (заявка B не удаляется каскадом),
	// а оператор получает ложное «device has escrow». Чужой/битый id молча становится
	// NULL: ack-контракт (accept-and-drop) цел, событие сохраняется без ложной привязки.
	// severity вычисляется ЗДЕСЬ, а не приходит параметром: три вызывающих в
	// gateway плюс будущие не должны иметь возможности её забыть или разойтись между
	// собой. Маршрутизация уведомлений на стороне вызывающего берёт то же значение
	// из той же чистой функции alerting.DefaultFor — расхождения быть не может.
	// Значение фиксируется в строке (см. 041): правка карты по умолчанию не должна
	// переписывать критичность уже разобранных инцидентов задним числом.
	severity := string(alerting.DefaultFor(alertType))
	alertTenantID, _ := TenantIDFrom(ctx)
	tag, err := db.Scoped(ctx).Exec(ctx, `
  INSERT INTO alerts (device_id, alert_type, details, admin_access_request_id, severity, tenant_id)
  SELECT $1::uuid, $2::text, $3::text,
    (SELECT r.id FROM admin_access_requests r WHERE r.id = $4::uuid AND r.device_id = $1::uuid),
    $5::text,
    COALESCE(NULLIF(current_setting('routineops.tenant_id', true), '')::uuid, $6::uuid)
  WHERE NOT EXISTS (
    SELECT 1 FROM alerts a
    WHERE a.device_id = $1::uuid AND a.alert_type = $2::text
      AND a.details = $3::text AND a.acknowledged_at IS NULL
  )
 `, deviceID, alertType, details, adminReqID, severity, alertTenantID)
	// 23503 = устройство/заявка удалены (гонка с удалением или retention-чисткой)
	// до доставки события — тот же терминальный класс, что и в SaveScriptResult.
	if err != nil {
		return false, wrapFKViolation(err)
	}
	return tag.RowsAffected() > 0, nil
}

type Alert struct {
	ID             string     `json:"id"`
	DeviceID       string     `json:"device_id"`
	DeviceHostname string     `json:"device_hostname"`
	AlertType      string     `json:"alert_type"`
	Severity       string     `json:"severity"`
	Details        string     `json:"details"`
	CreatedAt      time.Time  `json:"created_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
}

// severityRank строит SQL-выражение ранга критичности над произвольным выражением
// (столбцом или параметром запроса).
//
// Ранг выражением, а не сортировкой по тексту: severity хранится как TEXT под
// CHECK, и ORDER BY по нему дал бы алфавит ('critical' < 'high' < 'low' <
// 'medium'), то есть low оказался бы важнее medium. Числа держим только здесь и в
// alerting.Rank — наружу шкала не выставляется, чтобы её можно было расширить
// посередине. ELSE 0: неизвестное значение уезжает в конец, а не в начало.
func severityRank(expr string) string {
	return `CASE ` + expr + `
    WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1
    ELSE 0 END`
}

func (db *DB) ListAlerts(ctx context.Context, tenantID, deviceID string, limit int) ([]Alert, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	query := `
  SELECT a.id, a.device_id, COALESCE(d.hostname, ''), a.alert_type, a.severity, a.details, a.created_at, a.acknowledged_at
  FROM alerts a
  LEFT JOIN devices d ON d.id = a.device_id`
	// Непринятые ПЕРВЫМИ: фронт тянет один список и фильтрует «новые» клиентски, поэтому
	// при простой сортировке по дате непринятый алерт старше LIMIT-й строки молча выпадал
	// из выборки (и из счётчика «новых»), вытесненный более свежими ПРИНЯТЫМИ. Сортировка
	// (acknowledged_at IS NULL) DESC держит все непринятые в голове списка.
	//
	// Критичность — второй ключ, ПОСЛЕ признака принятости и ДО даты (миграция 043).
	// Именно в таком порядке, а не «критичность первой»: принятый critical уже
	// разобран человеком, и выталкивать им непринятые из окна LIMIT означало бы
	// вернуть ровно тот баг, ради которого появилась сортировка по acknowledged_at.
	order := ` ORDER BY (a.acknowledged_at IS NULL) DESC, ` + severityRank("a.severity") + ` DESC, a.created_at DESC`
	args := []any{tenantID}
	if deviceID != "" {
		query += ` WHERE a.tenant_id = $1 AND a.device_id = $2` + order + ` LIMIT $3`
		args = append(args, deviceID, limit)
	} else {
		query += ` WHERE a.tenant_id = $1` + order + ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := db.Scoped(ctx).Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.DeviceHostname, &a.AlertType, &a.Severity, &a.Details, &a.CreatedAt, &a.AcknowledgedAt); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// TakeEscalations забирает непринятые алерты, по которым пора напомнить, и СРАЗУ
// помечает их отправленными (escalated_at = now()).
//
// Захват и пометка — один UPDATE ... RETURNING, а не SELECT с последующим UPDATE.
// Это не оптимизация: между SELECT и UPDATE второй узел (или второй тик после
// зависшей отправки) выбрал бы те же строки и отправил напоминание повторно.
// UPDATE атомарен относительно строк, которые он трогает, поэтому каждый алерт
// достаётся ровно одному вызывающему. Цена — напоминание считается отправленным
// до того, как Telegram его подтвердил: при сбое доставки следующее придёт через
// repeatMinutes, а не немедленно. Это верный компромисс — обратный порядок
// (отправить, потом пометить) при падении процесса между шагами превращается в
// бесконечную рассылку одного и того же алерта.
//
// afterMinutes<=0 выключает эскалацию. repeatMinutes<=0 = напомнить ровно один раз.
func (db *DB) TakeEscalations(ctx context.Context, minSeverity string, afterMinutes, repeatMinutes int) ([]Alert, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return nil, scopeErr
	}
	defer finish(true)
	if afterMinutes <= 0 {
		return nil, nil
	}
	if _, ok := alerting.Parse(minSeverity); !ok {
		// Опечатка в ALERT_ESCALATE_MIN_SEVERITY не должна тихо превращаться в
		// «эскалировать всё подряд»: минимальный ранг у мусора равен 0, и предикат
		// ниже пропустил бы вообще каждый алерт, включая agent_unreachable.
		return nil, fmt.Errorf("escalation: unknown min severity %q", minSeverity)
	}
	rows, err := db.Scoped(ctx).Query(ctx, `
		UPDATE alerts a SET escalated_at = now()
		WHERE a.id IN (
		  SELECT a2.id FROM alerts a2
		  WHERE a2.acknowledged_at IS NULL
		    AND `+severityRank("a2.severity")+` >= `+severityRank("$1::text")+`
		    AND a2.created_at < now() - ($2 * interval '1 minute')
		    AND (a2.escalated_at IS NULL
		         OR ($3 > 0 AND a2.escalated_at < now() - ($3 * interval '1 minute')))
		  FOR UPDATE SKIP LOCKED
		)
		RETURNING a.id, a.device_id, '', a.alert_type, a.severity, a.details, a.created_at, a.acknowledged_at
	`, minSeverity, afterMinutes, repeatMinutes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var al Alert
		if err := rows.Scan(&al.ID, &al.DeviceID, &al.DeviceHostname, &al.AlertType,
			&al.Severity, &al.Details, &al.CreatedAt, &al.AcknowledgedAt); err != nil {
			return nil, err
		}
		out = append(out, al)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Hostname отдельным запросом: RETURNING не умеет JOIN, а напоминание без имени
	// машины бесполезно — оператор не поймёт, куда идти.
	for i := range out {
		var hostname string
		if err := db.Scoped(ctx).QueryRow(ctx,
			`SELECT COALESCE(hostname, '') FROM devices WHERE id = $1`, out[i].DeviceID).Scan(&hostname); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			// Устройство удалено между созданием алерта и напоминанием — не повод
			// глушить напоминание целиком: сам факт непринятого инцидента остаётся.
			continue
		}
		out[i].DeviceHostname = hostname
	}
	return out, nil
}

func (db *DB) AcknowledgeAlert(ctx context.Context, tenantID, alertID string) error {
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	defer finish(true)

	tag, err := db.Scoped(ctx).Exec(ctx, `
    UPDATE alerts SET acknowledged_at = now()
    WHERE id = $1 AND acknowledged_at IS NULL`, alertID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("alert not found or already acknowledged")
	}
	return nil
}

type PolicyRuleRow struct {
	ID           string    `json:"id"`
	SoftwareName string    `json:"software_name"`
	RuleType     string    `json:"rule_type"`
	DeviceID     *string   `json:"device_id"`
	GroupID      *string   `json:"group_id"`
	Platforms    []string  `json:"platforms"` // nil/пусто = все платформы
	UpdatedAt    time.Time `json:"updated_at"`
}

func (db *DB) ListPolicyRules(ctx context.Context, tenantID string) ([]PolicyRuleRow, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	rows, err := db.Scoped(ctx).Query(ctx, `
  SELECT id, software_name, rule_type, device_id, group_id, platforms, updated_at
  FROM software_policy_rules WHERE tenant_id = $1 ORDER BY updated_at DESC
 `, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PolicyRuleRow
	for rows.Next() {
		var r PolicyRuleRow
		if err := rows.Scan(&r.ID, &r.SoftwareName, &r.RuleType, &r.DeviceID, &r.GroupID, &r.Platforms, &r.UpdatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (db *DB) CreatePolicyRule(ctx context.Context, tenantID, softwareName, ruleType string, deviceID *string, platforms []string) (*PolicyRuleRow, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var r PolicyRuleRow
	var plat interface{} // nil → NULL (правило на всех платформах)
	if len(platforms) > 0 {
		plat = platforms
	}
	err = db.Scoped(ctx).QueryRow(ctx, `
  INSERT INTO software_policy_rules (tenant_id, software_name, rule_type, device_id, platforms)
  VALUES ($1, $2, $3, $4, $5)
  RETURNING id, software_name, rule_type, device_id, group_id, platforms, updated_at
 `, tenantID, softwareName, ruleType, deviceID, plat).
		Scan(&r.ID, &r.SoftwareName, &r.RuleType, &r.DeviceID, &r.GroupID, &r.Platforms, &r.UpdatedAt)
	return &r, err
}

// normalizePlatform приводит agent-reported ОС (free-form: "macOS 26", "Windows 11",
// "Ubuntu") к одному из {macOS, Windows, Linux} — тем же значениям, что шлёт UI.
func normalizePlatform(os string) string {
	l := strings.ToLower(os)
	switch {
	case strings.Contains(l, "win"):
		return "Windows"
	case strings.Contains(l, "mac"), strings.Contains(l, "darwin"):
		return "macOS"
	default:
		return "Linux"
	}
}

// platformMatches — применимо ли правило с данным platforms-фильтром к платформе p.
// Пустой фильтр = все платформы.
func platformMatches(platforms []string, p string) bool {
	if len(platforms) == 0 {
		return true
	}
	for _, x := range platforms {
		if x == p {
			return true
		}
	}
	return false
}

func (db *DB) DeletePolicyRule(ctx context.Context, tenantID, id string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx, `DELETE FROM software_policy_rules WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// SoftwarePolicyCompliance — сколько устройств проходит софт-правило, а сколько нет.
// Checked=false у правил-разрешений: агент проверяет ТОЛЬКО forbidden-список
// (см. internal/agent/policy/sync.go — allowed-правила в кэш не пишутся), поэтому
// pass/fail для них не считаются, и врать в UI «все прошли» нельзя.
type SoftwarePolicyCompliance struct {
	RuleID  string `json:"rule_id"`
	InScope int    `json:"in_scope"` // устройств, на которые правило распространяется
	Pass    int    `json:"pass"`
	Fail    int    `json:"fail"`
	Checked bool   `json:"checked"`
}

// ListSoftwarePolicyCompliance считает Pass/Fail по ИНВЕНТАРЮ (device_software), а не
// по алертам: алерт рождается на ЗАПУСК запрещённого процесса и живёт до ack'а, тогда
// как вопрос «сколько машин нарушает правило прямо сейчас» — про установленное ПО.
//
// Область действия правила повторяет FetchPolicyRules: глобальное (device_id и group_id
// пусты) ∪ device-оверрайд ∪ правила групп устройства, затем платформенный фильтр с тем
// же fail-safe (ОС неизвестна → не фильтруем). CASE ниже — SQL-двойник normalizePlatform.
//
// Сопоставление имени — регистронезависимая подстрока, как findForbidden у агента.
// Пустое software_name отсекается явно: strpos(x, ”) = 1, иначе «нарушают все».
func (db *DB) ListSoftwarePolicyCompliance(ctx context.Context, tenantID string) ([]SoftwarePolicyCompliance, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	// Явный tenant_id в JOIN: под суперюзером (локальные/прод-тесты на роли mdm)
	// FORCE RLS не режет строки, а ListEnrolledDevices уже фильтрует по tenant —
	// без этого in_scope раздувается чужими тенантами (см. TestListSoftwarePolicyCompliance).
	rows, err := db.Scoped(ctx).Query(ctx, `
		WITH scope AS (
			SELECT r.id AS rule_id, r.rule_type, d.id AS device_id,
			       EXISTS (
			         SELECT 1 FROM device_software s
			         WHERE s.device_id = d.id
			           AND r.software_name <> ''
			           AND strpos(lower(s.software_name), lower(r.software_name)) > 0
			       ) AS installed
			FROM software_policy_rules r
			JOIN devices d
			  ON d.tenant_id = $1
			 AND r.tenant_id = $1
			 AND d.status <> 'pending'
			 AND (
			       (r.device_id IS NULL AND r.group_id IS NULL)   -- глобальное
			    OR d.id = r.device_id                             -- оверрайд устройства
			    OR (r.group_id IS NOT NULL AND EXISTS (           -- группа устройства
			          SELECT 1 FROM device_group_members m
			          WHERE m.device_id = d.id AND m.group_id = r.group_id))
			     )
			 AND (
			       r.platforms IS NULL OR cardinality(r.platforms) = 0
			    OR COALESCE(d.os, '') = '' OR lower(d.os) = 'unknown'
			    OR (CASE
			          WHEN lower(d.os) LIKE '%win%' THEN 'Windows'
			          WHEN lower(d.os) LIKE '%mac%' OR lower(d.os) LIKE '%darwin%' THEN 'macOS'
			          ELSE 'Linux'
			        END) = ANY (r.platforms)
			     )
		)
		SELECT r.id, r.rule_type,
		       count(s.device_id)                                                    AS in_scope,
		       count(s.device_id) FILTER (WHERE s.rule_type = 'forbidden' AND NOT s.installed) AS pass,
		       count(s.device_id) FILTER (WHERE s.rule_type = 'forbidden' AND s.installed)     AS fail
		FROM software_policy_rules r
		LEFT JOIN scope s ON s.rule_id = r.id
		WHERE r.tenant_id = $1
		GROUP BY r.id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SoftwarePolicyCompliance
	for rows.Next() {
		var c SoftwarePolicyCompliance
		var ruleType string
		if err := rows.Scan(&c.RuleID, &ruleType, &c.InScope, &c.Pass, &c.Fail); err != nil {
			return nil, err
		}
		c.Checked = ruleType == "forbidden"
		out = append(out, c)
	}
	return out, rows.Err()
}

// SoftwarePolicyDeviceCompliance — разрез соответствия ОДНОГО софт-правила по
// устройствам: кто в области действия и что именно совпало в инвентаре.
// MatchedSoftware/MatchedVersion — первое совпадение (machine-установки вперёд,
// дальше по алфавиту; "" когда совпадений нет): для ответа «почему fail»
// достаточно одного примера. MatchedScope говорит, СНИМАЕМО ли это совпадение:
// 'user' = установка в профиль сотрудника, нарушение считается, но удалить его
// нельзя — служба агента в чужой профиль не ходит.
type SoftwarePolicyDeviceCompliance struct {
	DeviceID        string `json:"device_id"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	Status          string `json:"status"`
	Installed       bool   `json:"installed"`
	MatchedSoftware string `json:"matched_software"`
	MatchedVersion  string `json:"matched_version"`
	MatchedScope    string `json:"matched_scope"`
}

// ListSoftwarePolicyDeviceCompliance — те же область действия и матчер, что у
// ListSoftwarePolicyCompliance (глобальное ∪ device-оверрайд ∪ группа, платформенный
// фильтр с fail-safe, регистронезависимая подстрока), но без агрегации: по строке на
// каждое устройство в области правила. Нарушители первыми, дальше по hostname.
func (db *DB) ListSoftwarePolicyDeviceCompliance(ctx context.Context, tenantID, ruleID string) ([]SoftwarePolicyDeviceCompliance, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT d.id, d.hostname, COALESCE(d.os, ''), d.status,
		       m.software_name IS NOT NULL AS installed,
		       COALESCE(m.software_name, ''), COALESCE(m.version, ''), COALESCE(m.scope, '')
		FROM software_policy_rules r
		JOIN devices d
		  ON d.tenant_id = $1
		 AND r.tenant_id = $1
		 AND d.status <> 'pending'
		 AND (
		       (r.device_id IS NULL AND r.group_id IS NULL)   -- глобальное
		    OR d.id = r.device_id                             -- оверрайд устройства
		    OR (r.group_id IS NOT NULL AND EXISTS (           -- группа устройства
		          SELECT 1 FROM device_group_members gm
		          WHERE gm.device_id = d.id AND gm.group_id = r.group_id))
		     )
		 AND (
		       r.platforms IS NULL OR cardinality(r.platforms) = 0
		    OR COALESCE(d.os, '') = '' OR lower(d.os) = 'unknown'
		    OR (CASE
		          WHEN lower(d.os) LIKE '%win%' THEN 'Windows'
		          WHEN lower(d.os) LIKE '%mac%' OR lower(d.os) LIKE '%darwin%' THEN 'macOS'
		          ELSE 'Linux'
		        END) = ANY (r.platforms)
		     )
		LEFT JOIN LATERAL (
		    SELECT s.software_name, s.version, s.scope
		    FROM device_software s
		    WHERE s.device_id = d.id
		      AND r.software_name <> ''
		      AND strpos(lower(s.software_name), lower(r.software_name)) > 0
		    -- machine-установки вперёд: из двух совпадений оператору полезнее то,
		    -- которое можно снять. Если наверх всё же вышла per-user запись —
		    -- значит machine-совпадения нет вообще, и это тоже сигнал (UI покажет).
		    ORDER BY (s.scope = 'user'), lower(s.software_name)
		    LIMIT 1
		) m ON true
		-- id::text, а не id = $2: ruleID приходит сырым из URL, мусор вместо UUID
		-- дал бы 22P02 → 500; с ::text он просто ничего не находит (конвенция GetScript).
		WHERE r.id::text = $2
		ORDER BY installed DESC, lower(d.hostname)
	`, tenantID, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SoftwarePolicyDeviceCompliance
	for rows.Next() {
		var c SoftwarePolicyDeviceCompliance
		if err := rows.Scan(&c.DeviceID, &c.Hostname, &c.OS, &c.Status,
			&c.Installed, &c.MatchedSoftware, &c.MatchedVersion, &c.MatchedScope); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ScriptPolicyCompliance — Pass/Fail скрипт-политики по ПОСЛЕДНЕМУ прогону на каждом
// устройстве. Unknown = назначено, но результата ещё нет (или устройство не отчиталось).
type ScriptPolicyCompliance struct {
	PolicyID string `json:"policy_id"`
	InScope  int    `json:"in_scope"`
	Pass     int    `json:"pass"`
	Fail     int    `json:"fail"`
	Unknown  int    `json:"unknown"`
}

// ListScriptPolicyCompliance — Pass = exit_code 0 последнего прогона, Fail = ненулевой.
// Порядок «последнего» — по created_at (серверное время), а НЕ по started_at/finished_at:
// те приходят от агента и клампятся, доверять им для выбора победителя нельзя.
//
// Область действия — только через группы (policy_assignments → device_group_members):
// прямого назначения политики на устройство в схеме нет. Устройства, отчитавшиеся, но
// уже выкинутые из группы, в счётчики не попадают — авторитетен in_scope.
func (db *DB) ListScriptPolicyCompliance(ctx context.Context, tenantID string) ([]ScriptPolicyCompliance, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	// Явный tenant_id: под суперюзером mdm FORCE RLS не режет (см. software compliance).
	rows, err := db.Scoped(ctx).Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (sr.device_id, sr.policy_id) sr.policy_id, sr.device_id, sr.exit_code
			FROM script_results sr
			JOIN policies p0 ON p0.id = sr.policy_id AND p0.tenant_id = $1
			ORDER BY sr.device_id, sr.policy_id, sr.created_at DESC
		), assigned AS (
			SELECT DISTINCT pa.policy_id, m.device_id
			FROM policy_assignments pa
			JOIN policies p1 ON p1.id = pa.policy_id AND p1.tenant_id = $1
			JOIN device_group_members m ON m.group_id = pa.group_id
			JOIN devices d ON d.id = m.device_id AND d.status <> 'pending' AND d.tenant_id = $1
		)
		SELECT p.id,
		       count(a.device_id)                                        AS in_scope,
		       count(l.device_id) FILTER (WHERE l.exit_code = 0)         AS pass,
		       count(l.device_id) FILTER (WHERE l.exit_code <> 0)        AS fail
		FROM policies p
		LEFT JOIN assigned a ON a.policy_id = p.id
		LEFT JOIN latest   l ON l.policy_id = p.id AND l.device_id = a.device_id
		WHERE p.tenant_id = $1
		GROUP BY p.id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScriptPolicyCompliance
	for rows.Next() {
		var c ScriptPolicyCompliance
		if err := rows.Scan(&c.PolicyID, &c.InScope, &c.Pass, &c.Fail); err != nil {
			return nil, err
		}
		c.Unknown = c.InScope - c.Pass - c.Fail
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) GetDeviceTenantByFingerprint(ctx context.Context, fingerprint string) (id, tenantID, status string, err error) {
	err = db.pool.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, status FROM auth_device_by_fingerprint($1)`, fingerprint,
	).Scan(&id, &tenantID, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", "", nil
		}
		return "", "", "", err
	}
	return id, tenantID, status, nil
}

func (db *DB) GetDeviceIDByFingerprint(ctx context.Context, fingerprint string) (string, error) {
	id, _, _, err := db.GetDeviceTenantByFingerprint(ctx, fingerprint)
	if err != nil {
		return "", err
	}
	return id, nil
}

type AdminAccessRequest struct {
	ID               string     `json:"id"`
	DeviceID         string     `json:"device_id"`
	RequestedBy      string     `json:"requested_by"`
	Status           string     `json:"status"`
	Reason           string     `json:"reason"`
	RequestedAt      time.Time  `json:"requested_at"`
	PendingExpiresAt time.Time  `json:"pending_expires_at"`
	DecidedBy        *string    `json:"decided_by"`
	DecidedAt        *time.Time `json:"decided_at"`
	GrantedAt        *time.Time `json:"granted_at"`
	ExpiresAt        *time.Time `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at"`
}

func (db *DB) GetSystemSetting(ctx context.Context, tenantID, key string) (string, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return "", err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return "", err
		}
		defer finish(true)
	}
	var value string
	err = db.Scoped(ctx).QueryRow(ctx, `
		SELECT value FROM system_settings
		WHERE key = $1 AND tenant_id IN ($2::uuid, $3::uuid)
		ORDER BY (tenant_id = $2::uuid) DESC
		LIMIT 1
	`, key, tenantID, tenancy.InstallationSettingsTenantID).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return value, nil
}

func (db *DB) SetSystemSetting(ctx context.Context, tenantID, key, value string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx, `
		INSERT INTO system_settings (key, tenant_id, value)
		VALUES ($1, $2::uuid, $3)
		ON CONFLICT (key, tenant_id) DO UPDATE SET value = EXCLUDED.value
	`, key, tenantID, value)
	return err
}

// CreateAdminAccessRequest заводит заявку сотрудника на временные права администратора.
//
// 🔴 Тенант биндится ЗДЕСЬ и tenant_id проставляется ЯВНО. До 04.08 не делалось ни
// того, ни другого, и заявка сотрудника из трея не доезжала вовсе:
//
//   - скоупа вызывающий не открывал (шлюз только РЕЗОЛВИЛ тенанта по отпечатку, в
//     отличие от соседнего ReportAdminAccess, который открывает скоуп), поэтому запрос
//     уходил на соединение из пула без routineops.tenant_id;
//   - tenant_id в INSERT не передавался и брался из DEFAULT миграции 045 — то есть
//     ДЕФОЛТНЫЙ тенант, а не тенант устройства.
//
// На проде это два разных отказа. Мультитенантная установка: заявка ложится в чужой
// тенант — своему администратору не видна, чужому видна. Обычная установка: у свежего
// соединения GUC пуст, `WITH CHECK (tenant_id = current_setting(...)::uuid)` не
// проходит, вставка отбивается — шлюз отдаёт агенту Internal, агент считает Internal
// транзиентом и ретраит каждые 5 секунд ВЕЧНО, а сотруднику трей уже показал
// «Запрос отправлен ✓».
//
// Соседняя FetchActiveAdminRequest всегда биндила тенанта сама — расхождение было
// остатком, а не решением.
func (db *DB) CreateAdminAccessRequest(ctx context.Context, deviceID, requestedBy, reason string, requestedAt, pendingExpiresAt time.Time) (*AdminAccessRequest, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer finish(true)

	var r AdminAccessRequest
	err = db.Scoped(ctx).QueryRow(ctx, `
		INSERT INTO admin_access_requests (device_id, requested_by, reason, requested_at, pending_expires_at, tenant_id)
		VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5,
		        (SELECT tenant_id FROM devices WHERE id = $1))
		RETURNING id, device_id, COALESCE(requested_by::text, ''), status, COALESCE(reason,''),
		          requested_at, pending_expires_at, decided_by, decided_at, granted_at, expires_at, revoked_at
	`, deviceID, requestedBy, reason, requestedAt, pendingExpiresAt).
		Scan(&r.ID, &r.DeviceID, &r.RequestedBy, &r.Status, &r.Reason,
			&r.RequestedAt, &r.PendingExpiresAt, &r.DecidedBy, &r.DecidedAt, &r.GrantedAt, &r.ExpiresAt, &r.RevokedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// FetchActiveAdminRequest returns the latest PENDING or APPROVED request for a device.
// Returns nil if no active request exists.
func (db *DB) FetchActiveAdminRequest(ctx context.Context, deviceID string) (*AdminAccessRequest, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer finish(true)

	var r AdminAccessRequest
	err = db.Scoped(ctx).QueryRow(ctx, `
		SELECT id, device_id, COALESCE(requested_by::text, ''), status, COALESCE(reason,''),
		       requested_at, pending_expires_at, decided_by, decided_at, granted_at, expires_at, revoked_at
		FROM admin_access_requests
		WHERE device_id = $1 AND status IN ('pending', 'approved')
		ORDER BY requested_at DESC
		LIMIT 1
	`, deviceID).Scan(&r.ID, &r.DeviceID, &r.RequestedBy, &r.Status, &r.Reason,
		&r.RequestedAt, &r.PendingExpiresAt, &r.DecidedBy, &r.DecidedAt, &r.GrantedAt, &r.ExpiresAt, &r.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// ErrAdminRequestNotFound — заявки нет или она уже закрыта (UPDATE затронул 0 строк).
// Не транзиентная ошибка: вызывающий делает accept-and-drop, а не ретрай.
var ErrAdminRequestNotFound = errors.New("admin access request not found or already closed")

// UpdateAdminAccessReport records the agent's applied/revoked event.
// status="approved": sets granted_at (first time only).
// status="revoked": sets revoked_at and marks request as revoked.
// Возвращает ErrAdminRequestNotFound, если заявка не найдена / уже закрыта.
// UpdateAdminAccessReport скоупит по device_id: без `AND device_id` любое устройство,
// зная чужой request_id, могло отозвать выданный грант другого устройства (IDOR).
//
// 🔴 Q(ctx), а НЕ db.pool: admin_access_requests под FORCE RLS (миграция 046). Через
// пул запрос уходил на СОСЕДНЕЕ соединение, где routineops.tenant_id не выставлен, и
// предикат политики не совпадал ни с одной строкой — UPDATE трогал 0 строк, функция
// возвращала ErrAdminRequestNotFound, а вызывающий по этой ошибке делает accept-and-drop.
// То есть отчёт агента «локальный админ выдан / отозван» ТИХО терялся: в панели грант
// оставался в прежнем состоянии, и разбирать инцидент было бы не по чему. На отравленном
// соединении (GUC == ” после транзакционного set_config) тот же запрос падал бы в 22P02.
// Вызывающий скоуп открывает сам (gateway.ReportAdminAccess → scopeByFingerprint), так
// что достаточно перестать его игнорировать. Соседняя MarkAdminBaselineCaptured в этом
// же потоке всегда ходила через Q(ctx) — расхождение было остатком, а не решением.
func (db *DB) UpdateAdminAccessReport(ctx context.Context, requestID, deviceID, status string, occurredAt time.Time) error {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return scopeErr
	}
	defer finish(true)
	var q string
	if status == "approved" {
		q = `UPDATE admin_access_requests SET granted_at = $2 WHERE id = $1 AND device_id = $3 AND granted_at IS NULL`
	} else {
		q = `UPDATE admin_access_requests SET status = 'revoked', revoked_at = $2 WHERE id = $1 AND device_id = $3`
	}
	tag, err := db.Scoped(ctx).Exec(ctx, q, requestID, occurredAt, deviceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAdminRequestNotFound
	}
	return nil
}

// RespondToAdminRequest sets the IT admin's decision on a PENDING request.
// expiresAt is only relevant for "approved" decisions.
func (db *DB) RespondToAdminRequest(ctx context.Context, requestID, decision, decidedByUserID string, expiresAt *time.Time) error {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return scopeErr
	}
	defer finish(true)
	_, err := db.Scoped(ctx).Exec(ctx, `
		UPDATE admin_access_requests
		SET status = $2, decided_by = $3, decided_at = now(), expires_at = $4
		WHERE id = $1 AND status = 'pending'
	`, requestID, decision, decidedByUserID, expiresAt)
	return err
}

func (db *DB) RevokeAdminAccessRequest(ctx context.Context, tenantID, requestID string) error {
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	defer finish(true)

	_, err = db.Scoped(ctx).Exec(ctx,
		`UPDATE admin_access_requests SET status = 'revoked', revoked_at = NOW()
   WHERE id = $1 AND status = 'approved'`,
		requestID)
	return err
}

// ExpireStaleAdminRequests marks PENDING requests past their pending_expires_at
// and APPROVED requests past their expires_at as EXPIRED.
func (db *DB) ExpireStaleAdminRequests(ctx context.Context) (int64, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return 0, scopeErr
	}
	defer finish(true)
	result, err := db.Scoped(ctx).Exec(ctx, `
		UPDATE admin_access_requests
		SET status = 'expired'
		WHERE (status = 'pending' AND pending_expires_at < now())
		   OR (status = 'approved' AND expires_at IS NOT NULL AND expires_at < now())
	`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

type AdminAccessRequestRow struct {
	ID               string     `json:"id"`
	DeviceID         string     `json:"device_id"`
	DeviceHostname   string     `json:"device_hostname"`
	RequestedBy      string     `json:"requested_by"`
	RequesterEmail   string     `json:"requester_email"`
	Status           string     `json:"status"`
	Reason           string     `json:"reason"`
	RequestedAt      time.Time  `json:"requested_at"`
	PendingExpiresAt time.Time  `json:"pending_expires_at"`
	DecidedAt        *time.Time `json:"decided_at"`
	GrantedAt        *time.Time `json:"granted_at"`
	ExpiresAt        *time.Time `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at"`
	// Сводка улик — колонками в заявке, без JOIN/N+1 (контракт §5.2).
	BaselineCapturedAt  *time.Time `json:"baseline_captured_at"`
	ChangesFinalAt      *time.Time `json:"changes_final_at"`
	ChangesCompleteness string     `json:"changes_completeness"`
	ChangesRebooted     bool       `json:"changes_rebooted"`
	ChangesTruncated    bool       `json:"changes_truncated"`
	SoftwareHealth      string     `json:"software_health"`
	ServicesHealth      string     `json:"services_health"`
	LastWindowSeq       int32      `json:"last_window_seq"`
}

func (db *DB) ListAdminAccessRequests(ctx context.Context, tenantID, statusFilter string) ([]AdminAccessRequestRow, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT r.id, r.device_id, COALESCE(d.hostname, ''), COALESCE(r.requested_by::text, ''), COALESCE(u.email, ''),
		       r.status, COALESCE(r.reason, ''), r.requested_at, r.pending_expires_at,
		       r.decided_at, r.granted_at, r.expires_at, r.revoked_at,
		       r.baseline_captured_at, r.changes_final_at, r.changes_completeness,
		       r.changes_rebooted, r.changes_truncated, r.software_health, r.services_health,
		       r.last_window_seq
		FROM admin_access_requests r
		LEFT JOIN devices d ON d.id = r.device_id
		LEFT JOIN users u ON u.id = r.requested_by
		WHERE r.tenant_id = $1 AND ($2 = '' OR r.status = $2)
		ORDER BY r.requested_at DESC
		LIMIT 100
	`, tenantID, statusFilter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AdminAccessRequestRow
	for rows.Next() {
		var r AdminAccessRequestRow
		if err := rows.Scan(&r.ID, &r.DeviceID, &r.DeviceHostname, &r.RequestedBy, &r.RequesterEmail,
			&r.Status, &r.Reason, &r.RequestedAt, &r.PendingExpiresAt,
			&r.DecidedAt, &r.GrantedAt, &r.ExpiresAt, &r.RevokedAt,
			&r.BaselineCapturedAt, &r.ChangesFinalAt, &r.ChangesCompleteness,
			&r.ChangesRebooted, &r.ChangesTruncated, &r.SoftwareHealth, &r.ServicesHealth,
			&r.LastWindowSeq); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// ====== Scripts ======

type Script struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (db *DB) ListScripts(ctx context.Context, tenantID string) ([]Script, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	rows, err := db.Scoped(ctx).Query(ctx,
		`SELECT id, name, platform, content, created_at, updated_at FROM scripts
		 WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scripts []Script
	for rows.Next() {
		var s Script
		if err := rows.Scan(&s.ID, &s.Name, &s.Platform, &s.Content, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		scripts = append(scripts, s)
	}
	return scripts, rows.Err()
}

// ErrDuplicateName — имя ресурса занято (уникальные индексы по lower(btrim(name)):
// device_groups в 026, scripts и policies в 033). Имя — идентичность ресурса для
// YAML-apply, поэтому занятое имя обязано отдаваться 409, а не 500.
var ErrDuplicateName = errors.New("resource name already exists")

// asDuplicateName переводит нарушение уникального индекса в ErrDuplicateName, прочие
// ошибки пропускает как есть.
func asDuplicateName(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrDuplicateName
	}
	return err
}

func (db *DB) CreateScript(ctx context.Context, tenantID, name, platform, content string) (*Script, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var s Script
	err = db.Scoped(ctx).QueryRow(ctx, `
		INSERT INTO scripts (tenant_id, name, platform, content)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, platform, content, created_at, updated_at
	`, tenantID, name, platform, content).Scan(&s.ID, &s.Name, &s.Platform, &s.Content, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, asDuplicateName(err)
	}
	return &s, nil
}

func (db *DB) GetScript(ctx context.Context, tenantID, id string) (*Script, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var s Script
	// id::text, а не id = $1: при кривом script_id (не UUID) сравнение с uuid-колонкой
	// падает 22P02 → handler отдавал 500 вместо 404. Через ::text несуществующий/кривой
	// id просто не находится → ErrNoRows → nil,nil → 404 (приём как у DeviceGroupExists).
	err = db.Scoped(ctx).QueryRow(ctx,
		`SELECT id, name, platform, content, created_at, updated_at FROM scripts
		 WHERE tenant_id = $1 AND id::text = $2`, tenantID, id).
		Scan(&s.ID, &s.Name, &s.Platform, &s.Content, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

func (db *DB) UpdateScript(ctx context.Context, tenantID, id, name, platform, content string) (*Script, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var s Script
	err = db.Scoped(ctx).QueryRow(ctx, `
		UPDATE scripts SET name=$3, platform=$4, content=$5, updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, name, platform, content, created_at, updated_at
	`, tenantID, id, name, platform, content).Scan(&s.ID, &s.Name, &s.Platform, &s.Content, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, asDuplicateName(err)
	}
	return &s, nil
}

// ErrScriptInUse — на скрипт ссылается хотя бы одна script-политика (FK без CASCADE).
// Удалять нельзя: иначе политика осталась бы без тела скрипта. Отдаётся как 409.
var ErrScriptInUse = errors.New("script is referenced by script policies")

func (db *DB) DeleteScript(ctx context.Context, tenantID, id string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx, `DELETE FROM scripts WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if errors.Is(wrapFKViolation(err), ErrForeignKeyViolation) {
		return ErrScriptInUse
	}
	return err
}

// ====== Script Policies ======

type ScriptPolicy struct {
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	ScriptID           string          `json:"script_id"`
	ScriptName         string          `json:"script_name"`
	TriggerType        string          `json:"trigger_type"`
	ScheduleConfig     json.RawMessage `json:"schedule_config,omitempty"`
	EventTriggerConfig json.RawMessage `json:"event_trigger_config,omitempty"`
	IsActive           bool            `json:"is_active"`
	CreatedAt          time.Time       `json:"created_at"`
	// GroupNames — имена групп, которым назначена политика (через policy_assignments).
	// Пусто → политика не таргетит ни одно устройство и молча не выполняется (#4).
	GroupNames []string `json:"group_names"`
}

func (db *DB) ListScriptPolicies(ctx context.Context, tenantID string) ([]ScriptPolicy, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT p.id, p.name, p.script_id, COALESCE(s.name, ''), p.trigger_type,
		       COALESCE(p.schedule_config::text, 'null'), COALESCE(p.event_trigger_config::text, 'null'),
		       p.is_active, p.created_at,
		       COALESCE(
		         (SELECT array_agg(g.name ORDER BY g.name)
		          FROM policy_assignments pa JOIN device_groups g ON g.id = pa.group_id
		          WHERE pa.policy_id = p.id AND pa.tenant_id = $1),
		         ARRAY[]::text[]
		       ) AS group_names
		FROM policies p
		LEFT JOIN scripts s ON s.id = p.script_id
		WHERE p.tenant_id = $1
		ORDER BY p.created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []ScriptPolicy
	for rows.Next() {
		var p ScriptPolicy
		var schedRaw, eventRaw string
		if err := rows.Scan(&p.ID, &p.Name, &p.ScriptID, &p.ScriptName, &p.TriggerType,
			&schedRaw, &eventRaw, &p.IsActive, &p.CreatedAt, &p.GroupNames); err != nil {
			return nil, err
		}
		p.ScheduleConfig = json.RawMessage(schedRaw)
		p.EventTriggerConfig = json.RawMessage(eventRaw)
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func (db *DB) CreateScriptPolicy(ctx context.Context, tenantID, name, scriptID, triggerType string, scheduleConfig, eventTriggerConfig []byte) (*ScriptPolicy, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var p ScriptPolicy
	var schedRaw, eventRaw string
	// Скрипт обязан быть того же тенанта — иначе INSERT молча связал бы политику A со скриптом B.
	err = db.Scoped(ctx).QueryRow(ctx, `
		INSERT INTO policies (tenant_id, name, script_id, trigger_type, schedule_config, event_trigger_config)
		SELECT $1, $2, s.id, $4, $5::jsonb, $6::jsonb
		FROM scripts s WHERE s.id = $3 AND s.tenant_id = $1
		RETURNING id, name, script_id, trigger_type,
		          COALESCE(schedule_config::text, 'null'), COALESCE(event_trigger_config::text, 'null'),
		          is_active, created_at
	`, tenantID, name, scriptID, triggerType, nullableJSON(scheduleConfig), nullableJSON(eventTriggerConfig)).
		Scan(&p.ID, &p.Name, &p.ScriptID, &p.TriggerType, &schedRaw, &eventRaw, &p.IsActive, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // скрипта нет в этом тенанте
		}
		return nil, asDuplicateName(err)
	}
	p.ScheduleConfig = json.RawMessage(schedRaw)
	p.EventTriggerConfig = json.RawMessage(eventRaw)
	return &p, nil
}

func (db *DB) DeleteScriptPolicy(ctx context.Context, tenantID, id string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx, `DELETE FROM policies WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// UpdateScriptPolicy переписывает политику целиком (кроме is_active — им управляет
// ToggleScriptPolicy). Нужен для идемпотентного YAML-apply: без него правка расписания
// требовала бы delete+create, а это потеря истории результатов и id, на который
// ссылаются назначения групп. (nil, nil) = политики нет → 404.
func (db *DB) UpdateScriptPolicy(ctx context.Context, tenantID, id, name, scriptID, triggerType string, scheduleConfig, eventTriggerConfig []byte) (*ScriptPolicy, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var p ScriptPolicy
	var schedRaw, eventRaw string
	err = db.Scoped(ctx).QueryRow(ctx, `
		UPDATE policies
		SET    name = $3, script_id = $4, trigger_type = $5,
		       schedule_config = $6::jsonb, event_trigger_config = $7::jsonb
		WHERE  tenant_id = $1 AND id::text = $2
		  AND EXISTS (SELECT 1 FROM scripts s WHERE s.id = $4 AND s.tenant_id = $1)
		RETURNING id, name, script_id, trigger_type,
		          COALESCE(schedule_config::text, 'null'), COALESCE(event_trigger_config::text, 'null'),
		          is_active, created_at
	`, tenantID, id, name, scriptID, triggerType, nullableJSON(scheduleConfig), nullableJSON(eventTriggerConfig)).
		Scan(&p.ID, &p.Name, &p.ScriptID, &p.TriggerType, &schedRaw, &eventRaw, &p.IsActive, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, asDuplicateName(err)
	}
	p.ScheduleConfig = json.RawMessage(schedRaw)
	p.EventTriggerConfig = json.RawMessage(eventRaw)
	return &p, nil
}

func (db *DB) ToggleScriptPolicy(ctx context.Context, tenantID, id string, active bool) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx, `UPDATE policies SET is_active=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, id, active)
	return err
}

func nullableJSON(b []byte) any {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return string(b)
}

// ====== Device Groups ======

type DeviceGroup struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"` // '#rrggbb', CHECK в миграции 027
	// UpdateChannel — канал обновлений участников группы (065): stable|beta.
	// Канарейка — это группа канала beta, куда кладут несколько машин перед
	// выкаткой на парк.
	UpdateChannel string    `json:"update_channel"`
	CreatedAt     time.Time `json:"created_at"`
}

// DefaultGroupColor — то же значение, что DEFAULT колонки color (миграция 027).
// Используется, когда клиент цвет не прислал.
const DefaultGroupColor = "#3b82f6"

// GroupSoftwareRule — групповое софт-правило (allow/forbidden ПО), привязанное к
// группе через software_policy_rules.group_id (#2). Отдаётся в карточке группы.
type GroupSoftwareRule struct {
	ID           string `json:"id"`
	SoftwareName string `json:"software_name"`
	RuleType     string `json:"rule_type"`
}

type DeviceGroupWithMembers struct {
	DeviceGroup
	DeviceIDs     []string            `json:"device_ids"`
	PolicyIDs     []string            `json:"policy_ids"`
	SoftwareRules []GroupSoftwareRule `json:"software_rules"`
}

func (db *DB) ListDeviceGroups(ctx context.Context, tenantID string) ([]DeviceGroupWithMembers, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	rows, err := db.Scoped(ctx).Query(ctx,
		`SELECT id, name, color, update_channel, created_at FROM device_groups
		 WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []DeviceGroupWithMembers
	for rows.Next() {
		var g DeviceGroupWithMembers
		if err := rows.Scan(&g.ID, &g.Name, &g.Color, &g.UpdateChannel, &g.CreatedAt); err != nil {
			return nil, err
		}
		g.DeviceIDs = []string{}
		g.PolicyIDs = []string{}
		g.SoftwareRules = []GroupSoftwareRule{}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return groups, nil
	}

	// Три пакетных запроса вместо трёх на КАЖДУЮ группу (было 1+3N).
	byID := make(map[string]*DeviceGroupWithMembers, len(groups))
	for i := range groups {
		byID[groups[i].ID] = &groups[i]
	}

	members, err := db.Scoped(ctx).Query(ctx, `SELECT group_id, device_id FROM device_group_members WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer members.Close()
	for members.Next() {
		var gid, did string
		if err := members.Scan(&gid, &did); err != nil {
			return nil, err
		}
		if g := byID[gid]; g != nil {
			g.DeviceIDs = append(g.DeviceIDs, did)
		}
	}
	if err := members.Err(); err != nil {
		return nil, err
	}

	assignments, err := db.Scoped(ctx).Query(ctx, `SELECT group_id, policy_id FROM policy_assignments WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer assignments.Close()
	for assignments.Next() {
		var gid, pid string
		if err := assignments.Scan(&gid, &pid); err != nil {
			return nil, err
		}
		if g := byID[gid]; g != nil {
			g.PolicyIDs = append(g.PolicyIDs, pid)
		}
	}
	if err := assignments.Err(); err != nil {
		return nil, err
	}

	// Групповые софт-правила (#2): привязаны через software_policy_rules.group_id.
	sw, err := db.Scoped(ctx).Query(ctx,
		`SELECT group_id, id, software_name, rule_type FROM software_policy_rules
		 WHERE tenant_id = $1 AND group_id IS NOT NULL`, tenantID)
	if err != nil {
		return nil, err
	}
	defer sw.Close()
	for sw.Next() {
		var gid string
		var rule GroupSoftwareRule
		if err := sw.Scan(&gid, &rule.ID, &rule.SoftwareName, &rule.RuleType); err != nil {
			return nil, err
		}
		if g := byID[gid]; g != nil {
			g.SoftwareRules = append(g.SoftwareRules, rule)
		}
	}
	if err := sw.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}

// ErrDuplicateGroupName — имя группы занято (уникальный индекс по lower(btrim(name)),
// миграция 026). Отдаётся как 409, не 500.
var ErrDuplicateGroupName = errors.New("device group name already exists")

// CreateDeviceGroup — пустой color не ошибка, а «на усмотрение БД» (DEFAULT из 027).
// Валидацию формата делает хендлер, БД страхует CHECK'ом. Пустой channel — то же
// самое: DEFAULT 'stable' из 065.
func (db *DB) CreateDeviceGroup(ctx context.Context, tenantID, name, color, channel string) (*DeviceGroup, error) {
	if channel != "" && !ValidChannel(channel) {
		return nil, fmt.Errorf("неизвестный канал обновлений %q", channel)
	}
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var g DeviceGroup
	err = db.Scoped(ctx).QueryRow(ctx,
		`INSERT INTO device_groups (tenant_id, name, color, update_channel)
		 VALUES ($1, $2, COALESCE(NULLIF($3, ''), $4), COALESCE(NULLIF($5, ''), $6))
		 RETURNING id, name, color, update_channel, created_at`,
		tenantID, name, color, DefaultGroupColor, channel, ChannelStable).
		Scan(&g.ID, &g.Name, &g.Color, &g.UpdateChannel, &g.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateGroupName
		}
		return nil, err
	}
	return &g, nil
}

// UpdateDeviceGroup меняет имя, цвет и/или канал обновлений. Пустая строка = «не
// трогать это поле», поэтому переименовать в пустое имя нельзя (и не нужно: CHECK 026
// всё равно не даст). Возвращает (nil, nil), если группы нет — хендлер отдаёт 404.
func (db *DB) UpdateDeviceGroup(ctx context.Context, tenantID, id, name, color, channel string) (*DeviceGroup, error) {
	if channel != "" && !ValidChannel(channel) {
		return nil, fmt.Errorf("неизвестный канал обновлений %q", channel)
	}
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var g DeviceGroup
	err = db.Scoped(ctx).QueryRow(ctx, `
		UPDATE device_groups
		SET    name           = COALESCE(NULLIF($3, ''), name),
		       color          = COALESCE(NULLIF($4, ''), color),
		       update_channel = COALESCE(NULLIF($5, ''), update_channel)
		WHERE  tenant_id = $1 AND id::text = $2
		RETURNING id, name, color, update_channel, created_at
	`, tenantID, id, name, color, channel).Scan(&g.ID, &g.Name, &g.Color, &g.UpdateChannel, &g.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateGroupName
		}
		return nil, err
	}
	return &g, nil
}

// DeviceGroupExists нужен там, где иначе молча получается no-op: запуск скрипта на
// несуществующей группе возвращал 201 created:0.
func (db *DB) DeviceGroupExists(ctx context.Context, tenantID, id string) (bool, error) {
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
	var exists bool
	// id::text, а не id: кривой UUID из URL иначе даёт 22P02 и превращается в 500.
	err = db.Scoped(ctx).QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM device_groups WHERE tenant_id = $1 AND id::text = $2)`,
		tenantID, id).Scan(&exists)
	return exists, err
}

func (db *DB) DeleteDeviceGroup(ctx context.Context, tenantID, id string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx, `DELETE FROM device_groups WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	return err
}

// AddDeviceToGroup — несуществующее устройство/группа = ErrForeignKeyViolation (→400),
// а не «internal error». То же у AssignPolicyToGroup / AssignSoftwarePolicyToGroup.
func (db *DB) AddDeviceToGroup(ctx context.Context, tenantID, deviceID, groupID string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	var ok bool
	if err = db.Scoped(ctx).QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM devices d
		  JOIN device_groups g ON g.tenant_id = d.tenant_id
		  WHERE d.id = $2 AND g.id = $3 AND d.tenant_id = $1
		)`, tenantID, deviceID, groupID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: device_or_group", ErrForeignKeyViolation)
	}
	_, err = db.Scoped(ctx).Exec(ctx, `
		INSERT INTO device_group_members (tenant_id, device_id, group_id)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, tenantID, deviceID, groupID)
	return wrapFKViolation(err)
}

func (db *DB) RemoveDeviceFromGroup(ctx context.Context, tenantID, deviceID, groupID string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx,
		`DELETE FROM device_group_members WHERE tenant_id=$1 AND device_id=$2 AND group_id=$3`,
		tenantID, deviceID, groupID)
	return err
}

func (db *DB) AssignPolicyToGroup(ctx context.Context, tenantID, policyID, groupID string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	var ok bool
	if err = db.Scoped(ctx).QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM policies p
		  JOIN device_groups g ON g.tenant_id = p.tenant_id
		  WHERE p.id = $2 AND g.id = $3 AND p.tenant_id = $1
		)`, tenantID, policyID, groupID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: policy_or_group", ErrForeignKeyViolation)
	}
	_, err = db.Scoped(ctx).Exec(ctx, `
		INSERT INTO policy_assignments (tenant_id, policy_id, group_id)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, tenantID, policyID, groupID)
	return wrapFKViolation(err)
}

func (db *DB) UnassignPolicyFromGroup(ctx context.Context, tenantID, policyID, groupID string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx,
		`DELETE FROM policy_assignments WHERE tenant_id=$1 AND policy_id=$2 AND group_id=$3`,
		tenantID, policyID, groupID)
	return err
}

// AssignSoftwarePolicyToGroup создаёт групповое софт-правило (group_id set, #2).
// Зеркалит CreatePolicyRule, но пишет group_id вместо device_id.
func (db *DB) AssignSoftwarePolicyToGroup(ctx context.Context, tenantID, groupID, softwareName, ruleType string) (*PolicyRuleRow, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var r PolicyRuleRow
	err = db.Scoped(ctx).QueryRow(ctx, `
  INSERT INTO software_policy_rules (tenant_id, software_name, rule_type, group_id)
  SELECT $1, $3, $4, g.id FROM device_groups g WHERE g.id = $2 AND g.tenant_id = $1
  RETURNING id, software_name, rule_type, device_id, group_id, updated_at
 `, tenantID, groupID, softwareName, ruleType).
		Scan(&r.ID, &r.SoftwareName, &r.RuleType, &r.DeviceID, &r.GroupID, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: group", ErrForeignKeyViolation)
		}
		return nil, wrapFKViolation(err)
	}
	return &r, nil
}

// UnassignSoftwarePolicyFromGroup удаляет групповое правило по id, ограничивая
// удаление рамками группы (нельзя снести чужое/device/global правило этим маршрутом).
func (db *DB) UnassignSoftwarePolicyFromGroup(ctx context.Context, tenantID, groupID, ruleID string) error {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		defer finish(true)
	}
	_, err = db.Scoped(ctx).Exec(ctx,
		`DELETE FROM software_policy_rules WHERE tenant_id=$1 AND id=$2 AND group_id=$3`,
		tenantID, ruleID, groupID)
	return err
}

// FanOutScriptToGroup создаёт по одной pending-задаче на КАЖДОГО совместимого по
// платформе члена группы (#3) и возвращает их (для Enqueue). Значение platform в
// задаче = script.Platform (см. worker/agent run.go: PowerShell даёт строго "Windows",
// остальное → bash).
//
// Раньше сравнение было бинарным (windows / не-windows), из-за чего macOS-скрипт улетал
// на Linux, а Linux-скрипт — на macOS. Теперь обе стороны приводятся к одному словарю
// Windows/macOS/Linux (тот же, что normalizePlatform).
//
// ⚠️ Три-way (macOS ≠ Linux) — НАМЕРЕННО: справочный скрипт, помеченный "macOS", может
// содержать macOS-специфику (osascript/defaults), которую нельзя слепо гнать на Linux.
// Это расходится с фронтовым deviceRunsScript (там macOS/Linux = одна shell-family):
// оператор может выбрать в UI "macOS"-скрипт для группы Linux-машин и получить 0 задач
// при рапорте «успех». Выравнивание этих двух семантик — открытый дизайн-вопрос (бэклог),
// а не правка здесь: менять поведение без решения нельзя (тест закрепляет три-way).
func (db *DB) FanOutScriptToGroup(ctx context.Context, groupID, scriptContent, platform, priority string) ([]Task, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return nil, scopeErr
	}
	defer finish(true)
	rows, err := db.Scoped(ctx).Query(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status)
  SELECT m.device_id, $2, $3, $4, 'pending'
  FROM device_group_members m
  JOIN devices d ON d.id = m.device_id
  WHERE m.group_id = $1
    -- Скрипт-канал = RCE от SYSTEM/root: гоним ТОЛЬКО на active. Неодобренное
    -- (pending_approval) устройство — член группы ДО одобрения, но скриптов не
    -- получает (пуш-двойник pull-гейта в FetchScriptPolicies); rejected/blocked/
    -- decommissioned тоже исключены (не в парке).
    AND d.status = 'active'
    AND CASE
          WHEN d.os ILIKE '%win%' THEN 'Windows'
          WHEN d.os ILIKE '%mac%' OR d.os ILIKE '%darwin%' THEN 'macOS'
          ELSE 'Linux'
        END = $5
  RETURNING id, device_id, script_content, platform, priority, status, created_at
 `, groupID, scriptContent, platform, priority, normalizePlatform(platform))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.CreatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// ====== Effective Script Policies (gRPC Stage 5) ======

type EffectiveScriptPolicy struct {
	PolicyID    string
	Name        string
	Content     string
	Platform    string
	TriggerType string
	Cron        string
	EventName   string
	UpdatedAt   time.Time
}

type EffectivePoliciesResult struct {
	Policies []EffectiveScriptPolicy
	Version  int64 // unix max(updated_at) across the effective set
}

// GetEffectiveScriptPoliciesForDevice returns active script policies assigned
// (via device groups) to the device identified by its cert fingerprint.
// Server resolves group membership; the agent never sees groups directly (ADR-1).
func (db *DB) GetEffectiveScriptPoliciesForDevice(ctx context.Context, fingerprint string) (*EffectivePoliciesResult, error) {
	id, tenantID, _, err := db.GetDeviceTenantByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return &EffectivePoliciesResult{}, nil
	}
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT DISTINCT ON (p.id)
		       p.id, p.name, s.content, s.platform, p.trigger_type,
		       COALESCE(p.schedule_config->>'cron', ''),
		       COALESCE(p.event_trigger_config->>'event', ''),
		       GREATEST(p.updated_at, s.updated_at) AS effective_updated_at
		FROM   policies p
		JOIN   scripts s              ON s.id  = p.script_id
		JOIN   policy_assignments pa  ON pa.policy_id = p.id
		JOIN   device_group_members m ON m.group_id   = pa.group_id
		JOIN   devices d              ON d.id          = m.device_id
		WHERE  d.certificate_fingerprint = $1
		  AND  p.is_active = true
		ORDER  BY p.id, effective_updated_at DESC
	`, fingerprint)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result EffectivePoliciesResult
	for rows.Next() {
		var ep EffectiveScriptPolicy
		if err := rows.Scan(&ep.PolicyID, &ep.Name, &ep.Content, &ep.Platform,
			&ep.TriggerType, &ep.Cron, &ep.EventName, &ep.UpdatedAt); err != nil {
			return nil, err
		}
		result.Policies = append(result.Policies, ep)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Отпечаток всего набора, а не MAX(updated_at): снятие привязки и toggle=false
	// выкидывают политику из выборки, но максимума не двигают.
	fingerprints := make([]string, 0, len(result.Policies))
	for _, ep := range result.Policies {
		fingerprints = append(fingerprints, policySetItem(
			ep.PolicyID, ep.Name, ep.Platform, ep.TriggerType, ep.Cron, ep.EventName,
			strconv.FormatInt(ep.UpdatedAt.UnixNano(), 10), ep.Content,
		))
	}
	result.Version = policySetVersion(fingerprints)
	return &result, nil
}

type ScriptResultInput struct {
	PolicyID   string
	DeviceID   string
	RunID      string
	ExitCode   int32
	Stdout     string
	Stderr     string
	Trigger    string
	StartedAt  time.Time
	FinishedAt time.Time
}

func (db *DB) SaveScriptResult(ctx context.Context, r ScriptResultInput) error {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return scopeErr
	}
	defer finish(true)
	_, err := db.Scoped(ctx).Exec(ctx, `
		INSERT INTO script_results
		       (policy_id, device_id, run_id, exit_code, stdout, stderr, trigger, started_at, finished_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (run_id) DO NOTHING
	`, r.PolicyID, r.DeviceID, r.RunID, r.ExitCode, r.Stdout, r.Stderr, r.Trigger,
		r.StartedAt, r.FinishedAt)
	// 23503 = политика/устройство удалены до доставки результата (наблюдалось живьём:
	// outbox агента вечно ретраил результаты удалённой политики).
	return wrapFKViolation(err)
}

type ScriptResultRow struct {
	ID             string    `json:"id"`
	PolicyID       string    `json:"policy_id"`
	DeviceID       string    `json:"device_id"`
	DeviceHostname string    `json:"device_hostname"`
	RunID          string    `json:"run_id"`
	ExitCode       int32     `json:"exit_code"`
	Stdout         string    `json:"stdout"`
	Stderr         string    `json:"stderr"`
	Trigger        string    `json:"trigger"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	CreatedAt      time.Time `json:"created_at"`
}

// ListScriptResultsByPolicy — история результатов запусков script-политики (по убыванию
// времени), с хостнеймом устройства. limit ограничен для защиты от гигантских выборок.
func (db *DB) ListScriptResultsByPolicy(ctx context.Context, tenantID, policyID string, limit int) ([]ScriptResultRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	// BindTenant строго ДО запроса и запрос через Q(ctx): иначе SELECT уходит мимо
	// транзакции с выставленным GUC routineops.tenant_id, и tenant-скоуп не применяется
	// вовсе (до 049 — чужие строки, после — пустая выборка под RLS).
	ctx, finish, err := db.BindTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer finish(true)

	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT r.id, r.policy_id, r.device_id, COALESCE(d.hostname, ''), r.run_id,
		       r.exit_code, COALESCE(r.stdout, ''), COALESCE(r.stderr, ''), r.trigger,
		       r.started_at, r.finished_at, r.created_at
		FROM script_results r
		LEFT JOIN devices d ON d.id = r.device_id
		WHERE r.policy_id = $1
		ORDER BY r.created_at DESC
		LIMIT $2
	`, policyID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScriptResultRow
	for rows.Next() {
		var r ScriptResultRow
		if err := rows.Scan(&r.ID, &r.PolicyID, &r.DeviceID, &r.DeviceHostname, &r.RunID,
			&r.ExitCode, &r.Stdout, &r.Stderr, &r.Trigger,
			&r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ====== Device Tasks ======

func (db *DB) ListDeviceTasks(ctx context.Context, tenantID, deviceID string) ([]Task, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	rows, err := db.Scoped(ctx).Query(ctx, `
  SELECT id, device_id, script_content, platform, priority, status, output, error_log, created_at,
         task_type, uninstall_software_name, uninstall_version, uninstall_uninstall_id,
         uninstall_install_location, uninstall_method, uninstall_scope, uninstall_reason,
         uninstall_outcome
  FROM tasks WHERE device_id = $1 AND tenant_id = $2
  ORDER BY created_at DESC LIMIT 50
 `, deviceID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.Output, &t.ErrorLog, &t.CreatedAt,
			&t.TaskType,
			&t.Uninstall.SoftwareName, &t.Uninstall.Version, &t.Uninstall.UninstallID,
			&t.Uninstall.InstallLocation, &t.Uninstall.Method, &t.Uninstall.Scope, &t.Uninstall.Reason,
			&t.UninstallOutcome); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// ---- Device list (enrolled/active only) ----

// likeEscaper экранирует спецсимволы LIKE-паттерна. Без него пользовательский '%'
// матчит всё, а '_' — любой символ: поиск «_» вернул бы весь парк.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// macSeparators — разделители MAC/серийников, которые люди печатают как попало
// (aa:bb:cc, aa-bb-cc, aabb.ccdd). Нормализуем обе стороны сравнения.
var macSeparators = strings.NewReplacer(":", "", "-", "", ".", "", " ", "")

// deviceSearchColumns — атрибуты, по которым ищет ListEnrolledDevices. Всё, что
// собирает агент (инвентарь + сеть) плюс серверные идентификаторы. uuid и int
// кастуются в text: ILIKE по ним напрямую невозможен.
const deviceSearchColumns = `
	     COALESCE(d.hostname, '')       ILIKE $3
	  OR COALESCE(d.os, '')             ILIKE $3
	  OR COALESCE(d.os_version, '')     ILIKE $3
	  OR COALESCE(d.ip_address, '')     ILIKE $3
	  OR COALESCE(d.public_ip, '')      ILIKE $3
	  OR COALESCE(d.mac_address, '')    ILIKE $3
	  OR COALESCE(d.serial_number, '')  ILIKE $3
	  OR COALESCE(d.cpu, '')            ILIKE $3
	  OR COALESCE(d.disk, '')           ILIKE $3
	  OR COALESCE(d.agent_version, '')  ILIKE $3
	  OR COALESCE(d.cert_cn, '')        ILIKE $3
	  OR COALESCE(d.ram::text, '')      ILIKE $3
	  OR d.id::text                     ILIKE $3
	  OR ($4 <> '' AND translate(COALESCE(d.mac_address, ''), ':-. ', '') ILIKE $4)
	  OR ($4 <> '' AND translate(COALESCE(d.serial_number, ''), ':-. ', '') ILIKE $4)`

// ListEnrolledDevices возвращает все не-pending устройства. Непустой query фильтрует
// по подстроке ЛЮБОГО атрибута (см. deviceSearchColumns): достаточно хвоста серийника
// или куска IP. Пустой query — весь список, как раньше. Непустой groupID оставляет
// только членов этой группы; сравнение через group_id::text, иначе кривой UUID из
// URL даёт 22P02 и превращается в 500 вместо пустой выдачи.
func (db *DB) ListEnrolledDevices(ctx context.Context, tenantID, query, groupID string, limit, offset int) ([]Device, int, error) {
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
	q := strings.TrimSpace(query)
	pattern, stripped := "", ""
	if q != "" {
		pattern = "%" + likeEscaper.Replace(q) + "%"
		// Отдельный паттерн без разделителей — работает в обе стороны: «aabbcc» найдёт
		// «aa:bb:cc» в БД, «aa-bb» найдёт «aabb». Если после зачистки ничего не осталось
		// (запрос из одних дефисов) — клауза выключена, иначе '%%' сматчил бы весь парк.
		if s := macSeparators.Replace(q); s != "" {
			stripped = "%" + likeEscaper.Replace(s) + "%"
		}
	}
	// Порядок дополнен id: last_seen_at у устройств одной волны раскатки совпадает
	// с точностью до секунды, а нестабильный порядок постранично = строки, которые
	// перепрыгивают со страницы на страницу и «пропадают» из выдачи.
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT d.id, d.hostname, d.os, COALESCE(d.os_version, ''), COALESCE(d.ip_address, ''),
		       d.status, d.last_seen_at, d.created_at, COALESCE(d.agent_version, ''),
		       COALESCE(d.mac_address, ''), COALESCE(d.serial_number, ''), COALESCE(d.public_ip, ''),
		       d.outbox_unavailable, COALESCE(d.degraded_detail, ''), d.degraded_since,
		       COUNT(*) OVER() AS total
		FROM devices d
		WHERE d.tenant_id = $1
		  AND d.status != 'pending'
		  AND ($2 = '' OR (`+deviceSearchColumns+`))
		  AND ($5 = '' OR EXISTS (SELECT 1 FROM device_group_members m
		                          WHERE m.device_id = d.id AND m.group_id::text = $5 AND m.tenant_id = $1))
		ORDER BY d.last_seen_at DESC NULLS LAST, d.id
		LIMIT $6 OFFSET $7
	`, tenantID, q, pattern, stripped, strings.TrimSpace(groupID), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var devices []Device
	total := 0
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.OS, &d.OSVersion,
			&d.IPAddress, &d.Status, &d.LastSeenAt, &d.CreatedAt, &d.AgentVersion,
			&d.MACAddress, &d.SerialNumber, &d.PublicIP,
			&d.OutboxUnavailable, &d.DegradedDetail, &d.DegradedSince, &total); err != nil {
			return nil, 0, err
		}
		d.Groups = []DeviceGroupRef{}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := db.attachDeviceGroups(ctx, devices); err != nil {
		return nil, 0, err
	}
	return devices, total, nil
}

// attachDeviceGroups заполняет Device.Groups ОДНИМ запросом на всю страницу (было бы
// 1+N, если спрашивать по устройству). Пустой список устройств — сразу выход, иначе
// ANY('{}') сходил бы в БД впустую.
func (db *DB) attachDeviceGroups(ctx context.Context, devices []Device) error {
	if len(devices) == 0 {
		return nil
	}
	ids := make([]string, len(devices))
	byID := make(map[string]*Device, len(devices))
	for i := range devices {
		ids[i] = devices[i].ID
		byID[devices[i].ID] = &devices[i]
	}
	// Q(ctx), а НЕ db.pool: оба вызывающих уже держат скоуп тенанта, а запрос идёт по
	// двум таблицам под RLS. Через пул он брал соседнее соединение, на котором
	// routineops.tenant_id остался ПУСТОЙ СТРОКОЙ: кастомный GUC после
	// транзакционного set_config(...,true) возвращается не в «не задан», а в '', и
	// предикат 046 падает на ''::uuid. Итог на проде 30.07 — GET /api/v1/devices
	// отдавал 500 для всей панели, хотя сам список устройств был корректен.
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT m.device_id, g.id, g.name, g.color
		FROM device_group_members m
		JOIN device_groups g ON g.id = m.group_id
		WHERE m.device_id = ANY($1::uuid[])
		ORDER BY g.name
	`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var deviceID string
		var ref DeviceGroupRef
		if err := rows.Scan(&deviceID, &ref.ID, &ref.Name, &ref.Color); err != nil {
			return err
		}
		if d := byID[deviceID]; d != nil {
			d.Groups = append(d.Groups, ref)
		}
	}
	return rows.Err()
}

// ---- Users ----

// LookupUserEmail возвращает email по PK без скоупа тенанта. Нужен reset-flow: JWT ещё нет,
// а тенант неизвестен. Не использовать для panel list/get.
func (db *DB) LookupUserEmail(ctx context.Context, id string) (string, bool, error) {
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return "", false, scopeErr
	}
	defer finish(true)
	var email string
	err := db.Scoped(ctx).QueryRow(ctx, `SELECT email FROM users WHERE id::text = $1`, id).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return email, true, nil
}

// GetUserByID ищет по id::text, а не по id: до появления ручки удаления функцию звали
// только с идентификатором из проверенного JWT, а теперь в неё едет строка прямо из URL.
// Голое сравнение с uuid на кривом значении даёт 22P02 — то есть 500 вместо 404, и
// ловится это не глазами, а тестом на «not-a-uuid». Правка в общей функции, а не в
// вызывающем: остальным она не мешает, а следующий такой вызывающий появится незаметно.
func (db *DB) GetUserByID(ctx context.Context, tenantID, id string) (*User, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var u User
	err = db.Scoped(ctx).QueryRow(ctx, `
		SELECT id, identity_id, name, email, role, created_at FROM users
		WHERE tenant_id = $1 AND id::text = $2
	`, tenantID, id).Scan(&u.ID, &u.IdentityID, &u.Name, &u.Email, &u.Role, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (db *DB) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	rows, err := db.Scoped(ctx).Query(ctx, `
		SELECT id, identity_id, name, email, role, created_at FROM users
		WHERE tenant_id = $1 ORDER BY created_at
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.IdentityID, &u.Name, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ErrLastAdmin — попытка удалить последнего it_admin. Отдельная ошибка, а не просто
// «не удалилось»: оператору нужно объяснить причину, иначе отказ выглядит как баг.
var ErrLastAdmin = errors.New("last it_admin")

// AdminGuardLockKey — ключ advisory-локи, сериализующей удаление администраторов.
// Число произвольное, важна только уникальность в пределах базы.
//
// Экспортирован ради теста: тот берёт ЭТУ ЖЕ локу своим соединением и проверяет, что
// DeleteUser её ждёт. Косвенная проверка — «два параллельных удаления не снесли обоих» —
// была ложно-зелёной: она проходит и со снятой локой, потому что окно гонки узкое и
// две горутины в него попросту не попадают. Проверено снятием локи.
const AdminGuardLockKey = 4030407

// DeleteUser удаляет аккаунт панели. Возвращает false, если такого пользователя нет.
//
// 🔴 Проверка «последний администратор» и само удаление обязаны идти под локой. Без неё
// два параллельных удаления двух РАЗНЫХ администраторов каждое видит по два (чужая
// транзакция ещё не закоммичена), обе проходят — и в системе не остаётся ни одного
// администратора, то есть панель становится неуправляемой без доступа к БД. Лока
// сериализует именно эту пару операций; берётся на транзакцию и снимается сама.
//
// Что уезжает вместе с пользователем (по внешним ключам, миграции 012/029/040):
// сервисные токены и токены сброса пароля — CASCADE, приглашения и раскрытия эскроу —
// SET NULL (журнал переживает удаление), заявки на локальные права — SET NULL.
// Живые JWT умирают сами: jwtMiddleware отвергает токен, если пользователя больше нет.
func (db *DB) DeleteUser(ctx context.Context, tenantID, id string) (bool, error) {
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
	q := db.Scoped(ctx)

	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(AdminGuardLockKey)); err != nil {
		return false, err
	}

	// id::text — кривой UUID из URL иначе даёт 22P02 и превращается в 500 вместо 404.
	// Последний it_admin считается В ПРЕДЕЛАХ тенанта: чужой тенант не спасает от lockout.
	var role string
	err = q.QueryRow(ctx, `SELECT role FROM users WHERE tenant_id = $1 AND id::text = $2`, tenantID, id).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if role == "it_admin" {
		var admins int
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM users WHERE tenant_id = $1 AND role = 'it_admin'`, tenantID,
		).Scan(&admins); err != nil {
			return false, err
		}
		if admins <= 1 {
			return false, ErrLastAdmin
		}
	}

	tag, err := q.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1 AND id::text = $2`, tenantID, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// UserEpoch — то, что jwtMiddleware обязан перечитывать из БД на каждый запрос
// (ADR-6, ADR-7): тенант активного членства, момент последней смены пароля и
// признак надзора. Ничего из этого не лежит в JWT — иначе отзыв прав ждал бы
// истечения токена.
type UserEpoch struct {
	PasswordChangedAt time.Time
	TenantID          string
	IdentityID        string
	IsProviderAdmin   bool
}

// GetUserEpoch возвращает состояние членства по его user_id. nil, nil — членства
// больше нет (живой токен удалённого пользователя → jwtMiddleware отвергает).
//
// password_changed_at и is_provider_admin приходят с ЛИЧНОСТИ, а не с членства:
// пароль у человека один, поэтому его смена обязана гасить токены во всех
// тенантах сразу, а надзор не зависит от того, какой тенант сейчас активен.
func (db *DB) GetUserEpoch(ctx context.Context, userID string) (*UserEpoch, error) {
	var e UserEpoch
	err := db.pool.QueryRow(ctx,
		`SELECT password_changed_at, tenant_id::text, is_provider_admin, identity_id::text
		 FROM auth_user_password_epoch($1::uuid)`, userID,
	).Scan(&e.PasswordChangedAt, &e.TenantID, &e.IsProviderAdmin, &e.IdentityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ---- Invitations ----

type Invitation struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"-"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Token      string     `json:"token"`
	InvitedBy  *string    `json:"invited_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at"`
}

func (db *DB) CreateInvitation(ctx context.Context, tenantID, email, role, token, invitedBy string) (*Invitation, error) {
	tenantID, err := requireTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if _, ok := TxFrom(ctx); !ok {
		var finish func(bool)
		ctx, finish, err = db.BindTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		defer finish(true)
	}
	var inv Invitation
	err = db.Scoped(ctx).QueryRow(ctx, `
		INSERT INTO invitation_tokens (tenant_id, email, role, token, invited_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, email, role, token, invited_by, created_at, expires_at, accepted_at
	`, tenantID, email, role, token, invitedBy).
		Scan(&inv.ID, &inv.Email, &inv.Role, &inv.Token, &inv.InvitedBy,
			&inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt)
	return &inv, err
}

func (db *DB) GetInvitationByToken(ctx context.Context, token string) (*Invitation, error) {
	var inv Invitation
	err := db.pool.QueryRow(ctx, `
		SELECT id, tenant_id::text, email, role, token, invited_by, created_at, expires_at, accepted_at
		FROM auth_invitation_by_token($1)
	`, token).Scan(&inv.ID, &inv.TenantID, &inv.Email, &inv.Role, &inv.Token, &inv.InvitedBy,
		&inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &inv, nil
}

func (db *DB) AcceptInvitation(ctx context.Context, token string) error {
	inv, err := db.GetInvitationByToken(ctx, token)
	if err != nil {
		return err
	}
	if inv == nil {
		return nil
	}
	ctx, finish, err := db.BindTenant(ctx, inv.TenantID)
	if err != nil {
		return err
	}
	defer finish(true)
	_, err = db.Scoped(ctx).Exec(ctx, `
		UPDATE invitation_tokens SET accepted_at = now() WHERE token = $1
	`, token)
	return err
}

// ---- Password reset ----

type PasswordResetToken struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"-"`
	UserID    string     `json:"user_id"`
	Token     string     `json:"token"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
}

// CreatePasswordResetToken заводит одноразовый токен сброса пароля.
//
// Скоуп по пользователю обязателен: таблица тенантская, и вставка без привязанного
// тенанта не проходит `WITH CHECK` предиката 046 — то есть токен НЕ создаётся.
// Полевой e2e 30.07: письмо со ссылкой при этом уходило (ошибку вставки вызывающий
// отбрасывал), а сброс потом отвечал «invalid or expired token» — пользователь видел
// «ссылка истекла» на ссылку, которой никогда не существовало.
func (db *DB) CreatePasswordResetToken(ctx context.Context, userID, token string) error {
	ctx, finish, err := db.bindTenantForUser(ctx, userID)
	if err != nil {
		return err
	}
	defer finish(true)

	_, err = db.Scoped(ctx).Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, token) VALUES ($1, $2)
	`, userID, token)
	return err
}

func (db *DB) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	var t PasswordResetToken
	err := db.pool.QueryRow(ctx, `
		SELECT id, user_id, tenant_id::text, token, created_at, expires_at, used_at
		FROM auth_password_reset_by_token($1)
	`, token).Scan(&t.ID, &t.UserID, &t.TenantID, &t.Token, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

func (db *DB) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	tok, err := db.GetPasswordResetToken(ctx, token)
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	ctx, finish, err := db.BindTenant(ctx, tok.TenantID)
	if err != nil {
		return err
	}
	defer finish(true)
	_, err = db.Scoped(ctx).Exec(ctx, `
		UPDATE password_reset_tokens SET used_at = now() WHERE token = $1
	`, token)
	return err
}

// CleanupOldData чистит устаревшие записи. Операционные данные (alerts, script_results)
// — по dataRetentionDays; audit_log — по отдельному auditRetentionDays (журнал
// безопасности хранится дольше). Для любого срока 0/отриц = хранить бессрочно.
func (db *DB) CleanupOldData(ctx context.Context, dataRetentionDays, auditRetentionDays int, archiveDir string) (int64, error) {
	// Retention гоняется по тенантам (ForEachTenant в cmd/server), и скоуп обычно уже
	// открыт выше. Свой открываем на случай прямого вызова: чистка мимо скоупа удалила
	// бы ноль строк и отчиталась бы «удалено 0» — то есть выглядела бы как «мусора нет».
	ctx, finish, _, scopeErr := db.scopeFor(ctx, "")
	if scopeErr != nil {
		return 0, scopeErr
	}
	defer finish(true)
	var total int64
	purge := func(table, extraWhere string, days int) error {
		if days <= 0 {
			return nil
		}
		cutoff := time.Now().AddDate(0, 0, -days)
		q := `DELETE FROM ` + table + ` WHERE created_at < $1`
		if extraWhere != "" {
			q += ` AND ` + extraWhere
		}
		res, err := db.Scoped(ctx).Exec(ctx, q, cutoff)
		if err != nil {
			return fmt.Errorf("cleanup %s: %w", table, err)
		}
		total += res.RowsAffected()
		return nil
	}
	// НЕпринятые алерты retention НЕ трогает: (1) оператор их ещё не видел — молча
	// удалять сигнал нельзя; (2) непринятый agent_unreachable мёртвого устройства служит
	// ЯКОРЕМ дедупа в DetectUnreachableDevices — удалив его, retention заставлял бы то же
	// мёртвое устройство пере-алертить каждый период хранения и сбрасывать acknowledged.
	if err := purge("alerts", "acknowledged_at IS NOT NULL", dataRetentionDays); err != nil {
		return total, err
	}
	if err := purge("script_results", "", dataRetentionDays); err != nil {
		return total, err
	}
	if auditRetentionDays > 0 {
		// 🔴 FAIL-CLOSED: чистим журнал ТОЛЬКО если есть куда его выгрузить. Иначе
		// tamper-evident цепочка, ради которой она и строилась, умирала бы по
		// расписанию — а выглядело бы это как штатная работа retention. Отсутствие
		// AUDIT_ARCHIVE_DIR при заданном AUDIT_RETENTION_DAYS — ошибка конфигурации,
		// и молчать о ней нельзя: удалённые улики не восстанавливаются.
		if archiveDir == "" {
			return total, fmt.Errorf(
				"audit retention %d дней задан, а AUDIT_ARCHIVE_DIR пуст: журнал НЕ чищен, "+
					"иначе записи удалились бы без архива", auditRetentionDays)
		}
		cutoff := time.Now().AddDate(0, 0, -auditRetentionDays)
		if err := db.archiveAuditLogs(ctx, cutoff, archiveDir); err != nil {
			return total, fmt.Errorf("archive audit logs: %w", err)
		}
		if err := purge("audit_log", "", auditRetentionDays); err != nil {
			return total, err
		}
	}
	// Улики сессии админ-прав — по сроку аудита, не DataRetentionDays (контракт §5.2).
	if err := purge("admin_session_changes", "", auditRetentionDays); err != nil {
		return total, err
	}
	// Журнал ввода в сеансах с управлением — тоже по сроку аудита (§9.21 п.1 дословно).
	// Не по DataRetentionDays и не по сроку записей сеансов: запись показывает, что было
	// на экране, а этот журнал — что делал оператор под учётной записью сотрудника. Второе
	// нужно в кадровом разборе ровно тогда, когда первое уже удалено ретеншеном записей.
	if err := purge("screen_input_events", "", auditRetentionDays); err != nil {
		return total, err
	}
	return total, nil
}

// CreateFileVaultProvisionTask ставит задачу дозавершения provisioning FileVault.
//
// Оператор-путь взамен «зайти в терминал каждого мака и ввести пароль»: раскаткой это
// не является, а без пароля держателя Secure Token ключ восстановления не получить.
// Задача доезжает до агента обычным каналом, а пароль он запрашивает у сотрудника
// через трей — служба сама его взять не может и не должна.
//
// Как и перезагрузка, задача одна на устройство: ON CONFLICT DO NOTHING, повторный
// вызов отдаёт уже стоящую в очереди. Иначе нетерпеливый оператор насоздавал бы
// очередь диалогов, которые вылезут сотруднику один за другим.
func (db *DB) CreateFileVaultProvisionTask(ctx context.Context, deviceID, reason string) (*Task, error) {
	ctx, finish, err := db.BindTenantForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer finish(true)
	if err := db.assertAgentSupports(ctx, deviceID, "filevault_provision"); err != nil {
		return nil, err
	}

	const cols = `id, device_id, script_content, platform, priority, status, created_at, task_type,
	              lock_hash, lock_reason, lock_unlock, lock_mode, reboot_reason, reboot_delay_seconds`
	scan := func(row pgx.Row, t *Task) error {
		return row.Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status,
			&t.CreatedAt, &t.TaskType, &t.LockHash, &t.LockReason, &t.LockUnlock, &t.LockMode,
			&t.RebootReason, &t.RebootDelaySeconds)
	}

	var t Task
	err = scan(db.Scoped(ctx).QueryRow(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status, task_type, reboot_reason, tenant_id)
  SELECT $1, '', COALESCE(d.os, 'unknown'), 'normal', 'pending', 'filevault_provision', $2, d.tenant_id
  FROM devices d WHERE d.id = $1
  ON CONFLICT DO NOTHING
  RETURNING `+cols, deviceID, reason), &t)
	if err == nil {
		return &t, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	err = scan(db.Scoped(ctx).QueryRow(ctx, `
  SELECT `+cols+` FROM tasks
  WHERE device_id = $1 AND task_type = 'filevault_provision' AND status = 'pending'`, deviceID), &t)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
