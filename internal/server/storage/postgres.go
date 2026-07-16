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

type User struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

func (db *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	err := db.pool.QueryRow(ctx, `
		SELECT id, name, email, password_hash, role, created_at
		FROM users WHERE email = $1
	`, email).Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (db *DB) GetITAdminsWithTelegramChatID(ctx context.Context) ([]string, error) {
	rows, err := db.pool.Query(ctx, `
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

func (db *DB) SetUserTelegramChatID(ctx context.Context, userID, chatID string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE users SET telegram_chat_id = $1 WHERE id = $2`, chatID, userID)
	return err
}

func (db *DB) GetUserByLinkToken(ctx context.Context, token string) (*User, error) {
	var u User
	err := db.pool.QueryRow(ctx, `
		SELECT id, name, email, password_hash, role, created_at
		FROM users WHERE telegram_link_token = $1`, token).
		Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (db *DB) SetUserLinkToken(ctx context.Context, userID, token string) error {
	var err error
	if token == "" {
		_, err = db.pool.Exec(ctx, `UPDATE users SET telegram_link_token = NULL WHERE id = $1`, userID)
	} else {
		_, err = db.pool.Exec(ctx, `UPDATE users SET telegram_link_token = $1 WHERE id = $2`, token, userID)
	}
	return err
}

func (db *DB) GetUserTelegramStatus(ctx context.Context, userID string) (chatID *string, linkToken *string, err error) {
	err = db.pool.QueryRow(ctx, `
		SELECT telegram_chat_id, telegram_link_token FROM users WHERE id = $1`, userID).
		Scan(&chatID, &linkToken)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	return chatID, linkToken, err
}

func (db *DB) GetDeviceHostname(ctx context.Context, deviceID string) (string, error) {
	var hostname string
	err := db.pool.QueryRow(ctx, `SELECT hostname FROM devices WHERE id = $1`, deviceID).Scan(&hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		return deviceID[:8], nil
	}
	return hostname, err
}

func (db *DB) CreateUser(ctx context.Context, name, email, passwordHash, role string) (*User, error) {
	var u User
	err := db.pool.QueryRow(ctx, `
		INSERT INTO users (name, email, password_hash, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, email, password_hash, role, created_at
	`, name, email, passwordHash, role).
		Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	return &u, err
}

type Device struct {
	ID           string     `json:"id"`
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	OSVersion    string     `json:"os_version"`
	IPAddress    string     `json:"ip_address"`
	Status       string     `json:"status"`
	LockStatus   string     `json:"lock_status"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	CreatedAt    time.Time  `json:"created_at"`
	CertCN       string     `json:"cert_cn"`
	EnrolledAt   *time.Time `json:"enrolled_at"`
	CPU          string     `json:"cpu"`
	RAM          int64      `json:"ram_mb"`
	Disk         string     `json:"disk"`
	MACAddress   string     `json:"mac_address"`
	SerialNumber string     `json:"serial_number"`
	PublicIP     string     `json:"public_ip"`
	AgentVersion string     `json:"agent_version"`
	// Устройство может состоять в НЕСКОЛЬКИХ группах (device_group_members — m2m),
	// поэтому это список, а не одна ссылка. Первая группа задаёт цвет рамки в UI.
	Groups []DeviceGroupRef `json:"groups"`
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

func (db *DB) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, hostname, os, COALESCE(os_version, ''), COALESCE(ip_address, ''),
		       status, last_seen_at, created_at, COALESCE(agent_version, '')
		FROM devices ORDER BY last_seen_at DESC NULLS LAST
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.OS, &d.OSVersion,
			&d.IPAddress, &d.Status, &d.LastSeenAt, &d.CreatedAt, &d.AgentVersion); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// UpsertDeviceHeartbeat создаёт устройство при первом подключении или обновляет last_seen_at/ip.
// hostname = device_id (CN сертификата) до тех пор, пока не придёт ReportInventory.
// Heartbeat переводит enrolled→active И pending→active: раз пришёл heartbeat с валидным
// certificate_fingerprint — энролл фактически состоялся, значит устройство живое и должно
// быть видимым в списке (ListEnrolledDevices прячет pending). Иначе реенролл со старым
// сертификатом (fingerprint совпал, свежий токен не использован) навсегда оставлял бы
// живой девайс в pending. Прочие статусы (blocked) НЕ трогаем — иначе heartbeat молча
// снимал бы блокировку у подключённого устройства.

func (db *DB) UpsertDeviceHeartbeat(ctx context.Context, d HeartbeatData) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO devices (hostname, os, ip_address, public_ip, status, certificate_fingerprint, cert_cn, last_seen_at)
        VALUES ($1, 'unknown', $2, NULLIF($5,''), 'active', $3, $4, now())
		ON CONFLICT (certificate_fingerprint)
		DO UPDATE SET ip_address = $2, public_ip = COALESCE(NULLIF($5,''), devices.public_ip), last_seen_at = now(), cert_cn = $4,
			status = CASE WHEN devices.status IN ('enrolled', 'pending') THEN 'active' ELSE devices.status END
	`, d.DeviceID, d.IPAddress, d.CertFingerprint, d.CertCN, d.PublicIP)
	return err
}

type SoftwareItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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
}

type HeartbeatData struct {
	CertFingerprint string
	PublicIP        string
	DeviceID        string
	CertCN          string
	IPAddress       string
}

// UpsertInventory обновляет поля устройства и заменяет список ПО атомарно.
// Устройство должно уже существовать (создаётся при первом heartbeat).
func (db *DB) UpsertInventory(ctx context.Context, d InventoryData) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var deviceID string
	err = tx.QueryRow(ctx, `
		UPDATE devices
		SET hostname = $1, os = $2, os_version = $3, cpu = $4,
		    ram = $5, disk = $6, ip_address = $7,
		    mac_address = COALESCE(NULLIF($9,''), devices.mac_address),
		    serial_number = COALESCE(NULLIF($10,''), devices.serial_number),
		    agent_version = COALESCE(NULLIF($11,''), devices.agent_version),
		    last_seen_at = now()
		WHERE certificate_fingerprint = $8
		RETURNING id
	`, d.Hostname, d.OS, d.OSVersion, d.CPU, d.RAM, d.Disk, d.IPAddress, d.CertFingerprint, d.MACAddress, d.SerialNumber, d.AgentVersion).
		Scan(&deviceID)
	if err != nil {
		return fmt.Errorf("update device: %w", err)
	}

	if _, err = tx.Exec(ctx, `DELETE FROM device_software WHERE device_id = $1`, deviceID); err != nil {
		return fmt.Errorf("delete old software: %w", err)
	}

	for _, s := range d.Software {
		if _, err = tx.Exec(ctx, `
			INSERT INTO device_software (device_id, software_name, version)
			VALUES ($1, $2, $3)
		`, deviceID, s.Name, s.Version); err != nil {
			return fmt.Errorf("insert software %q: %w", s.Name, err)
		}
	}

	return tx.Commit(ctx)
}

func (db *DB) GetDevice(ctx context.Context, id string) (*Device, []SoftwareItem, error) {
	var d Device
	err := db.pool.QueryRow(ctx, `
  SELECT id, hostname, os, COALESCE(os_version, ''), COALESCE(ip_address, ''),
         status, COALESCE(lock_status, 'unlocked'), last_seen_at, created_at,
         COALESCE(cert_cn, ''), enrolled_at,
         COALESCE(cpu, ''), COALESCE(ram, 0), COALESCE(disk, ''),
       COALESCE(mac_address, ''), COALESCE(serial_number, ''), COALESCE(public_ip, ''),
       COALESCE(agent_version, '')
  FROM devices WHERE id = $1
 `, id).Scan(&d.ID, &d.Hostname, &d.OS, &d.OSVersion,
		&d.IPAddress, &d.Status, &d.LockStatus, &d.LastSeenAt, &d.CreatedAt,
		&d.CertCN, &d.EnrolledAt, &d.CPU, &d.RAM, &d.Disk, &d.MACAddress, &d.SerialNumber, &d.PublicIP,
		&d.AgentVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	d.Groups = []DeviceGroupRef{}
	groups, err := db.pool.Query(ctx, `
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

	rows, err := db.pool.Query(ctx, `
  SELECT software_name, COALESCE(version, '')
  FROM device_software WHERE device_id = $1
  ORDER BY software_name
 `, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var software []SoftwareItem
	for rows.Next() {
		var s SoftwareItem
		if err := rows.Scan(&s.Name, &s.Version); err != nil {
			return nil, nil, err
		}
		software = append(software, s)
	}
	return &d, software, rows.Err()
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
}

// Режимы блокировки (совпадают с CHECK-домены значений lock_mode в 022 и с
// proto LockMode). Пустая строка/unknown = overlay (fail-safe: НИКОГДА не деструктив).
const (
	LockModeOverlay   = "overlay"
	LockModeFileVault = "filevault"
)

func (db *DB) CreateTask(ctx context.Context, deviceID, scriptContent, platform, priority string) (*Task, error) {
	var t Task
	err := db.pool.QueryRow(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status)
  VALUES ($1, $2, $3, $4, 'pending')
  RETURNING id, device_id, script_content, platform, priority, status, created_at
 `, deviceID, scriptContent, platform, priority).
		Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.CreatedAt)
	return &t, err
}

// ErrTaskNotOwned — задача не принадлежит вызывающему устройству (или не существует).
// Возвращается Ack/CompleteTask, когда task_id + device_id не дают строки: без скоупинга
// по device_id одно устройство могло Ack'нуть/зарепортить задачу ЧУЖОГО (BOLA/IDOR) —
// тихо подавить доставку lock/remediation-команды или подделать её «успех».
var ErrTaskNotOwned = errors.New("task not found for this device")

func (db *DB) AckTask(ctx context.Context, taskID, deviceID string) error {
	tag, err := db.pool.Exec(ctx,
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

func (db *DB) CompleteTask(ctx context.Context, taskID, deviceID, status, output, errLog string) error {
	tag, err := db.pool.Exec(ctx, `
  UPDATE tasks
  SET status = $3, output = $4, error_log = $5, completed_at = now()
  WHERE id = $1 AND device_id = $2
 `, taskID, deviceID, status, output, errLog)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTaskNotOwned
	}
	return nil
}

func (db *DB) GetDeviceCN(ctx context.Context, deviceID string) (string, error) {
	var cn string
	err := db.pool.QueryRow(ctx,
		`SELECT COALESCE(cert_cn, '') FROM devices WHERE id = $1`, deviceID).Scan(&cn)
	return cn, err
}

func (db *DB) CreateLockTask(ctx context.Context, deviceID, lockHash, lockReason string, unlock bool, lockMode string) (*Task, error) {
	if lockMode == "" {
		lockMode = LockModeOverlay // fail-safe
	}
	var t Task
	err := db.pool.QueryRow(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status, task_type, lock_hash, lock_reason, lock_unlock, lock_mode)
  VALUES ($1, '', COALESCE((SELECT os FROM devices WHERE id = $1), 'unknown'), 'high', 'pending', 'lock', $2, $3, $4, $5)
  RETURNING id, device_id, script_content, platform, priority, status, created_at, task_type, lock_hash, lock_reason, lock_unlock, lock_mode
 `, deviceID, lockHash, lockReason, unlock, lockMode).
		Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.CreatedAt, &t.TaskType, &t.LockHash, &t.LockReason, &t.LockUnlock, &t.LockMode)
	return &t, err
}

func (db *DB) UpdateDeviceLockStatus(ctx context.Context, deviceID, lockStatus string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE devices SET lock_status = $2 WHERE id = $1`, deviceID, lockStatus)
	return err
}

func (db *DB) GetDeviceLockStatus(ctx context.Context, deviceID string) (string, error) {
	var s string
	err := db.pool.QueryRow(ctx, `SELECT lock_status FROM devices WHERE id = $1`, deviceID).Scan(&s)
	return s, err
}

// SetDeviceLockState записывает ЖЕЛАЕМОЕ состояние блокировки (авторитетное намерение
// админа) — статус, bcrypt-хеш пароля, причину и режим. Вызывается эндпоинтами
// lock/unlock. Это источник правды для реконсиляции FetchLockStatus: агент поллит и
// сводит к нему локальный lock.json (переживает потерю unlock-ack и ребут — push-канал
// их терял). При unlock hash/reason очищаются, режим сбрасывается в overlay (fail-safe:
// снятый лок НИКОГДА не остаётся в filevault-намерении).
func (db *DB) SetDeviceLockState(ctx context.Context, deviceID, lockStatus, lockHash, lockReason, lockMode string) error {
	if lockMode == "" {
		lockMode = LockModeOverlay
	}
	_, err := db.pool.Exec(ctx,
		`UPDATE devices SET lock_status = $2, lock_hash = $3, lock_reason = $4, lock_mode = $5 WHERE id = $1`,
		deviceID, lockStatus, lockHash, lockReason, lockMode)
	return err
}

// SetDeviceLockActualState записывает REPORTED состояние лока (что агент фактически
// сделал), НЕ трогая desired (lock_status/hash/reason). Колонка заведена в 022 ровно
// затем, чтобы filevault half-state (FILEVAULT_REVOKED: токен снят, ребут ещё не
// сделан) не портил desired — иначе реконсайлер отменил бы/повторил бы деструктив
// (класс полевого re-lock-бага).
func (db *DB) SetDeviceLockActualState(ctx context.Context, deviceID, state string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE devices SET lock_actual_state = $2, lock_actual_at = now() WHERE id = $1`,
		deviceID, state)
	return err
}

// GetDesiredLockState возвращает желаемое состояние блокировки устройства для отдачи
// агенту (FetchLockStatus). Пустой lock_status трактуется вызывающим как "unlocked".
// lockMode пустой/NULL → overlay (fail-safe).
func (db *DB) GetDesiredLockState(ctx context.Context, deviceID string) (lockStatus, lockHash, lockReason, lockMode string, err error) {
	err = db.pool.QueryRow(ctx,
		`SELECT COALESCE(lock_status,''), COALESCE(lock_hash,''), COALESCE(lock_reason,''), COALESCE(NULLIF(lock_mode,''),'overlay') FROM devices WHERE id = $1`,
		deviceID).Scan(&lockStatus, &lockHash, &lockReason, &lockMode)
	return lockStatus, lockHash, lockReason, lockMode, err
}

// FileVault recovery-escrow (StoreRecoveryKeyEscrow + ErrEscrowConflict) вынесено
// в enterprise-оверлей (internal/server/escrow, //go:build enterprise) — open-core
// его не содержит. Enterprise делает свой INSERT в recovery_key_escrow через DB.Pool().

func (db *DB) GetTask(ctx context.Context, taskID string) (*Task, error) {
	var t Task
	err := db.pool.QueryRow(ctx, `
  SELECT id, device_id, script_content, platform, priority, status, output, error_log, created_at,
         task_type, lock_hash, lock_reason, lock_unlock, lock_mode
FROM tasks WHERE id = $1
 `, taskID).Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.Output, &t.ErrorLog, &t.CreatedAt,
		&t.TaskType, &t.LockHash, &t.LockReason, &t.LockUnlock, &t.LockMode)
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
	rows, err := db.pool.Query(ctx, `
		SELECT t.id, d.cert_cn
		FROM tasks t
		JOIN devices d ON d.id = t.device_id
		WHERE t.status = 'pending' AND COALESCE(d.cert_cn, '') <> ''
		ORDER BY t.created_at
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []PendingTaskRef
	for rows.Next() {
		var ref PendingTaskRef
		if err := rows.Scan(&ref.TaskID, &ref.DeviceCN); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

func (db *DB) GetPendingTasks(ctx context.Context, deviceID string) ([]Task, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

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
	return tasks, tx.Commit(ctx)
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
	var deviceID *string
	var deviceOS string
	if err := db.pool.QueryRow(ctx,
		`SELECT id, COALESCE(os, '') FROM devices WHERE certificate_fingerprint = $1`, fingerprint,
	).Scan(&deviceID, &deviceOS); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			// Реальная ошибка БД: не деградируем молча до global-only политики —
			// иначе device-specific forbidden-правила перестают применяться (F-5).
			return nil, fmt.Errorf("lookup device by fingerprint: %w", err)
		}
		// Устройство не найдено — применяем только глобальные правила.
		deviceID = nil
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

	rows, err := db.pool.Query(ctx, query, args...)
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
	var status string
	err := db.pool.QueryRow(ctx,
		`SELECT COALESCE(status, '') FROM devices WHERE certificate_fingerprint = $1`, fingerprint,
	).Scan(&status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return status, nil
}

func (db *DB) UpdateDeviceStatus(ctx context.Context, deviceID, status string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE devices SET status = $2 WHERE id = $1`, deviceID, status)
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
func (db *DB) DeleteDevice(ctx context.Context, id string) (found bool, err error) {
	tag, err := db.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1`, id)
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
// cooldownMinutes<=0 отключает второй клоз. Возвращает число созданных.
func (db *DB) DetectUnreachableDevices(ctx context.Context, thresholdMinutes, cooldownMinutes int) (int64, error) {
	if thresholdMinutes <= 0 {
		return 0, nil
	}
	res, err := db.pool.Exec(ctx, `
		INSERT INTO alerts (device_id, alert_type, details)
		SELECT d.id, 'agent_unreachable',
		       'Не выходит на связь с ' || to_char(d.last_seen_at, 'YYYY-MM-DD HH24:MI')
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
	`, thresholdMinutes, cooldownMinutes)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
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
	tag, err := db.pool.Exec(ctx, `
  INSERT INTO alerts (device_id, alert_type, details, admin_access_request_id)
  SELECT $1::uuid, $2::text, $3::text,
    (SELECT r.id FROM admin_access_requests r WHERE r.id = $4::uuid AND r.device_id = $1::uuid)
  WHERE NOT EXISTS (
    SELECT 1 FROM alerts a
    WHERE a.device_id = $1::uuid AND a.alert_type = $2::text
      AND a.details = $3::text AND a.acknowledged_at IS NULL
  )
 `, deviceID, alertType, details, adminReqID)
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
	Details        string     `json:"details"`
	CreatedAt      time.Time  `json:"created_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
}

func (db *DB) ListAlerts(ctx context.Context, deviceID string, limit int) ([]Alert, error) {
	query := `
  SELECT a.id, a.device_id, COALESCE(d.hostname, ''), a.alert_type, a.details, a.created_at, a.acknowledged_at
  FROM alerts a
  LEFT JOIN devices d ON d.id = a.device_id`
	// Непринятые ПЕРВЫМИ: фронт тянет один список и фильтрует «новые» клиентски, поэтому
	// при простой сортировке по дате непринятый алерт старше LIMIT-й строки молча выпадал
	// из выборки (и из счётчика «новых»), вытесненный более свежими ПРИНЯТЫМИ. Сортировка
	// (acknowledged_at IS NULL) DESC держит все непринятые в голове списка.
	order := ` ORDER BY (a.acknowledged_at IS NULL) DESC, a.created_at DESC`
	args := []any{}
	if deviceID != "" {
		query += ` WHERE a.device_id = $1` + order + ` LIMIT $2`
		args = append(args, deviceID, limit)
	} else {
		query += order + ` LIMIT $1`
		args = append(args, limit)
	}
	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.DeviceHostname, &a.AlertType, &a.Details, &a.CreatedAt, &a.AcknowledgedAt); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func (db *DB) AcknowledgeAlert(ctx context.Context, alertID string) error {
	tag, err := db.pool.Exec(ctx, `
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

func (db *DB) ListPolicyRules(ctx context.Context) ([]PolicyRuleRow, error) {
	rows, err := db.pool.Query(ctx, `
  SELECT id, software_name, rule_type, device_id, group_id, platforms, updated_at
  FROM software_policy_rules ORDER BY updated_at DESC
 `)
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

func (db *DB) CreatePolicyRule(ctx context.Context, softwareName, ruleType string, deviceID *string, platforms []string) (*PolicyRuleRow, error) {
	var r PolicyRuleRow
	var plat interface{} // nil → NULL (правило на всех платформах)
	if len(platforms) > 0 {
		plat = platforms
	}
	err := db.pool.QueryRow(ctx, `
  INSERT INTO software_policy_rules (software_name, rule_type, device_id, platforms)
  VALUES ($1, $2, $3, $4)
  RETURNING id, software_name, rule_type, device_id, group_id, platforms, updated_at
 `, softwareName, ruleType, deviceID, plat).
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

func (db *DB) DeletePolicyRule(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx, `DELETE FROM software_policy_rules WHERE id = $1`, id)
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
func (db *DB) ListSoftwarePolicyCompliance(ctx context.Context) ([]SoftwarePolicyCompliance, error) {
	rows, err := db.pool.Query(ctx, `
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
			  ON d.status <> 'pending'
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
		GROUP BY r.id
	`)
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
// MatchedSoftware/MatchedVersion — первое совпадение по алфавиту ("" когда
// совпадений нет): для ответа «почему fail» достаточно одного примера.
type SoftwarePolicyDeviceCompliance struct {
	DeviceID        string `json:"device_id"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	Status          string `json:"status"`
	Installed       bool   `json:"installed"`
	MatchedSoftware string `json:"matched_software"`
	MatchedVersion  string `json:"matched_version"`
}

// ListSoftwarePolicyDeviceCompliance — те же область действия и матчер, что у
// ListSoftwarePolicyCompliance (глобальное ∪ device-оверрайд ∪ группа, платформенный
// фильтр с fail-safe, регистронезависимая подстрока), но без агрегации: по строке на
// каждое устройство в области правила. Нарушители первыми, дальше по hostname.
func (db *DB) ListSoftwarePolicyDeviceCompliance(ctx context.Context, ruleID string) ([]SoftwarePolicyDeviceCompliance, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT d.id, d.hostname, COALESCE(d.os, ''), d.status,
		       m.software_name IS NOT NULL AS installed,
		       COALESCE(m.software_name, ''), COALESCE(m.version, '')
		FROM software_policy_rules r
		JOIN devices d
		  ON d.status <> 'pending'
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
		    SELECT s.software_name, s.version
		    FROM device_software s
		    WHERE s.device_id = d.id
		      AND r.software_name <> ''
		      AND strpos(lower(s.software_name), lower(r.software_name)) > 0
		    ORDER BY lower(s.software_name)
		    LIMIT 1
		) m ON true
		-- id::text, а не id = $1: ruleID приходит сырым из URL, мусор вместо UUID
		-- дал бы 22P02 → 500; с ::text он просто ничего не находит (конвенция GetScript).
		WHERE r.id::text = $1
		ORDER BY installed DESC, lower(d.hostname)
	`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SoftwarePolicyDeviceCompliance
	for rows.Next() {
		var c SoftwarePolicyDeviceCompliance
		if err := rows.Scan(&c.DeviceID, &c.Hostname, &c.OS, &c.Status,
			&c.Installed, &c.MatchedSoftware, &c.MatchedVersion); err != nil {
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
func (db *DB) ListScriptPolicyCompliance(ctx context.Context) ([]ScriptPolicyCompliance, error) {
	rows, err := db.pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (device_id, policy_id) policy_id, device_id, exit_code
			FROM script_results
			ORDER BY device_id, policy_id, created_at DESC
		), assigned AS (
			SELECT DISTINCT pa.policy_id, m.device_id
			FROM policy_assignments pa
			JOIN device_group_members m ON m.group_id = pa.group_id
			JOIN devices d ON d.id = m.device_id AND d.status <> 'pending'
		)
		SELECT p.id,
		       count(a.device_id)                                        AS in_scope,
		       count(l.device_id) FILTER (WHERE l.exit_code = 0)         AS pass,
		       count(l.device_id) FILTER (WHERE l.exit_code <> 0)        AS fail
		FROM policies p
		LEFT JOIN assigned a ON a.policy_id = p.id
		LEFT JOIN latest   l ON l.policy_id = p.id AND l.device_id = a.device_id
		GROUP BY p.id
	`)
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

func (db *DB) GetDeviceIDByFingerprint(ctx context.Context, fingerprint string) (string, error) {
	var id string
	err := db.pool.QueryRow(ctx,
		`SELECT id FROM devices WHERE certificate_fingerprint = $1`, fingerprint).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
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

func (db *DB) GetSystemSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := db.pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = $1`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return value, nil
}

// GetDeviceOwner returns (deviceID, ownerID) by certificate fingerprint.
// ownerID is empty string when owner_id IS NULL.
func (db *DB) GetDeviceOwner(ctx context.Context, fingerprint string) (deviceID, ownerID string, err error) {
	err = db.pool.QueryRow(ctx,
		`SELECT id, COALESCE(owner_id::text, '') FROM devices WHERE certificate_fingerprint = $1`,
		fingerprint).Scan(&deviceID, &ownerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", nil
		}
		return "", "", err
	}
	return deviceID, ownerID, nil
}

func (db *DB) CreateAdminAccessRequest(ctx context.Context, deviceID, requestedBy, reason string, requestedAt, pendingExpiresAt time.Time) (*AdminAccessRequest, error) {
	var r AdminAccessRequest
	err := db.pool.QueryRow(ctx, `
		INSERT INTO admin_access_requests (device_id, requested_by, reason, requested_at, pending_expires_at)
		VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5)
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
	var r AdminAccessRequest
	err := db.pool.QueryRow(ctx, `
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
func (db *DB) UpdateAdminAccessReport(ctx context.Context, requestID, deviceID, status string, occurredAt time.Time) error {
	var q string
	if status == "approved" {
		q = `UPDATE admin_access_requests SET granted_at = $2 WHERE id = $1 AND device_id = $3 AND granted_at IS NULL`
	} else {
		q = `UPDATE admin_access_requests SET status = 'revoked', revoked_at = $2 WHERE id = $1 AND device_id = $3`
	}
	tag, err := db.pool.Exec(ctx, q, requestID, occurredAt, deviceID)
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
	_, err := db.pool.Exec(ctx, `
		UPDATE admin_access_requests
		SET status = $2, decided_by = $3, decided_at = now(), expires_at = $4
		WHERE id = $1 AND status = 'pending'
	`, requestID, decision, decidedByUserID, expiresAt)
	return err
}

func (db *DB) RevokeAdminAccessRequest(ctx context.Context, requestID string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE admin_access_requests SET status = 'revoked', revoked_at = NOW()
   WHERE id = $1 AND status = 'approved'`,
		requestID)
	return err
}

// ExpireStaleAdminRequests marks PENDING requests past their pending_expires_at
// and APPROVED requests past their expires_at as EXPIRED.
func (db *DB) ExpireStaleAdminRequests(ctx context.Context) (int64, error) {
	result, err := db.pool.Exec(ctx, `
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
}

func (db *DB) ListAdminAccessRequests(ctx context.Context, statusFilter string) ([]AdminAccessRequestRow, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT r.id, r.device_id, COALESCE(d.hostname, ''), COALESCE(r.requested_by::text, ''), COALESCE(u.email, ''),
		       r.status, COALESCE(r.reason, ''), r.requested_at, r.pending_expires_at,
		       r.decided_at, r.granted_at, r.expires_at, r.revoked_at
		FROM admin_access_requests r
		LEFT JOIN devices d ON d.id = r.device_id
		LEFT JOIN users u ON u.id = r.requested_by
		WHERE ($1 = '' OR r.status = $1)
		ORDER BY r.requested_at DESC
		LIMIT 100
	`, statusFilter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AdminAccessRequestRow
	for rows.Next() {
		var r AdminAccessRequestRow
		if err := rows.Scan(&r.ID, &r.DeviceID, &r.DeviceHostname, &r.RequestedBy, &r.RequesterEmail,
			&r.Status, &r.Reason, &r.RequestedAt, &r.PendingExpiresAt,
			&r.DecidedAt, &r.GrantedAt, &r.ExpiresAt, &r.RevokedAt); err != nil {
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

func (db *DB) ListScripts(ctx context.Context) ([]Script, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, name, platform, content, created_at, updated_at FROM scripts ORDER BY created_at DESC`)
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

func (db *DB) CreateScript(ctx context.Context, name, platform, content string) (*Script, error) {
	var s Script
	err := db.pool.QueryRow(ctx, `
		INSERT INTO scripts (name, platform, content)
		VALUES ($1, $2, $3)
		RETURNING id, name, platform, content, created_at, updated_at
	`, name, platform, content).Scan(&s.ID, &s.Name, &s.Platform, &s.Content, &s.CreatedAt, &s.UpdatedAt)
	return &s, err
}

func (db *DB) GetScript(ctx context.Context, id string) (*Script, error) {
	var s Script
	// id::text, а не id = $1: при кривом script_id (не UUID) сравнение с uuid-колонкой
	// падает 22P02 → handler отдавал 500 вместо 404. Через ::text несуществующий/кривой
	// id просто не находится → ErrNoRows → nil,nil → 404 (приём как у DeviceGroupExists).
	err := db.pool.QueryRow(ctx,
		`SELECT id, name, platform, content, created_at, updated_at FROM scripts WHERE id::text = $1`, id).
		Scan(&s.ID, &s.Name, &s.Platform, &s.Content, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

func (db *DB) UpdateScript(ctx context.Context, id, name, platform, content string) (*Script, error) {
	var s Script
	err := db.pool.QueryRow(ctx, `
		UPDATE scripts SET name=$2, platform=$3, content=$4, updated_at=now()
		WHERE id=$1
		RETURNING id, name, platform, content, created_at, updated_at
	`, id, name, platform, content).Scan(&s.ID, &s.Name, &s.Platform, &s.Content, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

// ErrScriptInUse — на скрипт ссылается хотя бы одна script-политика (FK без CASCADE).
// Удалять нельзя: иначе политика осталась бы без тела скрипта. Отдаётся как 409.
var ErrScriptInUse = errors.New("script is referenced by script policies")

func (db *DB) DeleteScript(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx, `DELETE FROM scripts WHERE id = $1`, id)
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

func (db *DB) ListScriptPolicies(ctx context.Context) ([]ScriptPolicy, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT p.id, p.name, p.script_id, COALESCE(s.name, ''), p.trigger_type,
		       COALESCE(p.schedule_config::text, 'null'), COALESCE(p.event_trigger_config::text, 'null'),
		       p.is_active, p.created_at,
		       COALESCE(
		         (SELECT array_agg(g.name ORDER BY g.name)
		          FROM policy_assignments pa JOIN device_groups g ON g.id = pa.group_id
		          WHERE pa.policy_id = p.id),
		         ARRAY[]::text[]
		       ) AS group_names
		FROM policies p
		LEFT JOIN scripts s ON s.id = p.script_id
		ORDER BY p.created_at DESC
	`)
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

func (db *DB) CreateScriptPolicy(ctx context.Context, name, scriptID, triggerType string, scheduleConfig, eventTriggerConfig []byte) (*ScriptPolicy, error) {
	var p ScriptPolicy
	var schedRaw, eventRaw string
	err := db.pool.QueryRow(ctx, `
		INSERT INTO policies (name, script_id, trigger_type, schedule_config, event_trigger_config)
		VALUES ($1, $2, $3, $4::jsonb, $5::jsonb)
		RETURNING id, name, script_id, trigger_type,
		          COALESCE(schedule_config::text, 'null'), COALESCE(event_trigger_config::text, 'null'),
		          is_active, created_at
	`, name, scriptID, triggerType, nullableJSON(scheduleConfig), nullableJSON(eventTriggerConfig)).
		Scan(&p.ID, &p.Name, &p.ScriptID, &p.TriggerType, &schedRaw, &eventRaw, &p.IsActive, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	p.ScheduleConfig = json.RawMessage(schedRaw)
	p.EventTriggerConfig = json.RawMessage(eventRaw)
	return &p, nil
}

func (db *DB) DeleteScriptPolicy(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx, `DELETE FROM policies WHERE id = $1`, id)
	return err
}

func (db *DB) ToggleScriptPolicy(ctx context.Context, id string, active bool) error {
	_, err := db.pool.Exec(ctx, `UPDATE policies SET is_active=$2 WHERE id=$1`, id, active)
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
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Color     string    `json:"color"` // '#rrggbb', CHECK в миграции 027
	CreatedAt time.Time `json:"created_at"`
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

func (db *DB) ListDeviceGroups(ctx context.Context) ([]DeviceGroupWithMembers, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, name, color, created_at FROM device_groups ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []DeviceGroupWithMembers
	for rows.Next() {
		var g DeviceGroupWithMembers
		if err := rows.Scan(&g.ID, &g.Name, &g.Color, &g.CreatedAt); err != nil {
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

	members, err := db.pool.Query(ctx, `SELECT group_id, device_id FROM device_group_members`)
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

	assignments, err := db.pool.Query(ctx, `SELECT group_id, policy_id FROM policy_assignments`)
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
	sw, err := db.pool.Query(ctx,
		`SELECT group_id, id, software_name, rule_type FROM software_policy_rules WHERE group_id IS NOT NULL`)
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
// Валидацию формата делает хендлер, БД страхует CHECK'ом.
func (db *DB) CreateDeviceGroup(ctx context.Context, name, color string) (*DeviceGroup, error) {
	var g DeviceGroup
	err := db.pool.QueryRow(ctx,
		`INSERT INTO device_groups (name, color) VALUES ($1, COALESCE(NULLIF($2, ''), $3))
		 RETURNING id, name, color, created_at`, name, color, DefaultGroupColor).
		Scan(&g.ID, &g.Name, &g.Color, &g.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrDuplicateGroupName
		}
		return nil, err
	}
	return &g, nil
}

// UpdateDeviceGroup меняет имя и/или цвет. Пустая строка = «не трогать это поле»,
// поэтому переименовать в пустое имя нельзя (и не нужно: CHECK 026 всё равно не даст).
// Возвращает (nil, nil), если группы нет — хендлер отдаёт 404.
func (db *DB) UpdateDeviceGroup(ctx context.Context, id, name, color string) (*DeviceGroup, error) {
	var g DeviceGroup
	err := db.pool.QueryRow(ctx, `
		UPDATE device_groups
		SET    name  = COALESCE(NULLIF($2, ''), name),
		       color = COALESCE(NULLIF($3, ''), color)
		WHERE  id::text = $1
		RETURNING id, name, color, created_at
	`, id, name, color).Scan(&g.ID, &g.Name, &g.Color, &g.CreatedAt)
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
func (db *DB) DeviceGroupExists(ctx context.Context, id string) (bool, error) {
	var exists bool
	// id::text, а не id: кривой UUID из URL иначе даёт 22P02 и превращается в 500.
	err := db.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM device_groups WHERE id::text = $1)`, id).Scan(&exists)
	return exists, err
}

func (db *DB) DeleteDeviceGroup(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx, `DELETE FROM device_groups WHERE id=$1`, id)
	return err
}

// AddDeviceToGroup — несуществующее устройство/группа = ErrForeignKeyViolation (→400),
// а не «internal error». То же у AssignPolicyToGroup / AssignSoftwarePolicyToGroup.
func (db *DB) AddDeviceToGroup(ctx context.Context, deviceID, groupID string) error {
	_, err := db.pool.Exec(ctx,
		`INSERT INTO device_group_members (device_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		deviceID, groupID)
	return wrapFKViolation(err)
}

func (db *DB) RemoveDeviceFromGroup(ctx context.Context, deviceID, groupID string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM device_group_members WHERE device_id=$1 AND group_id=$2`, deviceID, groupID)
	return err
}

func (db *DB) AssignPolicyToGroup(ctx context.Context, policyID, groupID string) error {
	_, err := db.pool.Exec(ctx,
		`INSERT INTO policy_assignments (policy_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		policyID, groupID)
	return wrapFKViolation(err)
}

func (db *DB) UnassignPolicyFromGroup(ctx context.Context, policyID, groupID string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM policy_assignments WHERE policy_id=$1 AND group_id=$2`, policyID, groupID)
	return err
}

// AssignSoftwarePolicyToGroup создаёт групповое софт-правило (group_id set, #2).
// Зеркалит CreatePolicyRule, но пишет group_id вместо device_id.
func (db *DB) AssignSoftwarePolicyToGroup(ctx context.Context, groupID, softwareName, ruleType string) (*PolicyRuleRow, error) {
	var r PolicyRuleRow
	err := db.pool.QueryRow(ctx, `
  INSERT INTO software_policy_rules (software_name, rule_type, group_id)
  VALUES ($1, $2, $3)
  RETURNING id, software_name, rule_type, device_id, group_id, updated_at
 `, softwareName, ruleType, groupID).
		Scan(&r.ID, &r.SoftwareName, &r.RuleType, &r.DeviceID, &r.GroupID, &r.UpdatedAt)
	if err != nil {
		return nil, wrapFKViolation(err)
	}
	return &r, nil
}

// UnassignSoftwarePolicyFromGroup удаляет групповое правило по id, ограничивая
// удаление рамками группы (нельзя снести чужое/device/global правило этим маршрутом).
func (db *DB) UnassignSoftwarePolicyFromGroup(ctx context.Context, groupID, ruleID string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM software_policy_rules WHERE id=$1 AND group_id=$2`, ruleID, groupID)
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
	rows, err := db.pool.Query(ctx, `
  INSERT INTO tasks (device_id, script_content, platform, priority, status)
  SELECT m.device_id, $2, $3, $4, 'pending'
  FROM device_group_members m
  JOIN devices d ON d.id = m.device_id
  WHERE m.group_id = $1
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
	rows, err := db.pool.Query(ctx, `
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
	_, err := db.pool.Exec(ctx, `
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
func (db *DB) ListScriptResultsByPolicy(ctx context.Context, policyID string, limit int) ([]ScriptResultRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.pool.Query(ctx, `
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

func (db *DB) ListDeviceTasks(ctx context.Context, deviceID string) ([]Task, error) {
	rows, err := db.pool.Query(ctx, `
  SELECT id, device_id, script_content, platform, priority, status, output, error_log, created_at
  FROM tasks WHERE device_id = $1
  ORDER BY created_at DESC LIMIT 50
 `, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.ScriptContent, &t.Platform, &t.Priority, &t.Status, &t.Output, &t.ErrorLog, &t.CreatedAt); err != nil {
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
	     COALESCE(d.hostname, '')       ILIKE $2
	  OR COALESCE(d.os, '')             ILIKE $2
	  OR COALESCE(d.os_version, '')     ILIKE $2
	  OR COALESCE(d.ip_address, '')     ILIKE $2
	  OR COALESCE(d.public_ip, '')      ILIKE $2
	  OR COALESCE(d.mac_address, '')    ILIKE $2
	  OR COALESCE(d.serial_number, '')  ILIKE $2
	  OR COALESCE(d.cpu, '')            ILIKE $2
	  OR COALESCE(d.disk, '')           ILIKE $2
	  OR COALESCE(d.agent_version, '')  ILIKE $2
	  OR COALESCE(d.cert_cn, '')        ILIKE $2
	  OR COALESCE(d.ram::text, '')      ILIKE $2
	  OR d.id::text                     ILIKE $2
	  OR ($3 <> '' AND translate(COALESCE(d.mac_address, ''), ':-. ', '') ILIKE $3)
	  OR ($3 <> '' AND translate(COALESCE(d.serial_number, ''), ':-. ', '') ILIKE $3)`

// ListEnrolledDevices возвращает все не-pending устройства. Непустой query фильтрует
// по подстроке ЛЮБОГО атрибута (см. deviceSearchColumns): достаточно хвоста серийника
// или куска IP. Пустой query — весь список, как раньше. Непустой groupID оставляет
// только членов этой группы; сравнение через group_id::text, иначе кривой UUID из
// URL даёт 22P02 и превращается в 500 вместо пустой выдачи.
func (db *DB) ListEnrolledDevices(ctx context.Context, query, groupID string) ([]Device, error) {
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
	rows, err := db.pool.Query(ctx, `
		SELECT d.id, d.hostname, d.os, COALESCE(d.os_version, ''), COALESCE(d.ip_address, ''),
		       d.status, d.last_seen_at, d.created_at, COALESCE(d.agent_version, ''),
		       COALESCE(d.mac_address, ''), COALESCE(d.serial_number, ''), COALESCE(d.public_ip, '')
		FROM devices d
		WHERE d.status != 'pending'
		  AND ($1 = '' OR (`+deviceSearchColumns+`))
		  AND ($4 = '' OR EXISTS (SELECT 1 FROM device_group_members m
		                          WHERE m.device_id = d.id AND m.group_id::text = $4))
		ORDER BY d.last_seen_at DESC NULLS LAST
	`, q, pattern, stripped, strings.TrimSpace(groupID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.OS, &d.OSVersion,
			&d.IPAddress, &d.Status, &d.LastSeenAt, &d.CreatedAt, &d.AgentVersion,
			&d.MACAddress, &d.SerialNumber, &d.PublicIP); err != nil {
			return nil, err
		}
		d.Groups = []DeviceGroupRef{}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := db.attachDeviceGroups(ctx, devices); err != nil {
		return nil, err
	}
	return devices, nil
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
	rows, err := db.pool.Query(ctx, `
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

func (db *DB) GetUserByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := db.pool.QueryRow(ctx, `
		SELECT id, name, email, password_hash, role, created_at FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (db *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, name, email, password_hash, role, created_at FROM users ORDER BY created_at
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUserPassword меняет хэш пароля И двигает password_changed_at=now()
// (token-epoch): все ранее выпущенные JWT становятся недействительны (см.
// GetUserPasswordChangedAt + jwtMiddleware). Общий путь для in-app смены и
// reset-flow — обе инвалидируют старые токены.
func (db *DB) UpdateUserPassword(ctx context.Context, userID, passwordHash string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, password_changed_at = now() WHERE id = $1`,
		userID, passwordHash)
	return err
}

// GetUserPasswordChangedAt возвращает момент последней смены пароля (token-epoch)
// и exists=false, если пользователя больше нет (живой токен удалённого юзера →
// jwtMiddleware отвергает). Лёгкий однострочный lookup для middleware.
func (db *DB) GetUserPasswordChangedAt(ctx context.Context, userID string) (time.Time, bool, error) {
	var t time.Time
	err := db.pool.QueryRow(ctx, `SELECT password_changed_at FROM users WHERE id = $1`, userID).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

// ---- Invitations ----

type Invitation struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Token      string     `json:"token"`
	InvitedBy  *string    `json:"invited_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at"`
}

func (db *DB) CreateInvitation(ctx context.Context, email, role, token, invitedBy string) (*Invitation, error) {
	var inv Invitation
	err := db.pool.QueryRow(ctx, `
		INSERT INTO invitation_tokens (email, role, token, invited_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, email, role, token, invited_by, created_at, expires_at, accepted_at
	`, email, role, token, invitedBy).
		Scan(&inv.ID, &inv.Email, &inv.Role, &inv.Token, &inv.InvitedBy,
			&inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt)
	return &inv, err
}

func (db *DB) GetInvitationByToken(ctx context.Context, token string) (*Invitation, error) {
	var inv Invitation
	err := db.pool.QueryRow(ctx, `
		SELECT id, email, role, token, invited_by, created_at, expires_at, accepted_at
		FROM invitation_tokens WHERE token = $1
	`, token).Scan(&inv.ID, &inv.Email, &inv.Role, &inv.Token, &inv.InvitedBy,
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
	_, err := db.pool.Exec(ctx, `
		UPDATE invitation_tokens SET accepted_at = now() WHERE token = $1
	`, token)
	return err
}

// ---- Password reset ----

type PasswordResetToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Token     string     `json:"token"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
}

func (db *DB) CreatePasswordResetToken(ctx context.Context, userID, token string) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, token) VALUES ($1, $2)
	`, userID, token)
	return err
}

func (db *DB) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	var t PasswordResetToken
	err := db.pool.QueryRow(ctx, `
		SELECT id, user_id, token, created_at, expires_at, used_at
		FROM password_reset_tokens WHERE token = $1
	`, token).Scan(&t.ID, &t.UserID, &t.Token, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

func (db *DB) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE password_reset_tokens SET used_at = now() WHERE token = $1
	`, token)
	return err
}

// CleanupOldData чистит устаревшие записи. Операционные данные (alerts, script_results)
// — по dataRetentionDays; audit_log — по отдельному auditRetentionDays (журнал
// безопасности хранится дольше). Для любого срока 0/отриц = хранить бессрочно.
func (db *DB) CleanupOldData(ctx context.Context, dataRetentionDays, auditRetentionDays int) (int64, error) {
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
		res, err := db.pool.Exec(ctx, q, cutoff)
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
	if err := purge("audit_log", "", auditRetentionDays); err != nil {
		return total, err
	}
	return total, nil
}
