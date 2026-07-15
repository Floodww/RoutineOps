// Package config загружает конфигурацию агента из флагов и переменных окружения.
// Приоритет: флаг > env > значение по умолчанию. Никаких хардкод-путей и адресов.
package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config — параметры запуска агента.
type Config struct {
	// ServerAddr — host:port gRPC-сервера (Agent Gateway).
	ServerAddr string
	// ServerName — ожидаемое CN/SAN в серверном сертификате (TLS ServerName).
	// Должно совпадать с SAN серверного серта (см. scripts/gen-certs.sh: DNS:routineops-server).
	ServerName string

	// Пути к mTLS-материалу. Для MVP — файлы на диске.
	// Загрузка абстрагирована (internal/agent/transport.CertProvider), чтобы
	// позже заменить на Keychain/Certificate Store без правок остального кода.
	CertFile string
	KeyFile  string
	CAFile   string

	// HeartbeatInterval — период отправки heartbeat (ADR-5: ~30с).
	HeartbeatInterval time.Duration
	// InventoryInterval — период полной инвентаризации ReportInventory (редко).
	InventoryInterval time.Duration
	// SecurityScanInterval — период проверки процессов Security Monitor.
	SecurityScanInterval time.Duration
	// ForbiddenListFile — локальный кэш политики ПО (синхронизируется с сервера
	// через FetchPolicy, читается Security Monitor).
	ForbiddenListFile string
	// PolicySyncInterval — период синхронизации политики ПО (FetchPolicy).
	PolicySyncInterval time.Duration
	// TaskStateFile — файл персистентной идемпотентности задач (""=только память).
	TaskStateFile string
	// LockStateFile — файл состояния блокировки устройства (переживает рестарт/ребут).
	LockStateFile string
	// LockPollInterval — период реконсиляции блокировки с сервером (FetchLockStatus):
	// переживает потерю push-команды (Task.lock) и ребут агента.
	LockPollInterval time.Duration
	// BlockedRetry — пауза реконнекта при блокировке устройства (PermissionDenied).
	BlockedRetry time.Duration
	// AdminPollInterval — период поллинга статуса прав администратора (FetchAdminStatus).
	AdminPollInterval time.Duration
	// Reason — обоснование для подкоманды request-admin.
	Reason string
	// AdminDryRun — не применять админ-права к системе (только логировать).
	AdminDryRun bool

	// OutboxDir — каталог устойчивой очереди отчётов (security/admin), которые
	// нельзя терять при обрыве связи; до-сылаются после восстановления.
	OutboxDir string
	// OutboxMax — максимум записей в очереди (защита диска); при переполнении
	// отбрасываются самые старые.
	OutboxMax int
	// OutboxMaxAge — потолок возраста записи: старше дропаются ретеншеном
	// (0 = без ограничения по возрасту). Помогает не копить устаревшие отчёты при
	// длительном оффлайне и ограничить диск, когда OutboxMax=0 (без лимита по числу).
	OutboxMaxAge time.Duration
	// OutboxFlush — период фоновых попыток до-доставки очереди.
	OutboxFlush time.Duration

	// ScriptPollInterval — период синхронизации скрипт-политик (FetchScriptPolicies).
	ScriptPollInterval time.Duration
	// ScriptDedupFile — файл дедупа on_connect-запусков скриптов (""=только память).
	ScriptDedupFile string
	// EventScanInterval — период опроса событий ОС (login/logout/network_change).
	EventScanInterval time.Duration

	// UpdateCheckURL — URL manifest самообновления (""=автообновление выключено).
	UpdateCheckURL string
	// UpdateInterval — период проверки обновлений.
	UpdateInterval time.Duration
	// UpdatePubKey — base64 ed25519 публичного ключа релиза для проверки подписи
	// бинаря (""=выключено; без ключа неподписанный бинарь не применяется).
	UpdatePubKey string
	// UpdateFloorFile — файл high-water mark версии самообновления: не даёт
	// применить манифест ниже уже когда-либо применённой версии, даже если он
	// валидно подписан (защита от replay состарившегося релиза — SEC-3, аудит
	// 2026-07-01). ""=только память (сбрасывается на рестарте — деградация без
	// сети, не отказ).
	UpdateFloorFile string

	// EnrollURL — URL эндпоинта энроллмента (подкоманда enroll), напр.
	// https://host:8081/api/v1/enroll.
	EnrollURL string
	// EnrollToken — одноразовый enrollment-токен (подкоманда enroll).
	EnrollToken string
	// CAURL — откуда скачать CA-бандл для энроллмента, если файла -ca нет на диске
	// (подкоманда enroll). Упрощает MSI/установщик до одного вызова agent enroll.
	CAURL string
	// CASHA256 — ожидаемый hex sha256 CA-бандла (подкоманда enroll). Если задан,
	// скачанный по -ca-url бандл сверяется с этим хешем и отвергается при
	// несовпадении. Закрывает MITM на TOFU-шаге скачивания CA (InsecureSkipVerify).
	CASHA256 string
	// EnrollInstall — после успешного enroll зарегистрировать системную службу.
	EnrollInstall bool

	// CertSource — источник mTLS-материала: file (по умолчанию) | keystore
	// (защищённое хранилище ОС: macOS Keychain). См. internal/agent/keystore.
	CertSource string
	// KeystoreLabel — метка идентичности в хранилище ОС (обычно device_id = CN).
	KeystoreLabel string

	// Probe — для подкоманды diag: дополнительно проверить mTLS-соединение с сервером.
	Probe bool

	// FilevaultEscrowDir — каталог write-ahead escrow-записей (internal/agent/filevault.Client):
	// секреты FileVault (enterprise), запечатанные, ДО сети.
	FilevaultEscrowDir string
	// FilevaultDryRun — не выполнять привилегированные FileVault-операции
	// (provisioning на энролле, revoke на локе), только логировать намеченные шаги.
	// Тот же паттерн, что AdminDryRun (обязательный флаг перед боевым включением).
	FilevaultDryRun bool
}

// Load парсит флаги/env. fs передаётся для тестируемости; args — без имени программы.
func Load(fs *flag.FlagSet, args []string) (*Config, error) {
	c := &Config{}

	fs.StringVar(&c.ServerAddr, "server", env("ROUTINEOPS_SERVER_ADDR", "localhost:55443"),
		"адрес gRPC-сервера host:port (env ROUTINEOPS_SERVER_ADDR)")
	fs.StringVar(&c.ServerName, "server-name", env("ROUTINEOPS_SERVER_NAME", "routineops-server"),
		"ожидаемое имя в серверном сертификате (env ROUTINEOPS_SERVER_NAME)")
	fs.StringVar(&c.CertFile, "cert", env("ROUTINEOPS_AGENT_CERT", "certs/agent.crt"),
		"путь к клиентскому сертификату агента (env ROUTINEOPS_AGENT_CERT)")
	fs.StringVar(&c.KeyFile, "key", env("ROUTINEOPS_AGENT_KEY", "certs/agent.key"),
		"путь к приватному ключу агента (env ROUTINEOPS_AGENT_KEY)")
	fs.StringVar(&c.CAFile, "ca", env("ROUTINEOPS_CA_CERT", "certs/ca.crt"),
		"путь к корневому CA (env ROUTINEOPS_CA_CERT)")
	fs.DurationVar(&c.HeartbeatInterval, "heartbeat", envDuration("ROUTINEOPS_HEARTBEAT_INTERVAL", 30*time.Second),
		"период отправки heartbeat (env ROUTINEOPS_HEARTBEAT_INTERVAL)")
	fs.DurationVar(&c.InventoryInterval, "inventory", envDuration("ROUTINEOPS_INVENTORY_INTERVAL", 5*time.Minute),
		"период полной инвентаризации ReportInventory (env ROUTINEOPS_INVENTORY_INTERVAL)")
	fs.DurationVar(&c.SecurityScanInterval, "security-scan", envDuration("ROUTINEOPS_SECURITY_SCAN", 30*time.Second),
		"период проверки процессов Security Monitor (env ROUTINEOPS_SECURITY_SCAN)")
	fs.StringVar(&c.ForbiddenListFile, "forbidden-list", env("ROUTINEOPS_FORBIDDEN_LIST", "forbidden_software.txt"),
		"локальный кэш политики ПО (FetchPolicy), читается Security Monitor (env ROUTINEOPS_FORBIDDEN_LIST)")
	fs.DurationVar(&c.PolicySyncInterval, "policy-sync", envDuration("ROUTINEOPS_POLICY_SYNC", 5*time.Minute),
		"период синхронизации политики ПО через FetchPolicy (env ROUTINEOPS_POLICY_SYNC)")
	fs.StringVar(&c.TaskStateFile, "task-state", env("ROUTINEOPS_TASK_STATE", "agent_tasks.seen"),
		"файл идемпотентности выполненных задач (env ROUTINEOPS_TASK_STATE)")
	fs.StringVar(&c.LockStateFile, "lock-state", env("ROUTINEOPS_LOCK_STATE", ""),
		"файл состояния блокировки (пусто = машинный каталог: ProgramData\\RoutineOps\\lock.json), env ROUTINEOPS_LOCK_STATE")
	fs.DurationVar(&c.LockPollInterval, "lock-poll", envDuration("ROUTINEOPS_LOCK_POLL", 30*time.Second),
		"период реконсиляции блокировки с сервером, FetchLockStatus (env ROUTINEOPS_LOCK_POLL)")
	fs.DurationVar(&c.BlockedRetry, "blocked-retry", envDuration("ROUTINEOPS_BLOCKED_RETRY", 5*time.Minute),
		"пауза реконнекта при блокировке устройства, PermissionDenied (env ROUTINEOPS_BLOCKED_RETRY)")
	fs.DurationVar(&c.AdminPollInterval, "admin-poll", envDuration("ROUTINEOPS_ADMIN_POLL", 30*time.Second),
		"период поллинга статуса прав администратора (env ROUTINEOPS_ADMIN_POLL)")
	fs.StringVar(&c.Reason, "reason", "", "обоснование для подкоманды request-admin")
	fs.BoolVar(&c.AdminDryRun, "admin-dry-run", envBool("ROUTINEOPS_ADMIN_DRYRUN"),
		"не применять админ-права к системе, только логировать (env ROUTINEOPS_ADMIN_DRYRUN)")
	fs.StringVar(&c.OutboxDir, "outbox-dir", env("ROUTINEOPS_OUTBOX_DIR", "agent_outbox"),
		"каталог устойчивой очереди отчётов (env ROUTINEOPS_OUTBOX_DIR)")
	fs.IntVar(&c.OutboxMax, "outbox-max", envInt("ROUTINEOPS_OUTBOX_MAX", 1000),
		"максимум записей в очереди отчётов, 0=без лимита (env ROUTINEOPS_OUTBOX_MAX)")
	fs.DurationVar(&c.OutboxMaxAge, "outbox-max-age", envDuration("ROUTINEOPS_OUTBOX_MAX_AGE", 0),
		"потолок возраста записи в очереди, 0=без лимита по возрасту (env ROUTINEOPS_OUTBOX_MAX_AGE)")
	fs.DurationVar(&c.OutboxFlush, "outbox-flush", envDuration("ROUTINEOPS_OUTBOX_FLUSH", 30*time.Second),
		"период фоновых попыток до-доставки очереди (env ROUTINEOPS_OUTBOX_FLUSH)")
	fs.DurationVar(&c.ScriptPollInterval, "script-poll", envDuration("ROUTINEOPS_SCRIPT_POLL", time.Minute),
		"период синхронизации скрипт-политик FetchScriptPolicies (env ROUTINEOPS_SCRIPT_POLL)")
	fs.StringVar(&c.ScriptDedupFile, "script-dedup", env("ROUTINEOPS_SCRIPT_DEDUP", "agent_scripts.seen"),
		"файл дедупа on_connect-запусков скриптов (env ROUTINEOPS_SCRIPT_DEDUP)")
	fs.DurationVar(&c.EventScanInterval, "event-scan", envDuration("ROUTINEOPS_EVENT_SCAN", 15*time.Second),
		"период опроса событий ОС login/logout/network_change (env ROUTINEOPS_EVENT_SCAN)")
	fs.StringVar(&c.UpdateCheckURL, "update-url", env("ROUTINEOPS_UPDATE_URL", ""),
		"URL manifest самообновления, пусто=выключено (env ROUTINEOPS_UPDATE_URL)")
	fs.DurationVar(&c.UpdateInterval, "update-interval", envDuration("ROUTINEOPS_UPDATE_INTERVAL", 6*time.Hour),
		"период проверки обновлений (env ROUTINEOPS_UPDATE_INTERVAL)")
	fs.StringVar(&c.UpdatePubKey, "update-pubkey", env("ROUTINEOPS_UPDATE_PUBKEY", ""),
		"base64 ed25519 публичного ключа релиза (env ROUTINEOPS_UPDATE_PUBKEY)")
	fs.StringVar(&c.UpdateFloorFile, "update-floor", env("ROUTINEOPS_UPDATE_FLOOR", "agent_update_floor.txt"),
		"файл high-water mark версии самообновления, защита от replay старого релиза (env ROUTINEOPS_UPDATE_FLOOR)")
	fs.StringVar(&c.EnrollURL, "enroll-url", env("ROUTINEOPS_ENROLL_URL", ""),
		"URL эндпоинта энроллмента для подкоманды enroll (env ROUTINEOPS_ENROLL_URL)")
	fs.StringVar(&c.EnrollToken, "token", env("ROUTINEOPS_ENROLL_TOKEN", ""),
		"одноразовый enrollment-токен для подкоманды enroll (env ROUTINEOPS_ENROLL_TOKEN)")
	fs.StringVar(&c.CAURL, "ca-url", env("ROUTINEOPS_CA_URL", ""),
		"URL CA-бандла: скачать, если файла -ca нет на диске, подкоманда enroll (env ROUTINEOPS_CA_URL)")
	fs.StringVar(&c.CASHA256, "ca-sha256", env("ROUTINEOPS_CA_SHA256", ""),
		"hex sha256 CA-бандла: пин против MITM при скачивании по -ca-url, подкоманда enroll (env ROUTINEOPS_CA_SHA256)")
	fs.BoolVar(&c.EnrollInstall, "install-service", envBool("ROUTINEOPS_ENROLL_INSTALL"),
		"после enroll зарегистрировать системную службу (env ROUTINEOPS_ENROLL_INSTALL)")
	fs.StringVar(&c.CertSource, "cert-source", env("ROUTINEOPS_CERT_SOURCE", "file"),
		"источник mTLS-материала: file|keystore (env ROUTINEOPS_CERT_SOURCE)")
	fs.StringVar(&c.KeystoreLabel, "keystore-label", env("ROUTINEOPS_KEYSTORE_LABEL", ""),
		"метка идентичности в хранилище ОС для cert-source=keystore, обычно device_id (env ROUTINEOPS_KEYSTORE_LABEL)")
	fs.BoolVar(&c.Probe, "probe", false,
		"diag: дополнительно проверить mTLS-соединение с сервером")
	fs.StringVar(&c.FilevaultEscrowDir, "filevault-escrow-dir", env("ROUTINEOPS_FILEVAULT_ESCROW_DIR", "filevault_escrow"),
		"каталог write-ahead escrow-записей FileVault (enterprise; env ROUTINEOPS_FILEVAULT_ESCROW_DIR)")
	fs.BoolVar(&c.FilevaultDryRun, "filevault-dry-run", envBool("ROUTINEOPS_FILEVAULT_DRYRUN"),
		"не выполнять привилегированные FileVault-операции, только логировать (env ROUTINEOPS_FILEVAULT_DRYRUN)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if c.ServerAddr == "" {
		return nil, fmt.Errorf("server address is required")
	}
	if c.HeartbeatInterval <= 0 {
		return nil, fmt.Errorf("heartbeat interval must be > 0, got %s", c.HeartbeatInterval)
	}
	if c.InventoryInterval <= 0 {
		return nil, fmt.Errorf("inventory interval must be > 0, got %s", c.InventoryInterval)
	}
	if c.SecurityScanInterval <= 0 {
		return nil, fmt.Errorf("security scan interval must be > 0, got %s", c.SecurityScanInterval)
	}
	if c.BlockedRetry <= 0 {
		return nil, fmt.Errorf("blocked retry must be > 0, got %s", c.BlockedRetry)
	}
	if c.AdminPollInterval <= 0 {
		return nil, fmt.Errorf("admin poll interval must be > 0, got %s", c.AdminPollInterval)
	}
	if c.LockPollInterval <= 0 {
		return nil, fmt.Errorf("lock poll interval must be > 0, got %s", c.LockPollInterval)
	}
	if c.PolicySyncInterval <= 0 {
		return nil, fmt.Errorf("policy sync interval must be > 0, got %s", c.PolicySyncInterval)
	}
	if c.ScriptPollInterval <= 0 {
		return nil, fmt.Errorf("script poll interval must be > 0, got %s", c.ScriptPollInterval)
	}
	if c.EventScanInterval <= 0 {
		return nil, fmt.Errorf("event scan interval must be > 0, got %s", c.EventScanInterval)
	}
	if c.UpdateInterval <= 0 {
		return nil, fmt.Errorf("update interval must be > 0, got %s", c.UpdateInterval)
	}
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	v := os.Getenv(key)
	return v == "1" || v == "true" || v == "yes"
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
