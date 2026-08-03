package config

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	GRPCAddr         string
	HTTPAddr         string
	ServerCert       string
	ServerKey        string
	CACert           string
	CAKey            string
	DatabaseDSN      string
	RedisAddr        string
	JWTSecret        string
	SeedAdminEmail   string
	SeedAdminPass    string
	TelegramBotToken string
	PublicWebURL     string
	ReleasePubKey    string
	ReleasesDir      string
	// ScreenDir — каталог записей интерактивных сеансов (enterprise). Отдельный
	// bind-mount: записи невосстановимы, в отличие от releases/, который регенерируется
	// из agent_releases (docs/remote-desktop-contract.md §5).
	ScreenDir         string
	SMTPHost          string
	SMTPPort          string
	SMTPUser          string
	SMTPPass          string
	SMTPFrom          string
	SMTPUseTLS        bool
	DataRetentionDays int
	// AuditRetentionDays — отдельный (длинный) срок хранения audit_log. Аудит — журнал
	// безопасности; чистить его коротким DataRetentionDays (операционные alerts/results)
	// бессмысленно. 0/отриц = хранить бессрочно.
	AuditRetentionDays int
	AuditArchiveDir    string
	// UnreachableThresholdMinutes — сколько минут без heartbeat до alert agent_unreachable.
	// Дефолт 10080 (7 суток): алерт означает «машина реально выпала из парка», а не
	// «ушла на выходные / в отпуск с ноутбуком». Короткий порог давал шум на каждый
	// сон и отключение VPN.
	UnreachableThresholdMinutes int
	// UnreachableCooldownMinutes — окно подавления повторных agent_unreachable по одному
	// устройству. Гасит дребезг modern-standby (машина просыпается ~раз в час на минуту,
	// двигает last_seen_at → каждый сон выглядит новым эпизодом). 0/отриц = без cooldown.
	UnreachableCooldownMinutes int
	// EscalateAfterMinutes — сколько минут непринятый алерт критичности не ниже
	// EscalateMinSeverity висит, прежде чем в Telegram уйдёт напоминание.
	// 0/отриц = эскалация выключена. Дефолт 30: короче — и напоминание придёт
	// раньше, чем дежурный успеет открыть панель, то есть станет шумом, который
	// отключат целиком.
	EscalateAfterMinutes int
	// EscalateRepeatMinutes — интервал повторных напоминаний по тому же алерту,
	// пока его не приняли. 0/отриц = напомнить ровно один раз.
	EscalateRepeatMinutes int
	// EscalateMinSeverity — минимальная критичность, участвующая в эскалации.
	// Дефолт critical: эскалируется то, что не должно ждать до утра. Понижать до
	// medium/low имеет смысл только там, где алертов мало.
	EscalateMinSeverity string
	CookieSecure        bool
	// TrustedProxies — TRUSTED_PROXIES: с каких адресов верить заголовку с адресом
	// клиента (X-Real-IP / X-Forwarded-For). Пусто = приватные и loopback-диапазоны,
	// чего хватает для штатного деплоя (nginx рядом в compose-сети). Задавать нужно,
	// если прокси стоит на ПУБЛИЧНОМ адресе — иначе per-IP лимиты снова схлопнутся в
	// один общий бакет. Разбор и семантика — internal/server/api/realip.go.
	TrustedProxies string
	// FileVault-escrow recipient (ESCROW_RECIPIENT) читается enterprise-оверлеем
	// (cmd/server, //go:build enterprise), не open-core-конфигом.
}

// yamlConfig mirrors config.yaml structure.
type yamlConfig struct {
	Server struct {
		HTTPAddr  string `yaml:"http_addr"`
		GRPCAddr  string `yaml:"grpc_addr"`
		PublicURL string `yaml:"public_url"`
	} `yaml:"server"`
	TLS struct {
		Cert   string `yaml:"cert"`
		Key    string `yaml:"key"`
		CACert string `yaml:"ca_cert"`
		CAKey  string `yaml:"ca_key"`
	} `yaml:"tls"`
	Database struct {
		DSN string `yaml:"dsn"`
	} `yaml:"database"`
	Redis struct {
		Addr string `yaml:"addr"`
	} `yaml:"redis"`
	Auth struct {
		JWTSecret string `yaml:"jwt_secret"`
	} `yaml:"auth"`
	Admin struct {
		SeedEmail    string `yaml:"seed_email"`
		SeedPassword string `yaml:"seed_password"`
	} `yaml:"admin"`
	SMTP struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
		From string `yaml:"from"`
	} `yaml:"smtp"`
	Telegram struct {
		BotToken string `yaml:"bot_token"`
	} `yaml:"telegram"`
	Releases struct {
		Dir string `yaml:"dir"`
	} `yaml:"releases"`
}

// Load reads config from a YAML file (default: config.yaml), then
// applies environment variable overrides. Env vars always win.
func Load(configPath string) Config {
	var y yamlConfig
	if data, err := os.ReadFile(configPath); err == nil {
		_ = yaml.Unmarshal(data, &y)
	}

	return Config{
		HTTPAddr:      coalesce(os.Getenv("HTTP_ADDR"), y.Server.HTTPAddr, ":8081"),
		GRPCAddr:      coalesce(os.Getenv("GRPC_ADDR"), y.Server.GRPCAddr, ":50051"),
		PublicWebURL:  coalesce(os.Getenv("PUBLIC_WEB_URL"), y.Server.PublicURL, "https://localhost:8081"),
		ReleasePubKey: os.Getenv("RELEASE_PUBKEY"),
		ServerCert:    coalesce(os.Getenv("SERVER_CERT"), y.TLS.Cert, "certs/server.crt"),
		ServerKey:     coalesce(os.Getenv("SERVER_KEY"), y.TLS.Key, "certs/server.key"),
		CACert:        coalesce(os.Getenv("CA_CERT"), y.TLS.CACert, "certs/ca.crt"),
		CAKey:         coalesce(os.Getenv("CA_KEY"), y.TLS.CAKey, "certs/ca.key"),
		// Дефолт только для локальной разработки. sslmode=prefer (а не disable):
		// на localhost без TLS откатится на plaintext, но в проде с TLS-СУБД канал
		// шифруется. Прод обязан задавать DATABASE_DSN явно (M-2).
		DatabaseDSN:                 coalesce(os.Getenv("DATABASE_DSN"), y.Database.DSN, "postgres://mdm:mdm_dev_password@localhost:5432/mdm?sslmode=prefer"),
		RedisAddr:                   coalesce(os.Getenv("REDIS_ADDR"), y.Redis.Addr, "localhost:6379"),
		JWTSecret:                   coalesce(os.Getenv("JWT_SECRET"), y.Auth.JWTSecret, "dev-secret-change-in-production"),
		SeedAdminEmail:              coalesce(os.Getenv("SEED_ADMIN_EMAIL"), y.Admin.SeedEmail),
		SeedAdminPass:               coalesce(os.Getenv("SEED_ADMIN_PASSWORD"), y.Admin.SeedPassword),
		TelegramBotToken:            coalesce(os.Getenv("TELEGRAM_BOT_TOKEN"), y.Telegram.BotToken),
		ReleasesDir:                 coalesce(os.Getenv("RELEASES_DIR"), y.Releases.Dir, "./releases"),
		ScreenDir:                   coalesce(os.Getenv("SCREEN_DIR"), "./screen-recordings"),
		SMTPHost:                    coalesce(os.Getenv("SMTP_HOST"), y.SMTP.Host),
		SMTPPort:                    coalesce(os.Getenv("SMTP_PORT"), y.SMTP.Port, "587"),
		SMTPUser:                    coalesce(os.Getenv("SMTP_USER"), y.SMTP.User),
		SMTPPass:                    coalesce(os.Getenv("SMTP_PASS"), y.SMTP.Pass),
		SMTPFrom:                    coalesce(os.Getenv("SMTP_FROM"), y.SMTP.From, "noreply@mdm.local"),
		SMTPUseTLS:                  os.Getenv("SMTP_TLS") == "true",
		DataRetentionDays:           parseInt(os.Getenv("DATA_RETENTION_DAYS"), 7),
		AuditRetentionDays:          parseInt(os.Getenv("AUDIT_RETENTION_DAYS"), 365),
		AuditArchiveDir:             os.Getenv("AUDIT_ARCHIVE_DIR"),
		UnreachableThresholdMinutes: parseInt(os.Getenv("AGENT_UNREACHABLE_MINUTES"), 10080),
		UnreachableCooldownMinutes:  parseInt(os.Getenv("AGENT_UNREACHABLE_COOLDOWN_MINUTES"), 360),
		EscalateAfterMinutes:        parseInt(os.Getenv("ALERT_ESCALATE_AFTER_MINUTES"), 30),
		EscalateRepeatMinutes:       parseInt(os.Getenv("ALERT_ESCALATE_REPEAT_MINUTES"), 60),
		EscalateMinSeverity:         coalesce(os.Getenv("ALERT_ESCALATE_MIN_SEVERITY"), "critical"),
		CookieSecure:                os.Getenv("COOKIE_SECURE") == "true",
		TrustedProxies:              os.Getenv("TRUSTED_PROXIES"),
	}
}

// coalesce returns the first non-empty string.
func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseInt parses s to an integer, returning def if parsing fails or n <= 0.
func parseInt(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}
