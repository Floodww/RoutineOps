package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/alerting"
	"github.com/Floodww/RoutineOps/internal/server/api"
	"github.com/Floodww/RoutineOps/internal/server/config"
	"github.com/Floodww/RoutineOps/internal/server/enroll"
	"github.com/Floodww/RoutineOps/internal/server/gateway"
	"github.com/Floodww/RoutineOps/internal/server/mailer"
	"github.com/Floodww/RoutineOps/internal/server/notifier"
	"github.com/Floodww/RoutineOps/internal/server/registry"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"github.com/Floodww/RoutineOps/internal/server/uninstall"
	"github.com/Floodww/RoutineOps/internal/server/worker"
	pb "github.com/Floodww/RoutineOps/proto"
	"github.com/hibiken/asynq"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// version — semver ПРОДУКТА (сервер+веб), вшивается через ldflags (-X main.version)
// на сборке образа (Dockerfile ARG VERSION). Пусто/"dev" в локальной сборке. Источник —
// файл VERSION в корне. Агент версионируется ОТДЕЛЬНО (файл AGENT_VERSION); self-update
// сравнивает именно её, а не эту.
var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	showVersion := flag.Bool("version", false, "напечатать версию сервера и выйти")
	registerEnterpriseFlags() // enterprise-оверлей добавляет -escrow-fpr (иначе no-op)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	// Enterprise-CLI (напр. -escrow-fpr): в open-core no-op → false. Иначе печатает и выходит.
	if runEnterpriseCLI() {
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := config.Load(*configPath)
	logger.Info("config loaded", "path", *configPath)

	if cfg.JWTSecret == "" || cfg.JWTSecret == "dev-secret-change-in-production" || cfg.JWTSecret == "change-me-in-production" {
		logger.Error("JWT_SECRET is not set or uses a default value — refusing to start")
		os.Exit(1)
	}
	// JWT-гигиена: секрет — единственный корень доверия (симметричный HS256), утёк →
	// бесконечный форж admin-токенов. Требуем длину и энтропию, иначе перебор реален.
	if len(cfg.JWTSecret) < 32 {
		logger.Error("JWT_SECRET too short — need ≥32 bytes — refusing to start", "len", len(cfg.JWTSecret))
		os.Exit(1)
	}
	if distinctByteCount(cfg.JWTSecret) < 16 {
		logger.Error("JWT_SECRET has too few distinct bytes (low entropy) — refusing to start")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := storage.Connect(ctx, cfg.DatabaseDSN)
	if err != nil {
		logger.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("database connected")

	if cfg.SeedAdminEmail != "" && cfg.SeedAdminPass != "" {
		if err := seedAdmin(ctx, db, cfg.SeedAdminEmail, cfg.SeedAdminPass, logger); err != nil {
			logger.Error("seed admin failed", "err", err)
		}
	}

	var caSigner *enroll.CASigner
	if cfg.CAKey != "" {
		if s, err := enroll.LoadCASigner(cfg.CACert, cfg.CAKey); err != nil {
			logger.Warn("CA signer unavailable, enrollment disabled", "err", err)
		} else {
			caSigner = s
			logger.Info("CA signer loaded, enrollment enabled")
		}
	}

	creds, err := buildTLSCredentials(cfg)
	if err != nil {
		logger.Error("tls setup failed", "err", err)
		os.Exit(1)
	}

	reg := registry.New()

	asynqClient := worker.NewClient(cfg.RedisAddr)
	defer asynqClient.Close()

	asynqSrv := worker.NewServer(cfg.RedisAddr)
	mux := asynq.NewServeMux()
	mux.HandleFunc(worker.TypeDeliverTask, worker.NewHandler(db, reg, logger).ProcessTask)
	// Обработчики enterprise-очередей (выгрузка в SIEM, пересчёт CVE). В открытой
	// сборке — no-op: типов задач нет, ставить их тоже некому.
	registerEnterpriseWorkers(mux, db, cfg.JWTSecret, logger)
	go func() {
		if err := asynqSrv.Run(mux); err != nil {
			logger.Error("asynq worker failed", "err", err)
		}
	}()
	logger.Info("asynq worker started", "redis", cfg.RedisAddr)

	// tgBot — интерфейсного типа, чтобы при пустом токене это был НАСТОЯЩИЙ nil,
	// а не typed-nil (*Bot)(nil) внутри интерфейса. Иначе g.bot != nil врёт и
	// NotifyITAdmins падает с nil-ресивером (полевой инцидент 2026-06-29).
	var tgBot gateway.Notifier
	var tgUsername func(context.Context) string
	if cfg.TelegramBotToken != "" {
		bot := notifier.New(cfg.TelegramBotToken, db, logger)
		go bot.StartPolling(ctx)
		tgBot = bot
		tgUsername = bot.Username
		logger.Info("telegram bot started")
	}

	// GRPC-LIMITS (аудит безопасности): защита gRPC-шлюза от ресурсного DoS.
	// Консервативно, чтобы не рвать долгоживущий Connect-стрим агента.
	// Blocked-guard на границе gRPC: любой agent-RPC от устройства со status='blocked'
	// отклоняется до хендлера (kill-switch для кражи/офбординга — раньше рвался только
	// Connect-стрим, а FetchScriptPolicies и др. работали по валидному серту).
	blockedUnary, blockedStream := gateway.NewBlockedInterceptors(db, logger)
	grpcSrv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(blockedUnary),
		grpc.ChainStreamInterceptor(blockedStream),
		grpc.MaxRecvMsgSize(4*1024*1024), // отчёты агента крошечные; кап против OOM на гигантском кадре
		grpc.MaxConcurrentStreams(64),    // потолок одновременных RPC на одно соединение
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second, // клиент не должен слать keepalive чаще — анти-ping-флуд
			PermitWithoutStream: true,             // у агента долгоживущий Connect-стрим
		}),
	)
	g := gateway.New(db, reg, asynqClient, logger, tgBot)
	// Манифест обновления (Q-52) отдаёт ссылку на бинарь — база та же, что у REST.
	g.SetPublicWebURL(cfg.PublicWebURL)
	// Enterprise-оверлей (//go:build enterprise) регистрирует escrow-сервис на g и
	// возвращает RouterOptions (WithLockModePolicy + /escrow/status). Open-core: nil →
	// escrow Unimplemented, lock mode=filevault → 409. См. enterprise{,_stub}.go.
	routerOpts := enterpriseSetup(g, db, asynqClient, reg, cfg.ScreenDir, cfg.RedisAddr, cfg.JWTSecret, logger)
	routerOpts = append(routerOpts, api.WithReleasePubKey(cfg.ReleasePubKey))
	// Удаление ПО — open-core на всех редакциях (13.08.2026, перенос из enterprise). Проводка
	// здесь, в общей композиции, а не в enterprise-оверлее: ручка есть в обеих сборках, без
	// лицензионного гейта. Агентская половина (internal/agent/uninstall) тоже не заперта тегом.
	routerOpts = append(routerOpts, uninstall.Routes(uninstall.NewService(db, asynqClient, logger)))
	// Fail-closed: опечатка в TRUSTED_PROXIES означает, что оператор настраивал
	// нестандартную топологию. Молча откатиться на дефолт — оставить его с per-IP
	// лимитом, который он считает настроенным, а тот схлопнут в один общий бакет.
	trustedProxies, err := api.ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		logger.Error("bad TRUSTED_PROXIES", "err", err)
		os.Exit(1)
	}
	routerOpts = append(routerOpts, api.WithTrustedProxies(trustedProxies))
	if tgUsername != nil {
		routerOpts = append(routerOpts, api.WithTelegramBotUsername(tgUsername))
	}
	pb.RegisterAgentServiceServer(grpcSrv, g)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		logger.Error("grpc listen failed", "addr", cfg.GRPCAddr, "err", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(cfg.ReleasesDir, 0o755); err != nil {
		logger.Error("releases dir create failed", "err", err)
		os.Exit(1)
	}

	m := mailer.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom, cfg.SMTPUseTLS)
	if m.Enabled() {
		logger.Info("mailer enabled", "host", cfg.SMTPHost, "port", cfg.SMTPPort, "tls", cfg.SMTPUseTLS)
		if mailer.PortTLSMismatch(cfg.SMTPPort, cfg.SMTPUseTLS) {
			logger.Warn("SMTP_PORT и SMTP_TLS не согласованы — письма, скорее всего, уходить не будут",
				"port", cfg.SMTPPort, "tls", cfg.SMTPUseTLS,
				"hint", "465 → SMTP_TLS=true (implicit TLS), 587/25 → SMTP_TLS=false (STARTTLS)")
		}
	} else {
		logger.Warn("mailer disabled: SMTP_HOST not set")
	}

	httpSrv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: api.NewRouter(db, asynqClient, []byte(cfg.JWTSecret), caSigner, cfg.PublicWebURL, cfg.ReleasesDir, m, cfg.CookieSecure,
			routerOpts...),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		logger.Info("HTTPS server listening", "addr", cfg.HTTPAddr)
		if err := httpSrv.ListenAndServeTLS(cfg.ServerCert, cfg.ServerKey); err != nil && err != http.ErrServerClosed {
			logger.Error("https serve failed", "err", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var n int64
				err := db.ForEachTenant(context.Background(), func(tctx context.Context) error {
					k, err := db.ExpireStaleAdminRequests(tctx)
					n += k
					return err
				})
				if err != nil {
					logger.Error("expire admin requests", "err", err)
				} else if n > 0 {
					logger.Info("expired stale admin requests", "count", n)
				}
			}
		}
	}()

	// Свипер отсутствующих улик сессии админ-прав (контракт §4/§6): базовая линия
	// снята, финала нет, заявка закрыта (revoked/expired). Покрывает досрочный отзыв.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var n int
				err := db.ForEachTenant(context.Background(), func(tctx context.Context) error {
					k, err := g.SweepAdminSessionEvidenceGaps(tctx)
					n += k
					return err
				})
				if err != nil {
					logger.Error("sweep admin session evidence gaps", "err", err)
				} else if n > 0 {
					logger.Warn("admin_session_evidence_gap alerts created", "count", n)
				}
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var n int64
				err := db.ForEachTenant(context.Background(), func(tctx context.Context) error {
					k, err := db.CleanupOldData(tctx, cfg.DataRetentionDays, cfg.AuditRetentionDays, cfg.AuditArchiveDir)
					n += k
					return err
				})
				if err != nil {
					logger.Error("cleanup old data", "err", err)
				} else if n > 0 {
					logger.Info("cleaned up old records", "count", n)
				}
			}
		}
	}()

	// Реконсайлер доставки: pending-задача ставится в очередь только при создании и
	// при реконнекте устройства (gateway.Connect). Любая потерянная постановка —
	// дедуп asynq по TaskID в гонке, перезапуск redis, отказ воркера — иначе оставила
	// бы задачу висеть в pending, хотя устройство онлайн. Тик дешёвый: asynq схлопывает
	// повторный enqueue того же TaskID.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refs, err := db.ListPendingTasksWithDeviceCN(context.Background(), 1000)
				if err != nil {
					logger.Error("reconcile pending tasks", "err", err)
					continue
				}
				for _, ref := range refs {
					if !reg.Connected(ref.DeviceCN) {
						continue
					}
					if err := worker.Enqueue(asynqClient, ref.TaskID); err != nil {
						logger.Error("reconcile: enqueue pending task", "task_id", ref.TaskID, "err", err)
					}
				}
				// Вторая половина реконсиляции — задачи, застрявшие в 'acked': агент
				// подтвердил получение и пропал, не прислав результат. Своего тикера не
				// заводим, окно 15 мин к минутному тику нечувствительно.
				var n int64
				if err := db.ForEachTenant(context.Background(), func(tctx context.Context) error {
					k, err := db.FailStaleAckedTasks(tctx, storage.StaleAckedTimeoutMinutes)
					n += k
					return err
				}); err != nil {
					logger.Error("reconcile: fail stale acked tasks", "err", err)
				} else if n > 0 {
					logger.Warn("задачи закрыты по таймауту: агент не прислал результат", "count", n)
				}
			}
		}
	}()

	// Детектор недоступных агентов: тикер сверяет last_seen_at и заводит alert
	// agent_unreachable (анти-дубль внутри запроса — один alert на эпизод).
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := db.DetectUnreachableDevices(context.Background(), cfg.UnreachableThresholdMinutes, cfg.UnreachableCooldownMinutes)
				if err != nil {
					logger.Error("detect unreachable devices", "err", err)
				} else if n > 0 {
					logger.Info("agent_unreachable alerts created", "count", n)
				}
			}
		}
	}()

	// Эскалация непринятых алертов (миграция 042): критичный инцидент, который никто
	// не принял за EscalateAfterMinutes, напоминает о себе в Telegram и продолжает
	// напоминать каждые EscalateRepeatMinutes, пока его не примут.
	//
	// Тикер в минуту, а не в EscalateAfterMinutes: порог проверяется по created_at в
	// SQL, поэтому частота опроса влияет только на точность момента напоминания, а не
	// на его наличие. Захват строк атомарный (TakeEscalations), так что лишние тики
	// безвредны.
	if cfg.EscalateAfterMinutes > 0 {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Ошибка одного тенанта НЕ отменяет рассылку по остальным: TakeEscalations
					// уже проставил им escalated_at, и выход по continue означал бы алерт,
					// помеченный отправленным и не отправленный никогда.
					//
					// Тенант запоминается ВМЕСТЕ с алертом, а не теряется при склейке: обход
					// собирает алерты всех тенантов в один список, и без этой пары напоминание
					// про устройство одного подразделения уходило бы администраторам всех.
					// Берём его из скоупа обхода, а не резолвим заново по device_id: это тот же
					// самый тенант, но без лишнего похода в базу — и, в отличие от резолва,
					// работает и для алерта, устройство которого уже списали.
					type dueAlert struct {
						tenantID string
						alert    storage.Alert
					}
					var due []dueAlert
					if err := db.ForEachTenant(context.Background(), func(tctx context.Context) error {
						d, err := db.TakeEscalations(tctx,
							cfg.EscalateMinSeverity, cfg.EscalateAfterMinutes, cfg.EscalateRepeatMinutes)
						tenantID, _ := storage.TenantIDFrom(tctx)
						for _, a := range d {
							due = append(due, dueAlert{tenantID: tenantID, alert: a})
						}
						return err
					}); err != nil {
						logger.Error("take alert escalations", "err", err)
					}
					for _, item := range due {
						a := item.alert
						waited := int(time.Since(a.CreatedAt).Minutes())
						sev, ok := alerting.Parse(a.Severity)
						if !ok {
							sev = alerting.UnknownSeverity
						}
						text := notifier.HTMLf(
							"%s <b>Алерт не принят %d мин</b>\nТип: %s\nКритичность: %s\nУстройство: <code>%s</code>\nДетали: %s",
							alerting.Emoji(sev), waited, a.AlertType, alerting.Label(sev), a.DeviceHostname, a.Details)
						// Напоминание уходит по тем же порогам, что и исходный алерт:
						// администратор, отписавшийся от этого уровня, не должен получать
						// его повторно под другим заголовком.
						//
						// tgBot, а не локальный bot: интерфейсная переменная — НАСТОЯЩИЙ
						// nil при пустом токене, а не typed-nil внутри интерфейса (см.
						// комментарий к её объявлению и полевой инцидент 2026-06-29).
						if tgBot != nil {
							// Скоуп обхода уже закрыт (транзакция завершилась вместе с fn), и
							// переиспользовать его нельзя. Переносим ровно тенанта — рассылка
							// откроет по нему свою транзакцию. Отправка ВНЕ скоупа намеренно:
							// внутри она держала бы транзакцию открытой на время похода в
							// api.telegram.org, до десяти секунд на каждого получателя.
							tgBot.NotifyAlert(storage.WithTenantID(context.Background(), item.tenantID), sev, text)
						}
					}
					if len(due) > 0 {
						logger.Info("alert escalations sent", "count", len(due))
					}
				}
			}
		}()
	}

	// Якорь хеш-цепочки аудита (миграция 042): раз в сутки фиксируем голову в
	// audit_anchors и — что важнее — ПЕЧАТАЕМ её в лог сервера.
	//
	// Якорь в той же БД, что и журнал, сам по себе слаб: тот, кто может переписать
	// цепочку, перепишет и его. Ценность появляется ровно тогда, когда голова
	// оказывается за пределами БД — в логе, который уезжает в сборщик логов, в
	// переписке оператора, в тикете. Поэтому строчка лога здесь не диагностика, а
	// сам механизм: её нельзя убрать как «шумную».
	go func() {
		// Якорь на КАЖДЫЙ тенант: цепочка аудита тенантская (карта tenancy), поэтому
		// одна голова на инсталляцию оставляла бы всех, кроме дефолтного тенанта, без
		// tamper-evidence — молча, при работающем /audit-log/verify.
		anchor := func() {
			if err := db.ForEachTenant(context.Background(), func(tctx context.Context) error {
				seq, hash, err := db.WriteAuditAnchor(tctx)
				if err != nil {
					return err
				}
				if seq == 0 {
					return nil // журнал тенанта пуст, фиксировать нечего
				}
				tenantID, _ := storage.TenantIDFrom(tctx)
				logger.Info("audit chain anchor", "tenant_id", tenantID, "seq", seq, "head_hash", hash)
				return nil
			}); err != nil {
				logger.Error("audit chain anchor", "err", err)
			}
		}
		// Первый якорь сразу на старте: перезапуск сервера — естественная точка,
		// в которой голову стоит зафиксировать, и он же гарантирует, что якорь
		// появится даже на инсталляции, которую переподнимают чаще раза в сутки.
		anchor()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				anchor()
			}
		}
	}()

	// M-7: чистка блок-листа отозванных токенов — отдельный тикер (1ч), чтобы не
	// зависеть от 24ч data-retention и держать таблицу маленькой; сбой одной чистки
	// не блокирует другую.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rn, rerr := db.CleanupExpiredRevokedTokens(context.Background())
				if rerr != nil {
					logger.Error("cleanup expired revoked tokens", "err", rerr)
				} else if rn > 0 {
					logger.Info("cleaned up expired revoked tokens", "count", rn)
				}
			}
		}
	}()

	go func() {
		logger.Info("gRPC server listening", "addr", cfg.GRPCAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			logger.Error("grpc serve failed", "err", err)
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received, stopping...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	grpcSrv.GracefulStop()
	_ = httpSrv.Shutdown(shutdownCtx)
	asynqSrv.Shutdown()
}

func seedAdmin(ctx context.Context, db *storage.DB, email, password string, logger *slog.Logger) error {
	// ADR-7: наличие проверяем по личности — она глобальна, а членство искали бы
	// в конкретном тенанте и на втором запуске завели бы человеку вторую учётку.
	existing, err := db.GetIdentityByEmail(ctx, email)
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	// D: seed-admin больше НЕ минует политику сложности — слабый пароль = отказ создания.
	if msg := api.ValidatePassword(password); msg != "" {
		return fmt.Errorf("seed admin password rejected: %s", msg)
	}
	// cost 12 (как api.bcryptCost) — выше DefaultCost для запаса по перебору.
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	_, err = db.CreateUser(ctx, tenancy.DefaultTenantID, "Admin", email, string(hash), "it_admin")
	if err != nil {
		return err
	}
	// Бутстрап-личность получает надзор над инсталляцией: после ADR-7 это признак
	// личности, и без него на чистой установке некому создать второй тенант —
	// создание уже под requireProviderAdmin. Выдаётся только когда личность в
	// инсталляции единственная, см. PromoteBootstrapProviderAdmin.
	granted, err := db.PromoteBootstrapProviderAdmin(ctx, email)
	if err != nil {
		return err
	}
	logger.Info("admin user created", "email", email, "provider_admin", granted)
	return nil
}

// distinctByteCount — число уникальных байт в строке. Грубый прокси энтропии для
// стартовой проверки JWT_SECRET: настоящий случайный секрет имеет много различных байт.
func distinctByteCount(s string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}

func buildTLSCredentials(cfg config.Config) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.ServerCert, cfg.ServerKey)
	if err != nil {
		return nil, err
	}

	caPEM, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		// Агент дозванивается строго по TLS 1.3 (transport.go) — пинуем тот же пол и
		// на сервере, чтобы случайно не согласовать TLS 1.2 и не ослабить канал.
		MinVersion: tls.VersionTLS13,
	}), nil
}
