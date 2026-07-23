package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Floodww/RoutineOps/internal/server/enroll"
	"github.com/Floodww/RoutineOps/internal/server/mailer"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/worker"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"golang.org/x/crypto/bcrypt"
)

// bcryptCost — стоимость bcrypt для хешей паролей. Выше DefaultCost (10), т.к.
// хеш разблокировки устройства лежит на самом устройстве и атакуем оффлайн;
// 12 даёт запас по перебору при приемлемой задержке хеширования на сервере.
const bcryptCost = 12

// validatePassword — политика сложности пароля (M-6): длина ≥8 и минимум 3 из 4
// классов символов (строчные, прописные, цифры, спецсимволы). Применяется при
// УСТАНОВКЕ пароля (accept-invite, reset-password); на логин не влияет (там только
// сверка хеша), seed-admin идёт мимо. Возвращает "" если ок, иначе сообщение.
func validatePassword(p string) string {
	if len(p) < 8 {
		return "password must be at least 8 characters"
	}
	var lower, upper, digit, special bool
	for _, r := range p {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			special = true
		}
	}
	classes := 0
	for _, ok := range []bool{lower, upper, digit, special} {
		if ok {
			classes++
		}
	}
	if classes < 3 {
		return "password must contain at least 3 of: lowercase, uppercase, digit, special character"
	}
	return ""
}

// ValidatePassword — экспортируемая обёртка над политикой сложности, чтобы её мог
// применять код вне пакета api (seed-admin в cmd/server). Возвращает "" если ок.
func ValidatePassword(p string) string { return validatePassword(p) }

// accessLogRedacted — access-лог БЕЗ query-string. Раньше стоял chi middleware.Logger,
// который печатает полный RequestURI (путь+query); одноразовые токены (invite/enroll/
// reset) приходят в query-string GET-запросов и оседали в stdout-логе открытым текстом
// (их мог перехватить читатель агрегатора логов без прав на хост, выиграв гонку у
// легитимного потребителя). Логируем только method+path+статус+длительность.
func accessLogRedacted(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		next.ServeHTTP(ww, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path, // БЕЗ RawQuery
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"dur", time.Since(start).String(),
		)
	})
}

type Handler struct {
	db            *storage.DB
	asynqClient   *asynq.Client
	jwtSecret     []byte
	ca            *enroll.CASigner
	publicWebURL  string
	releasePubKey string
	releasesDir   string
	mailer        *mailer.Mailer
	cookieSecure  bool
	loginLimiter  *loginLimiter
	// lockPolicy валидирует режим лока. Дефолт (open-core) — overlay-only; enterprise
	// подменяет через WithLockModePolicy. См. lockmode.go.
	lockPolicy LockModePolicy
	// telegramBotUsername — @username бота этого деплоя (getMe). nil = бот не настроен.
	telegramBotUsername func(context.Context) string
}

func NewRouter(db *storage.DB, asynqClient *asynq.Client, jwtSecret []byte, ca *enroll.CASigner, publicWebURL, releasesDir string, m *mailer.Mailer, cookieSecure bool, opts ...RouterOption) http.Handler {
	h := &Handler{
		db:           db,
		asynqClient:  asynqClient,
		jwtSecret:    jwtSecret,
		ca:           ca,
		publicWebURL: publicWebURL,
		releasesDir:  releasesDir,
		mailer:       m,
		cookieSecure: cookieSecure,
		lockPolicy:   overlayOnlyPolicy{},
		// D: 5 неудачных попыток на аккаунт за 15 мин → блок аккаунта на 15 мин.
		loginLimiter: newLoginLimiter(5, 15*time.Minute, 15*time.Minute),
	}

	r := chi.NewRouter()
	r.Use(accessLogRedacted) // не логируем query: одноразовые токены приходят в query-string
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestSize(1 << 20)) // 1 MB cap — защита от OOM через гигантские тела
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'")
			next.ServeHTTP(w, r)
		})
	})

	r.Get("/healthz", h.healthz)
	r.With(httprate.LimitByIP(10, time.Minute)).Post("/api/v1/auth/login", h.login)
	r.Post("/api/v1/auth/logout", h.logout)
	// Неаутентифицированные side-effect роуты: SECURITY.md заявляет «rate limits» как
	// общий контроль, но раньше он стоял только на /login. forgot-password шлёт письмо
	// через SMTP оператора (mail-bomb) и пишет reset-токен в БД (рост таблицы) — режем
	// жёстче; reset/accept-invite крипто-токен-гейтед, но лимит против амплификации/DoS.
	r.With(httprate.LimitByIP(5, time.Minute)).Post("/api/v1/auth/forgot-password", h.forgotPassword)
	r.With(httprate.LimitByIP(10, time.Minute)).Post("/api/v1/auth/reset-password", h.resetPassword)
	r.With(httprate.LimitByIP(10, time.Minute)).Post("/api/v1/auth/accept-invite", h.acceptInvite)
	r.Get("/api/v1/auth/invite", h.getInvite)
	r.Post("/api/v1/enroll", h.enroll)
	r.Get("/api/v1/agent/version", h.agentVersion)
	r.Get("/api/v1/installer", h.getInstaller)
	r.Get("/ca.crt", h.getCACert)
	r.Handle("/downloads/*", http.StripPrefix("/downloads/", noDirFileServer(releasesDir)))

	// SPA static files — serve web/dist, fallback to index.html for client-side routing
	if webDir := "web/dist"; func() bool { _, err := http.Dir(webDir).Open("/index.html"); return err == nil }() {
		fs := http.FileServer(http.Dir(webDir))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			if _, err := http.Dir(webDir).Open(r.URL.Path); err != nil {
				http.ServeFile(w, r, webDir+"/index.html")
				return
			}
			fs.ServeHTTP(w, r)
		})
	}

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(h.jwtMiddleware)

		// Read-only — все роли
		r.Get("/me", h.me)
		// requireHuman: у сервисного токена нет личного аккаунта, а claims.UserID —
		// это создавший админ. Без гарда viewer-токен менял бы админу пароль (и
		// сбрасывал все его живые сессии), зная лишь текущий пароль.
		r.With(requireHuman).Post("/me/password", h.changePassword)
		r.Get("/devices", h.listDevices)
		r.Get("/devices/{id}", h.getDevice)
		r.Get("/devices/{id}/tasks", h.listTasks)
		r.Get("/alerts", h.listAlerts)
		// requireHuman: ручка отдаёт telegram link_token ВЛАДЕЛЬЦА claims.UserID.
		// Под токеном это админ-создатель → его непогашенный линк-токен утекал
		// держателю read-only токена, а тот, скормив его боту, перехватывал
		// админские алерты. Привязка Telegram — личное действие человека.
		r.With(requireHuman).Get("/profile/telegram", h.getTelegramStatus)
		r.Get("/admin-access-requests", h.listAdminAccessRequests)
		r.Get("/policies", h.listPolicies)
		r.Get("/policies/compliance", h.listPolicyCompliance)
		r.Get("/policies/{id}/compliance", h.listPolicyDeviceCompliance)
		r.Get("/scripts", h.listScripts)
		r.Get("/scripts/{id}", h.getScript)
		r.Get("/script-policies", h.listScriptPolicies)
		r.Get("/script-policies/compliance", h.listScriptPolicyCompliance)
		r.Get("/script-policies/{id}/results", h.listScriptResults)
		r.Get("/device-groups", h.listDeviceGroups)
		r.Get("/audit-log", h.listAuditLog)
		r.Get("/users", h.listUsers)

		// Мутирующие операции — только it_admin
		r.Group(func(r chi.Router) {
			r.Use(h.requireRole("it_admin"))
			r.Post("/devices", h.createPendingDevice)
			r.Post("/devices/{id}/tasks", h.createTask)
			r.Put("/devices/{id}/status", h.updateDeviceStatus)
			r.Delete("/devices/{id}", h.deleteDevice)
			r.Post("/devices/{id}/lock", h.lockDevice)
			r.Post("/devices/{id}/unlock", h.unlockDevice)
			// requireHuman: вывод из эксплуатации необратим и деструктивен — агент сносит
			// серт/службу/состояние, устройство уходит в терминальный decommissioned.
			// Автоматике/сервисному токену такое запрещаем (🔴 правило requireHuman).
			r.With(requireHuman).Post("/devices/{id}/decommission", h.decommissionDevice)
			// Bulk enrollment. requireHuman на выпуск токена и одобрение (выпускают доступ
			// к парку — только человеком); reject/batch-reject НЕ гейтим (защитное действие).
			r.With(requireHuman).Post("/enrollment-tokens/bulk", h.issueBulkEnrollmentToken)
			r.Get("/enrollment-tokens/bulk", h.listBulkEnrollmentTokens)
			// Отзыв НЕ гейтим requireHuman: защитное действие (ниже тот же приём с правами).
			r.Delete("/enrollment-tokens/{id}", h.revokeEnrollmentToken)
			r.With(requireHuman).Post("/devices/{id}/approve", h.approveDevice)
			r.Post("/devices/{id}/reject", h.rejectDevice)
			r.With(requireHuman).Post("/enrollment-queue/approve", h.approvePendingDevices)
			r.Post("/enrollment-queue/reject", h.rejectPendingDevices)
			r.Get("/devices/{id}/enrollment-token", h.getEnrollmentToken)
			r.Post("/devices/{id}/reenroll", h.reenrollDevice)
			r.Post("/alerts/{id}/acknowledge", h.acknowledgeAlert)
			r.With(requireHuman).Post("/profile/telegram-link", h.generateTelegramLinkToken)
			// requireHuman: одобрение выдаёт сотруднику ЛОКАЛЬНОГО АДМИНА на устройстве —
			// решение человека, а не автоматизации. Плюс RespondToAdminRequest пишет
			// claims.UserID в durable-колонку approved_by, и под токеном там оказался бы
			// админ-создатель: при разборе инцидента единственным одобрившим числился бы
			// человек, который ничего не одобрял.
			r.With(requireHuman).Post("/admin-access-requests/{id}/respond", h.respondAdminRequest)
			// Отзыв НЕ гейтим: это защитное действие, автоматике его запрещать вредно.
			r.Post("/admin-access-requests/{id}/revoke", h.revokeAdminRequest)
			r.Post("/policies", h.createPolicy)
			r.Delete("/policies/{id}", h.deletePolicy)
			r.Post("/scripts", h.createScript)
			r.Put("/scripts/{id}", h.updateScript)
			r.Delete("/scripts/{id}", h.deleteScript)
			r.Post("/script-policies", h.createScriptPolicy)
			r.Delete("/script-policies/{id}", h.deleteScriptPolicy)
			r.Patch("/script-policies/{id}/toggle", h.toggleScriptPolicy)
			r.Post("/device-groups", h.createDeviceGroup)
			r.Patch("/device-groups/{id}", h.updateDeviceGroup)
			r.Delete("/device-groups/{id}", h.deleteDeviceGroup)
			r.Post("/device-groups/{id}/members", h.addGroupMember)
			r.Delete("/device-groups/{id}/members/{deviceId}", h.removeGroupMember)
			r.Post("/device-groups/{id}/policies", h.assignPolicyToGroup)
			r.Delete("/device-groups/{id}/policies/{policyId}", h.unassignPolicyFromGroup)
			r.Post("/device-groups/{id}/software-policies", h.assignSoftwarePolicyToGroup)
			r.Delete("/device-groups/{id}/software-policies/{ruleId}", h.unassignSoftwarePolicyFromGroup)
			r.Post("/device-groups/{id}/run-script", h.runScriptOnGroup)
			// requireHuman: приглашение выпускает УЧЁТНЫЕ ДАННЫЕ ЧЕЛОВЕКА с любой ролью,
			// включая it_admin, а accept-invite не требует авторизации. Без гарда утёкший
			// токен заводил себе живого админа: при выключенном SMTP хендлер отдаёт сырой
			// invite_url прямо в теле ответа. И это ХУЖЕ теневого токена — строки в users
			// нет в списке /api-tokens, поэтому при разборе инцидента её не находят, а
			// отзыв утёкшего токена доступ не отбирает.
			r.With(requireHuman).Post("/users/invite", h.inviteUser)
			// Сервисные токены — только it_admin И только человеком (requireHuman).
			// Токен это учётные данные с ролью, выпуск их равносилен заведению
			// пользователя. 🔴 Без requireHuman модель отзыва была фикцией: утёкший
			// токен выписывал себе теневой (created_by копировался с исходного, так что
			// в списке он неотличим от выданного руками), теневой переживал удаление
			// исходного, и «отозвали строку — доступа нет» переставало быть правдой.
			r.With(requireHuman).Get("/api-tokens", h.listAPITokens)
			r.With(requireHuman).Post("/api-tokens", h.createAPIToken)
			r.With(requireHuman).Delete("/api-tokens/{id}", h.deleteAPIToken)
		})

		// Enterprise-оверлей монтирует свои роуты/политику в authed-группу
		// (WithLockModePolicy, WithRoutes(escrow.StatusRoute)). Open-core: opts пуст.
		for _, opt := range opts {
			opt(h, r)
		}
	})

	return r
}

func (h *Handler) listPolicies(w http.ResponseWriter, r *http.Request) {
	rules, err := h.db.ListPolicyRules(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []storage.PolicyRuleRow{}
	}
	writeJSON(w, http.StatusOK, rules)
}

// listPolicyCompliance — отдельный эндпоинт, а не поля в /policies: агрегация ходит по
// всему парку и инвентарю, а список правил должен оставаться дешёвым. UI подтягивает
// счётчики вторым запросом и рисует их, когда придут.
func (h *Handler) listPolicyCompliance(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.ListSoftwarePolicyCompliance(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []storage.SoftwarePolicyCompliance{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// listPolicyDeviceCompliance — GET /policies/{id}/compliance: разрез одного софт-правила
// по устройствам области действия (кто pass, кто fail и что именно нашлось в инвентаре).
func (h *Handler) listPolicyDeviceCompliance(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.ListSoftwarePolicyDeviceCompliance(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []storage.SoftwarePolicyDeviceCompliance{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (h *Handler) listScriptPolicyCompliance(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.ListScriptPolicyCompliance(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []storage.ScriptPolicyCompliance{}
	}
	writeJSON(w, http.StatusOK, rows)
}

type createPolicyRequest struct {
	SoftwareName string   `json:"software_name"`
	RuleType     string   `json:"rule_type"`
	DeviceID     *string  `json:"device_id"`
	Platforms    []string `json:"platforms"` // пусто/все три = все платформы
}

// sanitizeSoftwareName приводит имя ПО к безопасному для агентского кэша виду и
// возвращает (очищенное, ok). Агент хранит forbidden-список ПОСТРОЧНО, где ведущий '#'
// и пустые строки — комментарии, а перевод строки — разделитель записей (list.go).
// Поэтому имя с '\n' расщепилось бы на два непреднамеренных паттерна, ведущий '#' сделал
// бы правило молчаливо неприменимым, а пробельное имя дало бы ложные Fail в compliance
// (strpos по ' '). Тримим и отвергаем пустое-после-trim, управляющие символы и '#'.
func sanitizeSoftwareName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f { // управляющие символы, включая \n \r \t
			return "", false
		}
	}
	return s, true
}

func (h *Handler) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req createPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	name, ok := sanitizeSoftwareName(req.SoftwareName)
	if !ok {
		http.Error(w, "software_name пустое или содержит недопустимые символы", http.StatusBadRequest)
		return
	}
	req.SoftwareName = name
	if req.RuleType != "allowed" && req.RuleType != "forbidden" {
		http.Error(w, "rule_type must be 'allowed' or 'forbidden'", http.StatusBadRequest)
		return
	}
	// Платформы: валидируем значения; пустой набор или все три = «все платформы» (nil-фильтр).
	validPlatform := map[string]bool{"macOS": true, "Windows": true, "Linux": true}
	seenPlatform := map[string]bool{}
	var platforms []string
	for _, p := range req.Platforms {
		if !validPlatform[p] {
			http.Error(w, "invalid platform: "+p, http.StatusBadRequest)
			return
		}
		if !seenPlatform[p] { // дедуп: дубли не должны раздувать scope до «все»
			seenPlatform[p] = true
			platforms = append(platforms, p)
		}
	}
	if len(platforms) >= 3 {
		platforms = nil // все три уникальные платформы = без фильтра
	}
	rule, err := h.db.CreatePolicyRule(r.Context(), req.SoftwareName, req.RuleType, req.DeviceID, platforms)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "create_policy", "policy", rule.ID,
		map[string]string{"software": req.SoftwareName, "rule_type": req.RuleType})
	writeJSON(w, http.StatusCreated, rule)
}

func (h *Handler) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.DeletePolicyRule(r.Context(), id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "delete_policy", "policy", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// maxDeviceSearchLen — потолок длины поисковой строки. Паттерн уходит в ILIKE по
// десятку колонок; километровый запрос — бесплатный способ сжечь CPU базы.
const maxDeviceSearchLen = 128

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if runes := []rune(query); len(runes) > maxDeviceSearchLen {
		query = string(runes[:maxDeviceSearchLen])
	}
	// group_id пустой = все устройства. Мусор вместо UUID отдаст пустой список
	// (сравнение по group_id::text в SQL), а не 500.
	groupID := strings.TrimSpace(r.URL.Query().Get("group_id"))
	devices, err := h.db.ListEnrolledDevices(r.Context(), query, groupID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if devices == nil {
		devices = []storage.Device{}
	}
	writeJSON(w, http.StatusOK, devices)
}

func (h *Handler) getDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	device, software, err := h.db.GetDevice(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device":   device,
		"software": software,
	})
}

type createTaskRequest struct {
	ScriptContent string `json:"script_content"`
	Platform      string `json:"platform"`
	Priority      string `json:"priority"`
}

func (h *Handler) createTask(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req createTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.ScriptContent == "" || req.Platform == "" {
		http.Error(w, "script_content and platform are required", http.StatusBadRequest)
		return
	}
	if req.Priority == "" {
		req.Priority = "medium"
	}

	task, err := h.db.CreateTask(r.Context(), id, req.ScriptContent, req.Platform, req.Priority)
	if err != nil {
		if errors.Is(err, storage.ErrDeviceNotActive) {
			http.Error(w, "device is not active (pending approval / blocked / rejected)", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := worker.Enqueue(h.asynqClient, task.ID); err != nil {
		http.Error(w, "enqueue failed", http.StatusInternalServerError)
		return
	}

	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "run_script", "device", id,
		map[string]string{"task_id": task.ID, "platform": req.Platform})
	writeJSON(w, http.StatusCreated, task)
}

type runScriptOnGroupRequest struct {
	ScriptID string `json:"script_id"`
	Priority string `json:"priority"`
}

// runScriptOnGroup — разовый прогон скрипта на всю группу (#3): fan-out по одной
// задаче на каждого совместимого по платформе члена. Живёт здесь (рядом с
// createTask), чтобы использовать h.asynqClient/worker без правки импортов
// script_policies_handler.go.
func (h *Handler) runScriptOnGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	var req runScriptOnGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.ScriptID == "" {
		http.Error(w, "script_id is required", http.StatusBadRequest)
		return
	}
	if req.Priority == "" {
		req.Priority = "medium"
	}

	script, err := h.db.GetScript(r.Context(), req.ScriptID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if script == nil {
		http.Error(w, "script not found", http.StatusNotFound)
		return
	}

	// Без этой проверки запуск на удалённой/опечатанной группе отдавал 201 created:0 —
	// в UI неотличимо от «в группе нет подходящих устройств».
	exists, err := h.db.DeviceGroupExists(r.Context(), groupID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	tasks, err := h.db.FanOutScriptToGroup(r.Context(), groupID,
		script.Content, script.Platform, req.Priority)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Задачи уже закоммичены (FanOut вернул RETURNING). Ошибка enqueue одной из них НЕ
	// повод ронять весь запрос в 500: pending-задачи персистентны, реконсайлер (main.go)
	// раз в минуту ре-энкьюит любую pending. Раньше 500 в середине веера провоцировал
	// ретрай оператора → FanOut создавал ЕЩЁ N задач → дубль запуска на всей группе.
	for _, t := range tasks {
		if err := worker.Enqueue(h.asynqClient, t.ID); err != nil {
			slog.Error("enqueue group task (доставит реконсайлер)", "task", t.ID, "err", err)
		}
	}

	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "run_script_on_group", "device_group", groupID,
		map[string]string{"script_id": req.ScriptID, "created": strconv.Itoa(len(tasks))})
	writeJSON(w, http.StatusCreated, map[string]int{"created": len(tasks)})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// noDirFileServer отдаёт файлы из dir, но возвращает 404 на запросы директорий —
// иначе http.FileServer рендерит листинг и раскрывает все имена релизов (M-5).
func noDirFileServer(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})
}

func (h *Handler) listTasks(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tasks, err := h.db.ListDeviceTasks(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if tasks == nil {
		tasks = []storage.Task{}
	}
	writeJSON(w, http.StatusOK, tasks)
}

type updateStatusRequest struct {
	Status string `json:"status"`
}

func (h *Handler) updateDeviceStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req updateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Status != "active" && req.Status != "blocked" {
		http.Error(w, "status must be 'active' or 'blocked'", http.StatusBadRequest)
		return
	}
	// Это ручка block/unblock (active↔blocked). НЕ бэкдор в managed-статусы: иначе
	// сервисный токен (не requireHuman) флипнул бы pending_approval→active в обход
	// approve, воскресил rejected/decommissioned. Их меняют только выделенные ручки
	// (approve/reject/decommission) с правильным гейтом.
	cur, err := h.db.GetDeviceStatusByID(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if cur == "" {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	switch cur {
	case "pending_approval", "rejected", "decommissioned":
		http.Error(w, "device in "+cur+": use approve/reject/decommission, not status", http.StatusConflict)
		return
	}
	if err := h.db.UpdateDeviceStatus(r.Context(), id, req.Status); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": req.Status})
	auditAction := "block_device"
	if req.Status == "active" {
		auditAction = "unblock_device"
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, auditAction, "device", id,
		map[string]any{"new_status": req.Status})

}

// deleteDevice удаляет устройство из инвентаря (списанное/переустановленное).
// ⚠️ Живой агент воскресит его следующим heartbeat — удаление предназначено для
// мёртвых записей. Каскад чистит связанные строки; recovery-эскроу (enterprise)
// блокирует удаление (409).
func (h *Handler) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	found, err := h.db.DeleteDevice(r.Context(), id)
	if errors.Is(err, storage.ErrDeviceHasEscrow) {
		http.Error(w, "device has recovery-key escrow records — resolve escrow before deleting", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "delete_device", "device", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listAdminAccessRequests(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")
	rows, err := h.db.ListAdminAccessRequests(r.Context(), statusFilter)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []storage.AdminAccessRequestRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

type respondAdminRequestReq struct {
	Decision        string `json:"decision"`
	DurationSeconds int    `json:"duration_seconds"`
}

// Границы срока выдачи админ-прав. Нижняя = минута: агент опрашивает статус раз в 30с
// (ROUTINEOPS_ADMIN_POLL), так что выдача короче минуты истекла бы раньше, чем доехала.
// Верхняя = 30 суток: временные права, а не постоянные.
const (
	minAdminGrantSeconds = 60
	maxAdminGrantSeconds = 30 * 24 * 3600
)

func (h *Handler) respondAdminRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	claims := r.Context().Value(claimsKey).(*jwtClaims)

	var req respondAdminRequestReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Decision != "approved" && req.Decision != "rejected" {
		http.Error(w, "decision must be 'approved' or 'rejected'", http.StatusBadRequest)
		return
	}

	var expiresAt *time.Time
	if req.Decision == "approved" {
		dur := req.DurationSeconds
		switch {
		case dur <= 0:
			// Явного срока нет — берём системную настройку, но не даём ей выйти за границы.
			defStr, _ := h.db.GetSystemSetting(r.Context(), "admin_request_default_duration")
			dur, _ = strconv.Atoi(defStr)
			if dur <= 0 {
				dur = 3600
			}
			dur = min(max(dur, minAdminGrantSeconds), maxAdminGrantSeconds)
		case dur < minAdminGrantSeconds || dur > maxAdminGrantSeconds:
			http.Error(w, "duration_seconds must be between 60 and 2592000", http.StatusBadRequest)
			return
		}
		t := time.Now().Add(time.Duration(dur) * time.Second)
		expiresAt = &t
	}

	if err := h.db.RespondToAdminRequest(r.Context(), id, req.Decision, claims.UserID, expiresAt); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": req.Decision})
	auditAction := "approve_admin_request"
	if req.Decision == "rejected" {
		auditAction = "reject_admin_request"
	}
	h.audit(r.Context(), claims.UserID, claims.Email, auditAction, "admin_request", id,
		map[string]any{"decision": req.Decision})

}

func (h *Handler) listAlerts(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device_id")
	// ponytail: фиксированный потолок 500 (клиентская фильтрация во фронте). Непринятые
	// идут первыми (см. ListAlerts), так что практически не теряются; при >500 непринятых
	// нужна серверная пагинация — апгрейд на тот момент.
	alerts, err := h.db.ListAlerts(r.Context(), deviceID, 500)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []storage.Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}

func (h *Handler) getTelegramStatus(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	chatID, linkToken, err := h.db.GetUserTelegramStatus(r.Context(), claims.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// bot_username пустой, если бот не настроен или Bot API недоступен — UI покажет
	// инструкцию без ссылки. Ссылку нельзя вшивать: у каждого деплоя свой бот.
	botUsername := ""
	if h.telegramBotUsername != nil {
		botUsername = h.telegramBotUsername(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"linked":       chatID != nil && *chatID != "",
		"link_token":   linkToken,
		"bot_username": botUsername,
	})
}

func (h *Handler) generateTelegramLinkToken(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(b)
	if err := h.db.SetUserLinkToken(r.Context(), claims.UserID, token); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (h *Handler) acknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.AcknowledgeAlert(r.Context(), id); err != nil {
		http.Error(w, "not found or already acknowledged", http.StatusBadRequest)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "acknowledge_alert", "alert", id, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

func (h *Handler) revokeAdminRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.db.RevokeAdminAccessRequest(r.Context(), id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "revoke_admin_request", "admin_request", id, nil)
}

// ====== Enrollment ======

type enrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	CSRPem          string `json:"csr_pem"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		http.Error(w, "enrollment not configured (CA key missing)", http.StatusServiceUnavailable)
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.EnrollmentToken == "" || req.CSRPem == "" {
		http.Error(w, "enrollment_token and csr_pem are required", http.StatusBadRequest)
		return
	}

	tok, err := h.db.GetEnrollmentToken(r.Context(), req.EnrollmentToken)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if tok == nil || tok.ExpiresAt.Before(time.Now()) {
		http.Error(w, "token not found or expired", http.StatusUnauthorized)
		return
	}

	// Bulk-токен (device_id NULL): устройство создаётся САМО, лимит/срок и статус
	// решает storage; легаси одноразовый токен (device_id задан) — прежний путь.
	if tok.DeviceID == "" {
		h.enrollBulk(w, r, tok, req)
		return
	}

	if tok.UsedAt != nil {
		http.Error(w, "token already used", http.StatusUnauthorized)
		return
	}

	deviceID := tok.DeviceID

	// Update hostname/os from agent if provided
	if req.Hostname != "" || req.OS != "" {
		_ = h.db.UpdatePendingDeviceInfo(r.Context(), deviceID, req.Hostname, req.OS)
	}

	certPEM, certSerial, fingerprint, err := h.ca.SignCSR([]byte(req.CSRPem), deviceID)
	if err != nil {
		slog.Error("enroll CSR parse", "err", err)
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}

	// Сохраняем отпечаток выданного серта: иначе после переустановки heartbeat
	// создаст дубль устройства вместо обновления (БАГ 4).
	if err := h.db.EnrollDevice(r.Context(), tok.ID, deviceID, certSerial, fingerprint); err != nil {
		if errors.Is(err, storage.ErrDeviceNotEnrollable) {
			// Списанное/заблокированное/неодобренное устройство не возвращается в строй
			// само по уцелевшему токену — только решением оператора.
			http.Error(w, "device status forbids enroll", http.StatusForbidden)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"device_id":      deviceID,
		"cert_pem":       string(certPEM),
		"ca_pem":         string(h.ca.CAPem()),
		"release_pubkey": h.releasePubKey, // универсальный агент берёт ключ self-update отсюда
	})
}

// enrollBulk — энролл по многоразовому bulk-токену: устройство создаётся само,
// лимит/срок и статус (pending_approval vs enrolled) решает storage. Ответ идентичен
// обычному энроллу (агент не различает bulk/single).
func (h *Handler) enrollBulk(w http.ResponseWriter, r *http.Request, tok *storage.EnrollmentToken, req enrollRequest) {
	// Резервируем использование + создаём устройство ДО подписи (CN серта = id устройства).
	deviceID, requireApproval, err := h.db.BeginBulkEnroll(r.Context(), tok.ID, req.Hostname, req.OS)
	if err != nil {
		if errors.Is(err, storage.ErrEnrollTokenAlreadyUsed) {
			http.Error(w, "token exhausted or expired", http.StatusUnauthorized)
			return
		}
		slog.Error("bulk enroll begin", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	certPEM, certSerial, fingerprint, err := h.ca.SignCSR([]byte(req.CSRPem), deviceID)
	if err != nil {
		slog.Error("bulk enroll CSR parse", "err", err)
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}

	if err := h.db.FinalizeBulkEnroll(r.Context(), deviceID, certSerial, fingerprint, requireApproval); err != nil {
		slog.Error("bulk enroll finalize", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"device_id":      deviceID,
		"cert_pem":       string(certPEM),
		"ca_pem":         string(h.ca.CAPem()),
		"release_pubkey": h.releasePubKey,
	})
}

type createPendingDeviceRequest struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

func (h *Handler) createPendingDevice(w http.ResponseWriter, r *http.Request) {
	var req createPendingDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Hostname == "" {
		http.Error(w, "hostname is required", http.StatusBadRequest)
		return
	}
	if req.OS == "" {
		req.OS = "unknown"
	}

	device, err := h.db.CreatePendingDevice(r.Context(), req.Hostname, req.OS)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	token := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)
	if err := h.db.CreateEnrollmentToken(r.Context(), device.ID, token, expiresAt); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// ca_sha256 — пин CA-бандла для универсального MSI: msiexec ... CA_URL=.. CA_SHA256=..;
	// агент качает CA по CA_URL и сверяет с пином (TOFU без пина отклоняется, SEC-1).
	caSHA256 := ""
	if h.ca != nil {
		caSum := sha256.Sum256(h.ca.CAPem())
		caSHA256 = hex.EncodeToString(caSum[:])
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"device":           device,
		"enrollment_token": token,
		"expires_at":       expiresAt,
		"ca_sha256":        caSHA256,
	})
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "create_device", "device", device.ID,
		map[string]any{"hostname": device.Hostname})
}

func (h *Handler) getEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tok, err := h.db.GetActiveEnrollmentToken(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if tok == nil {
		http.Error(w, "no active enrollment token", http.StatusNotFound)
		return
	}
	// N6: plaintext-токен хранится хешированным и здесь недоступен. Отдаём только
	// факт наличия активного токена и срок. Сам токен выдаётся один раз при
	// create/reenroll; потерян → перевыпустить (reenrollDevice).
	writeJSON(w, http.StatusOK, map[string]any{
		"expires_at": tok.ExpiresAt,
	})
}

// ====== Agent self-update manifest ======

func (h *Handler) agentVersion(w http.ResponseWriter, r *http.Request) {
	osParam := r.URL.Query().Get("os")
	archParam := r.URL.Query().Get("arch")
	if osParam == "" || archParam == "" {
		http.Error(w, "os and arch are required", http.StatusBadRequest)
		return
	}
	// "current" is informational only — we always return the latest manifest.
	// The agent calls IsNewer client-side and skips the download if already up to date.

	rel, err := h.db.GetLatestAgentRelease(r.Context(), osParam, archParam)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if rel == nil {
		http.Error(w, "no release for this os/arch", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"version":            rel.Version,
		"url":                fmt.Sprintf("%s/downloads/%s", h.publicWebURL, rel.Filename),
		"sha256":             rel.SHA256,
		"signature":          rel.Signature,         // над sha256(бинарь) — старые агенты
		"manifest_signature": rel.ManifestSignature, // над version\nos\narch\nsha256 — SEC-3
	})
}

func (h *Handler) lockDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Reason string `json:"reason"`
		Mode   string `json:"mode"` // "overlay" (дефолт) | "filevault"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Fail-safe разбор режима через lockPolicy (open-core: overlay-only; enterprise
	// разрешает filevault при готовом escrow). Деструктивный FILEVAULT-лок требует
	// эскроу recovery-ключа ДО revoke Secure Token — иначе кирпич. Явный 409 (фича не
	// готова/enterprise) вместо тихой деградации в overlay: админ должен это знать.
	if err := h.lockPolicy.ValidateMode(req.Mode); err != nil {
		if errors.Is(err, ErrLockModeUnavailable) {
			http.Error(w, "filevault lock unavailable: enterprise feature / escrow disabled", http.StatusConflict)
			return
		}
		http.Error(w, "invalid lock mode (want overlay|filevault)", http.StatusBadRequest)
		return
	}
	lockMode := storage.LockModeOverlay
	if req.Mode == storage.LockModeFileVault {
		lockMode = storage.LockModeFileVault
	}

	// generate 12-char random password (plaintext returned to admin, hash sent to agent)
	rawBytes := make([]byte, 9)
	if _, err := rand.Read(rawBytes); err != nil {
		http.Error(w, "failed to generate password", http.StatusInternalServerError)
		return
	}
	password := hex.EncodeToString(rawBytes)[:12]

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	task, err := h.db.CreateLockTask(r.Context(), id, string(hashBytes), req.Reason, false, lockMode)
	if err != nil {
		http.Error(w, "failed to create lock task", http.StatusInternalServerError)
		return
	}
	// Желаемое состояние = locked: источник правды для реконсиляции (FetchLockStatus).
	// Таск ниже — быстрый push; поллинг агента подхватит то же состояние после ребута.
	if err := h.db.SetDeviceLockState(r.Context(), id, "locked", string(hashBytes), req.Reason, lockMode, task.ID); err != nil {
		http.Error(w, "failed to persist lock state", http.StatusInternalServerError)
		return
	}
	if err := worker.Enqueue(h.asynqClient, task.ID); err != nil {
		slog.Error("enqueue lock task", "task_id", task.ID, "err", err)
		http.Error(w, "enqueue failed", http.StatusInternalServerError)
		return
	}

	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "lock_device", "device", id,
		map[string]string{"task_id": task.ID, "reason": req.Reason, "mode": lockMode})
	writeJSON(w, http.StatusOK, map[string]string{"task_id": task.ID, "password": password})
}

func (h *Handler) unlockDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	task, err := h.db.CreateLockTask(r.Context(), id, "", "", true, storage.LockModeOverlay)
	if err != nil {
		http.Error(w, "failed to create unlock task", http.StatusInternalServerError)
		return
	}
	// Желаемое состояние = unlocked, хеш/причина очищаются, режим сброшен в overlay:
	// реконсиляция уведёт агента из lock даже если push-таск не дойдёт.
	if err := h.db.SetDeviceLockState(r.Context(), id, "unlocked", "", "", storage.LockModeOverlay, ""); err != nil {
		http.Error(w, "failed to persist unlock state", http.StatusInternalServerError)
		return
	}
	if err := worker.Enqueue(h.asynqClient, task.ID); err != nil {
		slog.Error("enqueue unlock task", "task_id", task.ID, "err", err)
		http.Error(w, "enqueue failed", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "unlock_device", "device", id, nil)
	writeJSON(w, http.StatusOK, map[string]string{"task_id": task.ID})
}

// decommissionDevice ставит задачу полного самоудаления агента (вывод устройства из
// эксплуатации). requireHuman (см. маршрут): необратимая деструктивная операция.
// Статус устройства здесь НЕ меняем — оно должно принять Connect, чтобы получить
// команду сноса; терминальный флип в 'decommissioned' делает gateway.ReportTaskResult
// по подтверждению агента. reason — только для аудита (агенту едет фиксированный текст).
func (h *Handler) decommissionDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Reason string `json:"reason"`
	}
	// Тело необязательно (reason — advisory для аудита); пустой/битый body не блокирует.
	_ = json.NewDecoder(r.Body).Decode(&req)

	// Guard: устройство существует и ещё не списано (не плодим мёртвые задачи —
	// списанное всё равно не примет Connect, задача бы висела pending до свипа).
	st, err := h.db.GetDeviceStatusByID(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if st == "" {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	if st == "decommissioned" {
		http.Error(w, "device already decommissioned", http.StatusConflict)
		return
	}

	task, err := h.db.CreateDecommissionTask(r.Context(), id)
	if err != nil {
		http.Error(w, "failed to create decommission task", http.StatusInternalServerError)
		return
	}
	if err := worker.Enqueue(h.asynqClient, task.ID); err != nil {
		slog.Error("enqueue decommission task", "task_id", task.ID, "err", err)
		http.Error(w, "enqueue failed", http.StatusInternalServerError)
		return
	}

	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "decommission_device", "device", id,
		map[string]string{"task_id": task.ID, "reason": req.Reason})
	writeJSON(w, http.StatusOK, map[string]string{"task_id": task.ID})
}

// bulkTokenDefaultTTLHours — окно раскатки по умолчанию для bulk-токена (7 дней),
// длиннее одноразового (24ч): GPO-раскатка по парку занимает не один день.
const bulkTokenDefaultTTLHours = 168

type bulkEnrollTokenRequest struct {
	GroupID         string `json:"group_id"`         // "" = без группы
	MaxUses         *int   `json:"max_uses"`         // nil = безлимит до TTL
	RequireApproval *bool  `json:"require_approval"` // nil = true (очередь одобрения ВКЛ по умолчанию)
	TTLHours        int    `json:"ttl_hours"`        // 0 = дефолт
}

// issueBulkEnrollmentToken выпускает многоразовый bulk-токен (requireHuman: токен
// даёт устройствам вход в парк — выпускает доступ, только человеком). Возвращает
// токен + ca_sha256 для параметров MSI (server URL + CA_SHA256 + токен → GPO).
func (h *Handler) issueBulkEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req bulkEnrollTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	requireApproval := true // дефолт: очередь одобрения включена (нельзя запирать за деньги смягчение риска)
	if req.RequireApproval != nil {
		requireApproval = *req.RequireApproval
	}
	if req.MaxUses != nil && *req.MaxUses <= 0 {
		http.Error(w, "max_uses must be positive (omit for unlimited)", http.StatusBadRequest)
		return
	}
	ttl := time.Duration(bulkTokenDefaultTTLHours) * time.Hour
	if req.TTLHours > 0 {
		ttl = time.Duration(req.TTLHours) * time.Hour
	}
	token := uuid.New().String()
	expiresAt := time.Now().Add(ttl)
	if err := h.db.CreateBulkEnrollmentToken(r.Context(), token, req.GroupID, req.MaxUses, requireApproval, expiresAt); err != nil {
		slog.Error("create bulk token", "err", err)
		http.Error(w, "internal error (invalid group_id?)", http.StatusInternalServerError)
		return
	}

	caSHA256 := ""
	if h.ca != nil {
		caSum := sha256.Sum256(h.ca.CAPem())
		caSHA256 = hex.EncodeToString(caSum[:])
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "create_bulk_token", "enrollment_token", "",
		map[string]any{"group_id": req.GroupID, "require_approval": requireApproval, "max_uses": req.MaxUses})
	writeJSON(w, http.StatusCreated, map[string]any{
		"enrollment_token": token,
		"expires_at":       expiresAt,
		"ca_sha256":        caSHA256,
		"require_approval": requireApproval,
	})
}

// listBulkEnrollmentTokens — что прямо сейчас позволяет заводить устройства в парке.
// Секретов в ответе нет: в БД лежит только хеш, плейнтекст отдавался один раз при
// выпуске. Без этой ручки выпущенный массовый токен был невидим — узнать, сколько их
// живых и сколько раз ими воспользовались, было неоткуда.
func (h *Handler) listBulkEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.db.ListBulkEnrollmentTokens(r.Context())
	if err != nil {
		slog.Error("list bulk tokens", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

// revokeEnrollmentToken гасит выпущенный токен (и массовый, и одноразовый device-токен).
// Массовый токен — стоячий креденшл: он многоразовый, живёт неделями и лежит в
// enroll.env на каждом энроллящемся хосте. Утёк — до этой ручки погасить его было
// нечем, оставалось ждать expires_at.
// requireHuman НЕ ставим: отзыв отбирает права, а не выдаёт (см. правило выше), и
// запрещать его автоматике вредно — гасить утёкший креденшл надо немедленно.
func (h *Handler) revokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	ok, err := h.db.RevokeEnrollmentToken(r.Context(), id)
	if err != nil {
		slog.Error("revoke enrollment token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "token not found or already expired", http.StatusConflict)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "revoke_enrollment_token", "enrollment_token", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// approveDevice одобряет устройство из очереди (requireHuman: решение о членстве в
// парке — человеком). pending_approval → active.
func (h *Handler) approveDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ok, err := h.db.ApproveDevice(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "device not in approval queue", http.StatusConflict)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "approve_device", "device", id, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "active"})
}

// rejectDevice отклоняет устройство из очереди (НЕ requireHuman: защитное действие —
// закрывает доступ, автоматике запрещать вредно, как revoke admin-request).
// pending_approval → rejected (gateway режет Connect).
func (h *Handler) rejectDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ok, err := h.db.RejectDevice(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "device not in approval queue", http.StatusConflict)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "reject_device", "device", id, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

type pendingBatchRequest struct {
	GroupID string `json:"group_id"` // "" = все pending_approval
}

// approvePendingDevices — batch-одобрение всей очереди (± фильтр по группе). requireHuman.
func (h *Handler) approvePendingDevices(w http.ResponseWriter, r *http.Request) {
	var req pendingBatchRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // тело опционально
	n, err := h.db.ApprovePendingDevices(r.Context(), req.GroupID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "approve_pending_bulk", "device", "",
		map[string]any{"group_id": req.GroupID, "count": n})
	writeJSON(w, http.StatusOK, map[string]int64{"approved": n})
}

// rejectPendingDevices — batch-отклонение (симметрично, НЕ requireHuman).
func (h *Handler) rejectPendingDevices(w http.ResponseWriter, r *http.Request) {
	var req pendingBatchRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	n, err := h.db.RejectPendingDevices(r.Context(), req.GroupID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "reject_pending_bulk", "device", "",
		map[string]any{"group_id": req.GroupID, "count": n})
	writeJSON(w, http.StatusOK, map[string]int64{"rejected": n})
}

func (h *Handler) reenrollDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	token := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)
	if err := h.db.ResetDeviceForReenroll(r.Context(), id, token, expiresAt); err != nil {
		// Несуществующее устройство сюда же: WHERE не нашёл строку — 409 честнее 500-й.
		if errors.Is(err, storage.ErrDeviceNotReenrollable) {
			http.Error(w, "device status forbids reenroll: use approve/unblock first", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enrollment_token": token,
		"expires_at":       expiresAt,
	})
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "reenroll_device", "device", id, nil)
}

func (h *Handler) getCACert(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		http.Error(w, "CA not configured", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ca.crt"`)
	w.Write(h.ca.CAPem())
}

func (h *Handler) getInstaller(w http.ResponseWriter, r *http.Request) {
	osParam := r.URL.Query().Get("os")
	arch := r.URL.Query().Get("arch")
	token := r.URL.Query().Get("token")
	if osParam == "" || arch == "" || token == "" {
		http.Error(w, "os, arch, token required", http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(token); err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	rel, err := h.db.GetLatestAgentRelease(r.Context(), osParam, arch)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// CA нужен для пина скачивания (см. ниже). Без него скрипт бесполезен.
	if h.ca == nil {
		http.Error(w, "CA unavailable", http.StatusServiceUnavailable)
		return
	}

	serverURL := h.publicWebURL
	enrollURL := serverURL + "/api/v1/enroll"
	caURL := serverURL + "/ca.crt"
	// sha256-пин CA-бандла: агент качает CA по -ca-url и сверяет с этим хешем
	// (TOFU-скачивание без пина отклоняется, SEC-1). Заменяет небезопасный
	// ручной curl "-o ca.crt" + "-ca <файл>", который принимал rogue-CA при MITM.
	caSum := sha256.Sum256(h.ca.CAPem())
	caSHA256 := hex.EncodeToString(caSum[:])

	// extract hostname for gRPC server address (port 50051)
	grpcAddr := serverURL
	// httpBase — HTTP-адрес того же хоста для скачивания бинаря агента (см. ниже).
	httpBase := serverURL
	if u, err := url.Parse(serverURL); err == nil {
		grpcAddr = u.Hostname() + ":50051"
		httpBase = "http://" + u.Host
	}

	// Бинарь агента скачиваем по HTTP и сверяем sha256-пин (rel.SHA256): бинарь
	// публичный, целостность даёт хеш, поэтому доверие к TLS-сертификату сервера тут
	// не требуется. На дефолтном IP/self-signed деплое HTTPS-скачивание
	// (Invoke-WebRequest/curl) иначе падает на непроверяемом сертификате. Канал
	// enroll (ca-url по -ca-sha256 + gRPC/mTLS) остаётся защищённым пином CA.
	var script, filename string
	if osParam == "windows" {
		filename = "install-mdm.ps1"
		downloadLine := `# Поместите RoutineOps-agent.exe в $InstallDir вручную`
		if rel != nil {
			downloadLine = fmt.Sprintf(`Invoke-WebRequest -Uri "%s/downloads/%s" -OutFile "$InstallDir\RoutineOps-agent.exe"
$actual = (Get-FileHash "$InstallDir\RoutineOps-agent.exe" -Algorithm SHA256).Hash.ToLower()
if ($actual -ne "%s") { throw "sha256 mismatch: $actual" }`, httpBase, rel.Filename, rel.SHA256)
		}
		script = fmt.Sprintf(`$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\RoutineOps"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
%s
& "$InstallDir\RoutineOps-agent.exe" enroll -enroll-url "%s" -token "%s" -ca-url "%s" -ca-sha256 "%s" -server "%s" -install-service
Write-Host "RoutineOps agent installed and started."
`, downloadLine, enrollURL, token, caURL, caSHA256, grpcAddr)
	} else {
		filename = "install-mdm.sh"
		installDir := "/usr/local/bin"
		downloadLine := "# Поместите бинарь RoutineOps-agent в " + installDir + " вручную"
		if rel != nil {
			downloadLine = fmt.Sprintf(`curl -fsSL "%s/downloads/%s" -o %s/RoutineOps-agent
DIGEST="$(sha256sum %s/RoutineOps-agent 2>/dev/null | awk '{print $1}' || shasum -a 256 %s/RoutineOps-agent | awk '{print $1}')"
[ "$DIGEST" = "%s" ] || { echo "sha256 mismatch: $DIGEST" >&2; exit 1; }
chmod +x %s/RoutineOps-agent`, httpBase, rel.Filename, installDir, installDir, installDir, rel.SHA256, installDir)
		}
		script = fmt.Sprintf(`#!/bin/bash
set -e
%s
RoutineOps-agent enroll -enroll-url "%s" -token "%s" -ca-url "%s" -ca-sha256 "%s" -server "%s" -install-service
echo "RoutineOps agent installed and started."
`, downloadLine, enrollURL, token, caURL, caSHA256, grpcAddr)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, script)
}

// ---- Users ----

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.db.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []storage.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

type inviteUserRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (h *Handler) inviteUser(w http.ResponseWriter, r *http.Request) {
	var req inviteUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "viewer" // least-privilege: неуказанная роль = наименьшие права
	}
	if !validRoles[req.Role] {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}

	claims := r.Context().Value(claimsKey).(*jwtClaims)
	tb := make([]byte, 32)
	if _, err := rand.Read(tb); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(tb)
	if _, err := h.db.CreateInvitation(r.Context(), req.Email, req.Role, token, claims.UserID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(r.Context(), claims.UserID, claims.Email, "invite_user", "user", "",
		map[string]string{"email": req.Email, "role": req.Role})

	inviteURL := fmt.Sprintf("%s/accept-invite?token=%s", h.publicWebURL, token)
	// SMTP может быть выключен (SMTP_HOST пуст) — тогда Send/SendInvite — no-op,
	// возвращающий nil, а НЕ ошибку (mailer.go). Без этой ветки мы бы отвечали
	// "email_sent:true" без invite_url, и пригласить кого-либо было бы невозможно:
	// письмо не ушло, ссылки нет. Отдаём ссылку оператору, чтобы он передал её вручную —
	// тот же контракт, что и в ветке сбоя отправки ниже.
	if !h.mailer.Enabled() {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":     "invited",
			"email_sent": "false",
			"invite_url": inviteURL,
		})
		return
	}
	if err := h.mailer.SendInvite(req.Email, inviteURL); err != nil {
		slog.Error("send invite email", "to", req.Email, "err", err)
		writeJSON(w, http.StatusOK, map[string]string{
			"status":     "invited",
			"email_sent": "false",
			"invite_url": inviteURL,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "invited", "email_sent": "true"})
}

// ---- Accept invite ----

func (h *Handler) getInvite(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	inv, err := h.db.GetInvitationByToken(r.Context(), token)
	if err != nil || inv == nil || inv.AcceptedAt != nil || inv.ExpiresAt.Before(time.Now()) {
		http.Error(w, "invalid or expired invite", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": inv.Email, "role": inv.Role})
}

type acceptInviteRequest struct {
	Token    string `json:"token"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (h *Handler) acceptInvite(w http.ResponseWriter, r *http.Request) {
	var req acceptInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	inv, err := h.db.GetInvitationByToken(r.Context(), req.Token)
	if err != nil || inv == nil || inv.AcceptedAt != nil || inv.ExpiresAt.Before(time.Now()) {
		http.Error(w, "invalid or expired invite", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newUser, err := h.db.CreateUser(r.Context(), req.Name, inv.Email, string(hash), inv.Role)
	if err != nil {
		http.Error(w, "user already exists or internal error", http.StatusConflict)
		return
	}
	if err := h.db.AcceptInvitation(r.Context(), req.Token); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.audit(r.Context(), newUser.ID, newUser.Email, "accept_invite", "user", newUser.ID,
		map[string]string{"role": inv.Role})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- Password reset ----

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

func (h *Handler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// Always return 200 to not leak user existence
	user, _ := h.db.GetUserByEmail(r.Context(), req.Email)
	if user != nil {
		tb := make([]byte, 32)
		_, _ = rand.Read(tb)
		token := hex.EncodeToString(tb)
		_ = h.db.CreatePasswordResetToken(r.Context(), user.ID, token)
		h.audit(r.Context(), user.ID, user.Email, "password_reset_requested", "user", user.ID, nil)
		resetURL := fmt.Sprintf("%s/reset-password?token=%s", h.publicWebURL, token)
		// Ответ всегда 200 (анти-энумерация), но ошибку мейлера логируем — иначе
		// оператор не увидит, почему письма сброса не доходят (напр. SMTP-мисконфиг).
		if err := h.mailer.SendPasswordReset(req.Email, resetURL); err != nil {
			slog.Error("send password reset email", "err", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	t, err := h.db.GetPasswordResetToken(r.Context(), req.Token)
	if err != nil || t == nil || t.UsedAt != nil || t.ExpiresAt.Before(time.Now()) {
		http.Error(w, "invalid or expired token", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.db.UpdateUserPassword(r.Context(), t.UserID, string(hash)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.db.MarkPasswordResetTokenUsed(r.Context(), req.Token); err != nil {
		slog.Error("mark password reset token used", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var resetEmail string
	if u, uerr := h.db.GetUserByID(r.Context(), t.UserID); uerr == nil && u != nil {
		resetEmail = u.Email
	}
	h.audit(r.Context(), t.UserID, resetEmail, "password_reset", "user", t.UserID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
