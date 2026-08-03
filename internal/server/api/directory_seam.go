package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Шов enterprise-каталога (LDAP). Паттерн 1:1 с escrow: интерфейс во free-пакете,
// реализация в enterprise-оверлее (internal/server/directory, //go:build enterprise),
// регистрация через RouterOption в enterprise composition-root. Open-core НЕ регистрирует
// → h.directorySvc == nil → /directory/* отвечают 501. go-ldap живёт только в оверлее,
// в open-core-графе его нет (leak-guard).

// DirectoryConfig — конфиг подключения к каталогу. Bind-пароль сюда НЕ входит (секрет,
// хранится отдельно в rw-томе); в ответе GET отдаётся HasPassword-флаг, сам пароль — нет.
type DirectoryConfig struct {
	Enabled         bool   `json:"enabled"`
	URL             string `json:"url"` // ldaps://host:636
	BindDN          string `json:"bind_dn"`
	BaseDN          string `json:"base_dn"`
	UserFilter      string `json:"user_filter"`       // напр. (&(objectClass=user)(objectCategory=person))
	SyncIntervalMin int    `json:"sync_interval_min"` // 0 = только вручную
	HasPassword     bool   `json:"has_password"`      // только в ответе: задан ли bind-пароль
	// StartTLS — поднять TLS на уже открытом ldap://-соединении. Третий режим поверх
	// схемы URL: ldaps:// = неявный TLS, ldap:// = открытый канал, ldap:// + start_tls =
	// апгрейд. Взаимоисключающ с ldaps:// (двойной TLS бессмыслен) — validate отбивает.
	StartTLS bool `json:"start_tls"`
	// HasCACert — только в ответе: задан ли корневой сертификат каталога. Сам PEM
	// наружу не отдаётся никогда (симметрично bind-паролю): он не секрет, но его
	// наличие достаточно, а лишний вынос содержимого — лишняя поверхность.
	HasCACert bool `json:"has_ca_cert"`
	// LoginEnabled — разрешить вход в панель по паролю каталога. ОТДЕЛЬНЫЙ флаг, а не
	// следствие Enabled: синк персон и приём пароля на вход — разные по риску вещи, и
	// включение каталога ради инвентаря не должно молча открывать второй путь
	// аутентификации. Нулевое значение = сегодняшнее поведение, поэтому уже
	// сохранённые config.json миграции не требуют (та же логика, что у StartTLS).
	LoginEnabled bool `json:"login_enabled"`
}

// DirectorySyncResult — итог синка каталога.
type DirectorySyncResult struct {
	Synced   int `json:"synced"`   // персон записано/обновлено
	Disabled int `json:"disabled"` // помечено disabled (исчезли из выдачи)
	Matched  int `json:"matched"`  // устройств привязано к владельцу
}

// DirectoryService — enterprise-каталог. Реализация — internal/server/directory
// (//go:build enterprise).
type DirectoryService interface {
	GetConfig(ctx context.Context) (DirectoryConfig, error)
	// SetConfig: bindPassword=="" и caCertPEM=="" НЕ трогают уже сохранённые значения —
	// UI не показывает ни пароль, ни PEM и шлёт пустые строки при правке прочих полей.
	SetConfig(ctx context.Context, cfg DirectoryConfig, bindPassword, caCertPEM string) error
	TestConnection(ctx context.Context) error
	SyncNow(ctx context.Context) (DirectorySyncResult, error)
	// Authenticate проверяет пару логин/пароль по каталогу: ищет ровно одну запись под
	// сервисным bind, затем делает simple bind её DN с присланным паролем.
	//
	// ok=false, err==nil — каталог ответил «не тот пароль/нет такого». err!=nil —
	// каталог недоступен или настроен не так; звонящий обязан различать эти два случая
	// и НЕ выдавать токен во втором. Ответ каталога никогда не заменяет проверку того,
	// что аккаунт в панели существует: заводить пользователей вход по LDAP не должен.
	Authenticate(ctx context.Context, login, password string) (ok bool, err error)
}

// WithDirectoryService подключает enterprise-каталог. Зовётся ТОЛЬКО в enterprise
// composition-root (cmd/server, //go:build enterprise) после лиц-гейта.
func WithDirectoryService(svc DirectoryService) RouterOption {
	return func(h *Handler) { h.directorySvc = svc }
}

// directoryUnavailable — единый 501 open-core: фичи физически нет (нет go-ldap-кода).
func (h *Handler) directoryUnavailable(w http.ResponseWriter) bool {
	if h.directorySvc == nil {
		http.Error(w, "directory (LDAP) is an enterprise feature (not built)", http.StatusNotImplemented)
		return true
	}
	return false
}

// directoryLogin — проверка пароля по каталогу для login. Вынесено в шов, а не сделано
// по месту: в open-core h.directorySvc == nil, и тогда это молчаливое false, а не 501 —
// человеку на входе сообщать про несобранную enterprise-фичу нечего, он с точки зрения
// панели просто не тот пароль ввёл.
func (h *Handler) directoryLogin(ctx context.Context, login, password string) bool {
	if h.directorySvc == nil {
		return false
	}
	ok, err := h.directorySvc.Authenticate(ctx, login, password)
	if err != nil {
		// 🔴 Недоступный или неверно настроенный каталог — это НЕ разрешение войти:
		// fail-closed, иначе отвалившийся DC становился бы способом обойти пароль.
		// Локальный пароль при этом уже проверен выше и не зависит от этой ветки.
		slog.Warn("directory: вход по каталогу не проверен", "login", login, "err", err)
		return false
	}
	return ok
}

func (h *Handler) getDirectoryConfig(w http.ResponseWriter, r *http.Request) {
	if h.directoryUnavailable(w) {
		return
	}
	cfg, err := h.directorySvc.GetConfig(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (h *Handler) setDirectoryConfig(w http.ResponseWriter, r *http.Request) {
	if h.directoryUnavailable(w) {
		return
	}
	var req struct {
		DirectoryConfig
		BindPassword string `json:"bind_password"` // "" = не менять существующий пароль
		// CACertPEM — write-only, как и пароль: приходит в PUT, наружу не возвращается.
		CACertPEM string `json:"ca_cert_pem"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := h.directorySvc.SetConfig(r.Context(), req.DirectoryConfig, req.BindPassword, req.CACertPEM); err != nil {
		http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	// В аудит — метаданные, НЕ пароль.
	h.audit(r.Context(), claims.UserID, claims.Email, "set_directory_config", "directory", "",
		// Транспорт — часть модели доверия: по нему видно, ходил ли сервер к каталогу
		// открытым каналом. Содержимое PEM не пишем, только факт замены.
		map[string]any{
			"url": req.URL, "base_dn": req.BaseDN, "enabled": req.Enabled,
			"start_tls": req.StartTLS, "ca_cert_replaced": req.CACertPEM != "",
			// Второй путь аутентификации в панель — тоже часть модели доверия: по
			// журналу должно быть видно, когда его открыли и кто.
			"login_enabled": req.LoginEnabled,
		})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) testDirectory(w http.ResponseWriter, r *http.Request) {
	if h.directoryUnavailable(w) {
		return
	}
	if err := h.directorySvc.TestConnection(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "error", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) syncDirectory(w http.ResponseWriter, r *http.Request) {
	if h.directoryUnavailable(w) {
		return
	}
	res, err := h.directorySvc.SyncNow(r.Context())
	if err != nil {
		http.Error(w, "sync failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "sync_directory", "directory", "",
		map[string]any{"synced": res.Synced, "disabled": res.Disabled, "matched": res.Matched})
	writeJSON(w, http.StatusOK, res)
}

// listDirectoryPersons — читает directory_persons из ОБЩЕЙ БД (в Free пусто: синка нет).
// Не гейтит на сервис — список персон это просто данные; UI страницу «Каталог»
// показывает лишь в enterprise. Роут под it_admin (см. handler.go).
func (h *Handler) listDirectoryPersons(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	persons, err := h.db.ListDirectoryPersons(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if persons == nil {
		persons = []storage.DirectoryPerson{}
	}
	writeJSON(w, http.StatusOK, persons)
}
