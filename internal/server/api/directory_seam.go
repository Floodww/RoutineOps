package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/go-chi/chi/v5"
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
	SetConfig(ctx context.Context, cfg DirectoryConfig, bindPassword string) error // bindPassword=="" не меняет
	TestConnection(ctx context.Context) error
	SyncNow(ctx context.Context) (DirectorySyncResult, error)
}

// WithDirectoryService подключает enterprise-каталог. Зовётся ТОЛЬКО в enterprise
// composition-root (cmd/server, //go:build enterprise) после лиц-гейта.
func WithDirectoryService(svc DirectoryService) RouterOption {
	return func(h *Handler, _ chi.Router) { h.directorySvc = svc }
}

// directoryUnavailable — единый 501 open-core: фичи физически нет (нет go-ldap-кода).
func (h *Handler) directoryUnavailable(w http.ResponseWriter) bool {
	if h.directorySvc == nil {
		http.Error(w, "directory (LDAP) is an enterprise feature (not built)", http.StatusNotImplemented)
		return true
	}
	return false
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
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := h.directorySvc.SetConfig(r.Context(), req.DirectoryConfig, req.BindPassword); err != nil {
		http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	// В аудит — метаданные, НЕ пароль.
	h.audit(r.Context(), claims.UserID, claims.Email, "set_directory_config", "directory", "",
		map[string]any{"url": req.URL, "base_dn": req.BaseDN, "enabled": req.Enabled})
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
	persons, err := h.db.ListDirectoryPersons(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if persons == nil {
		persons = []storage.DirectoryPerson{}
	}
	writeJSON(w, http.StatusOK, persons)
}
