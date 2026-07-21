package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/go-chi/chi/v5"
)

// maxAPITokenNameLen — то же ограничение, что у имён групп: имя попадает в журнал
// аудита как "token:<имя>", и длинная строка ломала бы чтение журнала.
const maxAPITokenNameLen = 128

// maxAPITokenTTLDays — потолок срока. Не про политику, а про арифметику: огромное
// значение переполняет time.Time внутри AddDate и заворачивается в ПРОШЛОЕ, из-за чего
// сервер отдавал 201 с мёртвым токеном (SQL-предикат expires_at > now() отвергает его
// на первом же вызове), а плейнтекст показывается один раз и невосстановим. Десять лет
// — заведомо больше любого разумного срока и заведомо меньше границы переполнения.
const maxAPITokenTTLDays = 3650

func (h *Handler) listAPITokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.db.ListAPITokens(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

type createAPITokenRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
	// ExpiresInDays — 0/отсутствует означает бессрочный токен.
	ExpiresInDays int `json:"expires_in_days"`
}

// createAPITokenResponse — ЕДИНСТВЕННОЕ место, где плейнтекст токена покидает сервер.
// Дальше он невосстановим: в БД лежит только SHA-256, список его не отдаёт.
type createAPITokenResponse struct {
	storage.APIToken
	Token string `json:"token"`
}

func (h *Handler) createAPIToken(w http.ResponseWriter, r *http.Request) {
	var req createAPITokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if len([]rune(name)) > maxAPITokenNameLen {
		http.Error(w, "name is too long", http.StatusBadRequest)
		return
	}
	// Роль обязательна и проверяется явно: пустая строка молча создала бы токен,
	// не совпадающий ни с одной ролью, — то есть бесполезный, но выглядящий рабочим
	// (requireRole сравнивает точным равенством, иерархии ролей нет).
	if !validRoles[req.Role] {
		http.Error(w, "role must be it_admin or viewer", http.StatusBadRequest)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	// Выдать токен с правами ВЫШЕ собственных нельзя. Сейчас создание висит под
	// requireRole("it_admin"), так что ветка недостижима, — но она стоит здесь
	// намеренно: если роутинг когда-нибудь ослабят, viewer не сможет выписать
	// себе админский токен и повысить права.
	if req.Role == "it_admin" && claims.Role != "it_admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if req.ExpiresInDays < 0 || req.ExpiresInDays > maxAPITokenTTLDays {
		http.Error(w, "expires_in_days must be between 0 and 3650", http.StatusBadRequest)
		return
	}
	var expiresAt *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresInDays)
		expiresAt = &t
	}

	secret, err := storage.NewAPITokenSecret()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tok, err := h.db.CreateAPIToken(r.Context(), name, req.Role, claims.UserID, secret, expiresAt)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// В аудит — метаданные, но НЕ секрет и НЕ его хеш: журнал читают шире, чем БД.
	h.audit(r.Context(), claims.UserID, claims.Email, "create_api_token", "api_token", tok.ID,
		map[string]any{"name": tok.Name, "role": tok.Role, "expires_at": tok.ExpiresAt})
	writeJSON(w, http.StatusCreated, createAPITokenResponse{APIToken: *tok, Token: secret})
}

func (h *Handler) deleteAPIToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	found, err := h.db.DeleteAPIToken(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "revoke_api_token", "api_token", id, nil)
	w.WriteHeader(http.StatusNoContent)
}
