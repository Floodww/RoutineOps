package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/go-chi/chi/v5"
)

func (h *Handler) listScripts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	scripts, err := h.db.ListScripts(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if scripts == nil {
		scripts = []storage.Script{}
	}
	writeJSON(w, http.StatusOK, scripts)
}

type createScriptRequest struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	Content  string `json:"content"`
}

func (h *Handler) createScript(w http.ResponseWriter, r *http.Request) {
	var req createScriptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Platform == "" || req.Content == "" {
		http.Error(w, "name, platform and content are required", http.StatusBadRequest)
		return
	}
	canon, ok := canonicalPlatform(req.Platform)
	if !ok {
		http.Error(w, "platform must be macOS, Windows or Linux", http.StatusBadRequest)
		return
	}
	req.Platform = canon
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	script, err := h.db.CreateScript(r.Context(), tenantID, req.Name, req.Platform, req.Content)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateName) {
			// Имя скрипта — идентичность ресурса (033, как у групп в 026): по нему его
			// находит YAML-apply. Занятое имя — конфликт, а не внутренняя ошибка.
			http.Error(w, "script name already exists", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "create_script", "script", script.ID,
		map[string]string{"name": script.Name, "platform": script.Platform})
	writeJSON(w, http.StatusCreated, script)
}

func (h *Handler) getScript(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	script, err := h.db.GetScript(r.Context(), tenantID, id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if script == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, script)
}

func (h *Handler) updateScript(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req createScriptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Platform == "" || req.Content == "" {
		http.Error(w, "name, platform and content are required", http.StatusBadRequest)
		return
	}
	canon, ok := canonicalPlatform(req.Platform)
	if !ok {
		http.Error(w, "platform must be macOS, Windows or Linux", http.StatusBadRequest)
		return
	}
	req.Platform = canon
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	script, err := h.db.UpdateScript(r.Context(), tenantID, id, req.Name, req.Platform, req.Content)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateName) {
			http.Error(w, "script name already exists", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if script == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "update_script", "script", script.ID,
		map[string]string{"name": script.Name, "platform": script.Platform})
	writeJSON(w, http.StatusOK, script)
}

func (h *Handler) deleteScript(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := h.db.DeleteScript(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, storage.ErrScriptInUse) {
			http.Error(w, "script is used by script policies — delete them first", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "delete_script", "script", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// canonicalPlatform приводит платформу к единому набору macOS | Windows | Linux.
//
// Зачем нормализация, а не просто ещё одна константа: две соседние ручки требовали разного
// регистра — POST /scripts принимал только "linux", POST /policies только "Linux", и обе
// отвечали 400 на «чужой» вариант. Поймано при наливке демо-данных на прод 03.08.2026.
//
// Вход принимаем в любом регистре, наружу и в БД пишем канон. Старые строки со значением
// "linux" продолжают читаться (сравнение платформы скрипта нигде не влияет на выбор
// интерпретатора — gateway.platformToInterpreter смотрит только на "Windows"), но их стоит
// привести одноразовой миграцией — номер за владельцем нумерации.
func canonicalPlatform(p string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "macos":
		return "macOS", true
	case "windows":
		return "Windows", true
	case "linux":
		return "Linux", true
	default:
		return "", false
	}
}
