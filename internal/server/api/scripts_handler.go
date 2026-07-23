package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/go-chi/chi/v5"
)

func (h *Handler) listScripts(w http.ResponseWriter, r *http.Request) {
	scripts, err := h.db.ListScripts(r.Context())
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
	if req.Platform != "macOS" && req.Platform != "Windows" && req.Platform != "linux" {
		http.Error(w, "platform must be macOS, Windows or linux", http.StatusBadRequest)
		return
	}
	script, err := h.db.CreateScript(r.Context(), req.Name, req.Platform, req.Content)
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
	script, err := h.db.GetScript(r.Context(), id)
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
	if req.Platform != "macOS" && req.Platform != "Windows" && req.Platform != "linux" {
		http.Error(w, "platform must be macOS, Windows or linux", http.StatusBadRequest)
		return
	}
	script, err := h.db.UpdateScript(r.Context(), id, req.Name, req.Platform, req.Content)
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
	if err := h.db.DeleteScript(r.Context(), id); err != nil {
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
