package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/go-chi/chi/v5"
)

// Карточки людей — владельцы устройств. В Enterprise их приносит синк AD, во Free
// оператор заводит руками; сущность и поле в карточке устройства одни и те же
// (миграция 038). Здесь — только ручной путь: каталожные строки правятся в AD.
//
// Владелец НЕ аккаунт панели: аккаунты (приглашения) нужны тем, кто в панель ходит —
// админам, поддержке, стажёрам. Требовать от сотрудника завести пароль ради того, чтобы
// за ним числился ноутбук, бессмысленно, и раньше другого пути не было.

const (
	maxPersonNameLen  = 200
	maxPersonEmailLen = 320 // RFC 5321: 64 local + @ + 255 domain
)

type personRequest struct {
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

// normalize валидирует ввод оператора. ФИО обязательно — карточка без имени
// нечитаема в списке владельцев; почта опциональна (не у каждого сотрудника есть
// корпоративная), но если задана, то разбирается как адрес.
func (p *personRequest) normalize() error {
	p.DisplayName = strings.TrimSpace(p.DisplayName)
	p.Email = strings.TrimSpace(p.Email)
	if p.DisplayName == "" {
		return errors.New("display_name is required")
	}
	if len([]rune(p.DisplayName)) > maxPersonNameLen {
		return errors.New("display_name is too long")
	}
	if p.Email != "" {
		if len(p.Email) > maxPersonEmailLen {
			return errors.New("email is too long")
		}
		if _, err := mail.ParseAddress(p.Email); err != nil {
			return errors.New("email is not a valid address")
		}
	}
	return nil
}

func decodePerson(w http.ResponseWriter, r *http.Request) (personRequest, bool) {
	var req personRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return req, false
	}
	if err := req.normalize(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func (h *Handler) createPerson(w http.ResponseWriter, r *http.Request) {
	req, ok := decodePerson(w, r)
	if !ok {
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	p, err := h.db.CreateManualPerson(r.Context(), tenantID, req.DisplayName, req.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "create_person", "person", p.ID,
		map[string]any{"display_name": p.DisplayName, "email": p.Email})
	writeJSON(w, http.StatusCreated, p)
}

func (h *Handler) updatePerson(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	req, ok := decodePerson(w, r)
	if !ok {
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	found, err := h.db.UpdateManualPerson(r.Context(), tenantID, id, req.DisplayName, req.Email)
	if errors.Is(err, storage.ErrPersonNotManual) {
		// 409, а не 403: право у оператора есть, но источник истины для этой карточки —
		// каталог, и правка здесь пережила бы ровно до следующего синка.
		http.Error(w, "person comes from the directory, edit it in AD", http.StatusConflict)
		return
	}
	if err != nil {
		// Неверный uuid прилетает сюда же — это ввод оператора, 400.
		http.Error(w, "invalid person: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "update_person", "person", id,
		map[string]any{"display_name": req.DisplayName, "email": req.Email})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) deletePerson(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	found, err := h.db.DeleteManualPerson(r.Context(), tenantID, id)
	if errors.Is(err, storage.ErrPersonNotManual) {
		http.Error(w, "person comes from the directory, remove it in AD", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "invalid person: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	// Устройства, где карточка стояла владельцем, остаются без владельца
	// (owner_directory_id ON DELETE SET NULL) — сами машины не затрагиваются.
	h.audit(r.Context(), claims.UserID, claims.Email, "delete_person", "person", id, nil)
	w.WriteHeader(http.StatusNoContent)
}
