package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

type tenantsListResponse struct {
	// ShowTenant — UI показывает сущность «тенант» только при N>1 (§10.2).
	ShowTenant bool             `json:"show_tenant"`
	Tenants    []storage.Tenant `json:"tenants"`
}

// listTenants — реестр инсталляции. show_tenant=false при N=1 (панель прячет UI).
func (h *Handler) listTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.db.ListTenants(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if tenants == nil {
		tenants = []storage.Tenant{}
	}
	writeJSON(w, http.StatusOK, tenantsListResponse{
		ShowTenant: len(tenants) > 1,
		Tenants:    tenants,
	})
}

func (h *Handler) createTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	t, err := h.db.CreateTenant(r.Context(), name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Аудит в журнал НОВОГО тенанта (§10.3).
	if uid, email, ok := Actor(r.Context()); ok {
		ctx, finish, berr := h.db.BindTenant(r.Context(), t.ID)
		if berr == nil {
			_ = h.db.WriteAuditLog(ctx, uid, email, "tenant.create", "tenant", t.ID, map[string]any{
				"name": t.Name,
			})
			finish(true)
		}
	}
	writeJSON(w, http.StatusCreated, t)
}

func (h *Handler) renameTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	if err := h.db.RenameTenant(r.Context(), id, name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if uid, email, ok := Actor(r.Context()); ok {
		ctx, finish, berr := h.db.BindTenant(r.Context(), id)
		if berr == nil {
			_ = h.db.WriteAuditLog(ctx, uid, email, "tenant.rename", "tenant", id, map[string]any{
				"name": name,
			})
			finish(true)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "name": name})
}

// deleteTenant удаляет тенант, переселяя его содержимое в Default.
//
// Решение флуда 30.07: устройства и люди не пропадают и не требуют ручного переноса.
// Тенант по умолчанию неудаляем — в нём сидит бутстрап-личность, без него в систему
// некому войти; переименовать его при этом можно.
//
// Запись в журнал делается ДО удаления и в тенант, который удаляем: после пометки он
// исчезает из выборок, и событие потерялось бы ровно там, где оно нужнее всего.
func (h *Handler) deleteTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if uid, email, ok := Actor(r.Context()); ok {
		ctx, finish, berr := h.db.BindTenant(r.Context(), id)
		if berr == nil {
			_ = h.db.WriteAuditLog(ctx, uid, email, "tenant.delete", "tenant", id, map[string]any{
				"reparented_to": tenancy.DefaultTenantID,
			})
			finish(true)
		}
	}

	// Записи экрана всех устройств тенанта — до удаления самого тенанта: строки уедут
	// каскадом, файлы не уедут никуда (§6). Отказ отменяет удаление: тенант, удалённый
	// с оставшимися на диске записями его сотрудников, — это утечка, а не «почти
	// удалили».
	if err := h.purgeScreenTenant(r.Context(), id); err != nil {
		slog.Error("удаление записей экрана тенанта", "tenant_id", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.db.DeleteTenant(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, storage.ErrTenantUndeletable):
			http.Error(w, "тенант по умолчанию удалить нельзя", http.StatusBadRequest)
		case errors.Is(err, pgx.ErrNoRows):
			http.Error(w, "not found", http.StatusNotFound)
		default:
			slog.Error("удаление тенанта", "tenant_id", id, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// moveDeviceToTenant переносит устройство в другой тенант.
//
// Под надзором инсталляции: перекладывать машины между подразделениями — не работа
// администратора одного тенанта, он и чужого устройства-то не видит.
func (h *Handler) moveDeviceToTenant(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	var body struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.TenantID) == "" {
		http.Error(w, "tenant_id required", http.StatusBadRequest)
		return
	}
	// §6: персональные данные не переезжают к другому контролёру. Запись экрана сделана
	// в рамках согласия и политики ПРЕЖНЕГО подразделения, и после переноса она
	// оказалась бы доступна операторам нового — тем, кому её никто не показывал.
	// Поэтому записи удаляются, а не переносятся; журнал сеансов уезжает вместе со
	// строкой (там нет содержимого экрана, только факт и причина).
	srcTenant, err := h.db.DeviceTenantID(r.Context(), deviceID)
	if err != nil {
		slog.Error("перенос: тенант устройства", "device_id", deviceID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if srcTenant != "" && srcTenant != body.TenantID {
		if err := h.purgeScreenDevice(r.Context(), srcTenant, deviceID); err != nil {
			slog.Error("перенос: удаление записей экрана", "device_id", deviceID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if err := h.db.MoveDeviceToTenant(r.Context(), deviceID, body.TenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		slog.Error("перенос устройства в тенант", "device_id", deviceID, "tenant_id", body.TenantID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Аудит пишем в ЦЕЛЕВОЙ тенант: там устройство теперь живёт, и там же его будут
	// искать. В покинутом останется след переноса только косвенно — это осознанно,
	// дублировать событие в двух цепочках хешей нельзя.
	if uid, email, ok := Actor(r.Context()); ok {
		ctx, finish, berr := h.db.BindTenant(r.Context(), body.TenantID)
		if berr == nil {
			_ = h.db.WriteAuditLog(ctx, uid, email, "move_device_tenant", "device", deviceID, map[string]any{
				"tenant_id": body.TenantID,
			})
			finish(true)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// inviteToTenant приглашает человека в КОНКРЕТНЫЙ тенант.
//
// Закрывает дыру, найденную полевым e2e 30.07: надзорный мог создать тенант, но не
// мог никого в него добавить — обычный inviteUser скоупится тенантом вызывающего,
// и свежесозданный тенант оставался недостижим вообще ни для кого.
func (h *Handler) inviteToTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "id")
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Email) == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}
	role := strings.TrimSpace(body.Role)
	if role == "" {
		role = "viewer" // least-privilege, как и в обычном инвайте
	}
	if !validRoles[role] {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	h.inviteInto(w, r, tenantID, body.Email, role)
}
