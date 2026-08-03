package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/go-chi/chi/v5"
	"github.com/robfig/cron/v3"
)

// maxGroupNameLen — потолок имени группы. Схема хранит TEXT без ограничения; без кэпа
// в UI и в аудит-логе оседают мегабайтные «имена».
const maxGroupNameLen = 128

// fkBadRequest переводит нарушение внешнего ключа (несуществующие device/group/policy)
// в 400. Раньше такие запросы отдавали 500 и выглядели как поломка сервера.
func fkBadRequest(w http.ResponseWriter, err error) bool {
	if errors.Is(err, storage.ErrForeignKeyViolation) {
		http.Error(w, "referenced device, group or policy does not exist", http.StatusBadRequest)
		return true
	}
	return false
}

// ====== Script Policies ======

// listScriptResults — история результатов запусков script-политики (read-only, все роли).
func (h *Handler) listScriptResults(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	limitStr := r.URL.Query().Get("limit")
	limit, _ := strconv.Atoi(limitStr)
	if limit == 0 {
		limit = 100
	}
	results, err := h.db.ListScriptResultsByPolicy(r.Context(), tenantID, id, limit)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []storage.ScriptResultRow{}
	}
	writeJSON(w, http.StatusOK, results)
}

func (h *Handler) listScriptPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	policies, err := h.db.ListScriptPolicies(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if policies == nil {
		policies = []storage.ScriptPolicy{}
	}
	writeJSON(w, http.StatusOK, policies)
}

// validateScheduleConfig проверяет cron-выражение ТЕМ ЖЕ парсером, которым его исполняет
// агент (robfig/cron standard). Без этого политика с пустым или битым cron создавалась с
// 201, тихо не планировалась и выглядела рабочей. Возвращает текст ошибки или "".
func validateScheduleConfig(triggerType string, raw json.RawMessage) string {
	if triggerType != "schedule" {
		return ""
	}
	var cfg struct {
		Cron string `json:"cron"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return "schedule_config must be a JSON object"
		}
	}
	cfg.Cron = strings.TrimSpace(cfg.Cron)
	if cfg.Cron == "" {
		return "schedule_config.cron is required for trigger_type=schedule"
	}
	if _, err := cron.ParseStandard(cfg.Cron); err != nil {
		return "invalid cron expression: " + err.Error()
	}
	return ""
}

type createScriptPolicyRequest struct {
	Name               string          `json:"name"`
	ScriptID           string          `json:"script_id"`
	TriggerType        string          `json:"trigger_type"`
	ScheduleConfig     json.RawMessage `json:"schedule_config,omitempty"`
	EventTriggerConfig json.RawMessage `json:"event_trigger_config,omitempty"`
}

func (h *Handler) createScriptPolicy(w http.ResponseWriter, r *http.Request) {
	var req createScriptPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.ScriptID == "" || req.TriggerType == "" {
		http.Error(w, "name, script_id and trigger_type are required", http.StatusBadRequest)
		return
	}
	if req.TriggerType != "schedule" && req.TriggerType != "event_trigger" && req.TriggerType != "on_connect" {
		http.Error(w, "trigger_type must be schedule, event_trigger or on_connect", http.StatusBadRequest)
		return
	}
	if msg := validateScheduleConfig(req.TriggerType, req.ScheduleConfig); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	policy, err := h.db.CreateScriptPolicy(r.Context(), tenantID, req.Name, req.ScriptID, req.TriggerType,
		[]byte(req.ScheduleConfig), []byte(req.EventTriggerConfig))
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateName) {
			http.Error(w, "script policy name already exists", http.StatusConflict)
			return
		}
		if fkBadRequest(w, err) { // несуществующий script_id — 400, а не 500
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "create_script_policy", "script_policy", policy.ID,
		map[string]string{"name": policy.Name, "trigger": req.TriggerType})
	writeJSON(w, http.StatusCreated, policy)
}

// updateScriptPolicy переписывает политику целиком. Появился ради идемпотентного
// YAML-apply: без него правка расписания = delete+create, а это новый id (назначения
// групп отваливаются) и потерянная история результатов. Валидация — та же, что на
// создании: политика с битым cron не должна проходить через «чёрный ход» обновления.
func (h *Handler) updateScriptPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req createScriptPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.ScriptID == "" || req.TriggerType == "" {
		http.Error(w, "name, script_id and trigger_type are required", http.StatusBadRequest)
		return
	}
	if req.TriggerType != "schedule" && req.TriggerType != "event_trigger" && req.TriggerType != "on_connect" {
		http.Error(w, "trigger_type must be schedule, event_trigger or on_connect", http.StatusBadRequest)
		return
	}
	if msg := validateScheduleConfig(req.TriggerType, req.ScheduleConfig); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	policy, err := h.db.UpdateScriptPolicy(r.Context(), tenantID, id, req.Name, req.ScriptID, req.TriggerType,
		[]byte(req.ScheduleConfig), []byte(req.EventTriggerConfig))
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateName) {
			http.Error(w, "script policy name already exists", http.StatusConflict)
			return
		}
		if fkBadRequest(w, err) {
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if policy == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "update_script_policy", "script_policy", policy.ID,
		map[string]string{"name": policy.Name, "trigger": req.TriggerType})
	writeJSON(w, http.StatusOK, policy)
}

func (h *Handler) deleteScriptPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := h.db.DeleteScriptPolicy(r.Context(), tenantID, id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "delete_script_policy", "script_policy", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

type toggleScriptPolicyRequest struct {
	Active bool `json:"active"`
}

func (h *Handler) toggleScriptPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req toggleScriptPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := h.db.ToggleScriptPolicy(r.Context(), tenantID, id, req.Active); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	action := "disable_script_policy"
	if req.Active {
		action = "enable_script_policy"
	}
	h.audit(r.Context(), claims.UserID, claims.Email, action, "script_policy", id, nil)
	writeJSON(w, http.StatusOK, map[string]bool{"active": req.Active})
}

// ====== Device Groups ======

func (h *Handler) listDeviceGroups(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	groups, err := h.db.ListDeviceGroups(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if groups == nil {
		groups = []storage.DeviceGroupWithMembers{}
	}
	writeJSON(w, http.StatusOK, groups)
}

type createDeviceGroupRequest struct {
	Name  string `json:"name"`
	Color string `json:"color"` // '#rrggbb'; пусто = дефолт из схемы
	// UpdateChannel — канал обновлений участников (065); пусто = stable из схемы.
	UpdateChannel string `json:"update_channel"`
}

// normalizeUpdateChannel проверяет канал ЗДЕСЬ, а не только CHECK'ом в БД: опечатка
// в канале должна быть понятным 400, а не 500 из глубины. Пустая строка проходит и
// означает «не задан» (create → stable из схемы, update → не менять).
func normalizeUpdateChannel(c string) (string, bool) {
	c = strings.TrimSpace(c)
	if c == "" {
		return "", true
	}
	if !storage.ValidChannel(c) {
		return "", false
	}
	return c, true
}

// hexColor — единственный допустимый формат цвета группы. Строгая проверка ЗДЕСЬ, а не
// только CHECK'ом в БД: значение подставляется в inline-style на фронте, и «почти цвет»
// должен ловиться как 400, а не как 500 от нарушения констрейнта.
var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// normalizeGroupColor приводит цвет к виду, который принимает CHECK (строчные буквы).
// Пустая строка проходит: означает «не задан».
func normalizeGroupColor(c string) (string, bool) {
	c = strings.TrimSpace(c)
	if c == "" {
		return "", true
	}
	if !hexColor.MatchString(c) {
		return "", false
	}
	return strings.ToLower(c), true
}

func (h *Handler) createDeviceGroup(w http.ResponseWriter, r *http.Request) {
	var req createDeviceGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	// Имя из одних пробелов проходило NOT NULL и создавало безымянную группу.
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if utf8.RuneCountInString(req.Name) > maxGroupNameLen {
		http.Error(w, "name is too long", http.StatusBadRequest)
		return
	}
	color, ok := normalizeGroupColor(req.Color)
	if !ok {
		http.Error(w, "color must be #rrggbb", http.StatusBadRequest)
		return
	}
	channel, ok := normalizeUpdateChannel(req.UpdateChannel)
	if !ok {
		http.Error(w, "update_channel must be stable or beta", http.StatusBadRequest)
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	group, err := h.db.CreateDeviceGroup(r.Context(), tenantID, req.Name, color, channel)
	if errors.Is(err, storage.ErrDuplicateGroupName) {
		http.Error(w, "group with this name already exists", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "create_device_group", "device_group", group.ID,
		map[string]string{"name": req.Name, "color": group.Color, "update_channel": group.UpdateChannel})
	writeJSON(w, http.StatusCreated, group)
}

type updateDeviceGroupRequest struct {
	Name          string `json:"name"`           // пусто = не менять
	Color         string `json:"color"`          // пусто = не менять
	UpdateChannel string `json:"update_channel"` // пусто = не менять
}

func (h *Handler) updateDeviceGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req updateDeviceGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if utf8.RuneCountInString(req.Name) > maxGroupNameLen {
		http.Error(w, "name is too long", http.StatusBadRequest)
		return
	}
	color, ok := normalizeGroupColor(req.Color)
	if !ok {
		http.Error(w, "color must be #rrggbb", http.StatusBadRequest)
		return
	}
	channel, ok := normalizeUpdateChannel(req.UpdateChannel)
	if !ok {
		http.Error(w, "update_channel must be stable or beta", http.StatusBadRequest)
		return
	}
	if req.Name == "" && color == "" && channel == "" {
		http.Error(w, "nothing to update", http.StatusBadRequest)
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	group, err := h.db.UpdateDeviceGroup(r.Context(), tenantID, id, req.Name, color, channel)
	if errors.Is(err, storage.ErrDuplicateGroupName) {
		http.Error(w, "group with this name already exists", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if group == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	// Смена канала — событие выкатки: по журналу должно быть видно, КОГДА группа
	// стала канареечной, иначе «почему эти пять машин уехали на другую версию»
	// восстанавливать нечем.
	h.audit(r.Context(), claims.UserID, claims.Email, "update_device_group", "device_group", group.ID,
		map[string]string{"name": group.Name, "color": group.Color, "update_channel": group.UpdateChannel})
	writeJSON(w, http.StatusOK, group)
}

func (h *Handler) deleteDeviceGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := h.db.DeleteDeviceGroup(r.Context(), tenantID, id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "delete_device_group", "device_group", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

type groupMemberRequest struct {
	DeviceID string `json:"device_id"`
}

func (h *Handler) addGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	var req groupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.DeviceID == "" {
		http.Error(w, "device_id is required", http.StatusBadRequest)
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := h.db.AddDeviceToGroup(r.Context(), tenantID, req.DeviceID, groupID); err != nil {
		if fkBadRequest(w, err) {
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "add_device_to_group", "device_group", groupID,
		map[string]string{"device_id": req.DeviceID})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	deviceID := chi.URLParam(r, "deviceId")
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := h.db.RemoveDeviceFromGroup(r.Context(), tenantID, deviceID, groupID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "remove_device_from_group", "device_group", groupID,
		map[string]string{"device_id": deviceID})
	w.WriteHeader(http.StatusNoContent)
}

type groupPolicyRequest struct {
	PolicyID string `json:"policy_id"`
}

func (h *Handler) assignPolicyToGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	var req groupPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.PolicyID == "" {
		http.Error(w, "policy_id is required", http.StatusBadRequest)
		return
	}
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := h.db.AssignPolicyToGroup(r.Context(), tenantID, req.PolicyID, groupID); err != nil {
		if fkBadRequest(w, err) {
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "assign_policy_to_group", "device_group", groupID,
		map[string]string{"policy_id": req.PolicyID})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) unassignPolicyFromGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	policyID := chi.URLParam(r, "policyId")
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := h.db.UnassignPolicyFromGroup(r.Context(), tenantID, policyID, groupID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "unassign_policy_from_group", "device_group", groupID,
		map[string]string{"policy_id": policyID})
	w.WriteHeader(http.StatusNoContent)
}

// ---- Групповые софт-политики (#2) ----

type groupSoftwarePolicyRequest struct {
	SoftwareName string `json:"software_name"`
	RuleType     string `json:"rule_type"`
}

func (h *Handler) assignSoftwarePolicyToGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	var req groupSoftwarePolicyRequest
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
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	rule, err := h.db.AssignSoftwarePolicyToGroup(r.Context(), tenantID, groupID, req.SoftwareName, req.RuleType)
	if err != nil {
		if fkBadRequest(w, err) {
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "assign_software_policy_to_group", "device_group", groupID,
		map[string]string{"software_name": req.SoftwareName, "rule_type": req.RuleType, "rule_id": rule.ID})
	writeJSON(w, http.StatusCreated, rule)
}

func (h *Handler) unassignSoftwarePolicyFromGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	ruleID := chi.URLParam(r, "ruleId")
	tenantID, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := h.db.UnassignSoftwarePolicyFromGroup(r.Context(), tenantID, groupID, ruleID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	claims := r.Context().Value(claimsKey).(*jwtClaims)
	h.audit(r.Context(), claims.UserID, claims.Email, "unassign_software_policy_from_group", "device_group", groupID,
		map[string]string{"rule_id": ruleID})
	w.WriteHeader(http.StatusNoContent)
}
