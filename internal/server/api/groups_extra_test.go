package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// ====== Групповые софт-политики (#2) ======

func TestGroupSoftwarePolicies_AssignUnassign(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	groupID := createGroup(t, rtr, tok, "grp-sw-assign")

	// assign → 201, тело содержит id.
	body, _ := json.Marshal(map[string]string{"software_name": "chrome", "rule_type": "allowed"})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/software-policies", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("assign: got %d, want 201; body: %s", w.Code, w.Body)
	}
	var rule map[string]any
	json.NewDecoder(w.Body).Decode(&rule)
	ruleID, _ := rule["id"].(string)
	if ruleID == "" {
		t.Fatalf("assign response missing id: %v", rule)
	}

	// unassign → 204.
	w = authedDo(t, rtr, http.MethodDelete, "/api/v1/device-groups/"+groupID+"/software-policies/"+ruleID, nil, tok)
	if w.Code != http.StatusNoContent {
		t.Errorf("unassign: got %d, want 204; body: %s", w.Code, w.Body)
	}
}

func TestGroupSoftwarePolicies_Validation_400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	groupID := createGroup(t, rtr, tok, "grp-sw-valid")

	cases := map[string]map[string]string{
		"empty software_name": {"software_name": "", "rule_type": "allowed"},
		"bad rule_type":       {"software_name": "app", "rule_type": "bad"},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(payload)
			w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/software-policies", body, tok)
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body)
			}
		})
	}
}

func TestListDeviceGroups_IncludesSoftwareRules(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	groupID := createGroup(t, rtr, tok, "grp-sw-list")
	body, _ := json.Marshal(map[string]string{"software_name": "steam", "rule_type": "forbidden"})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/software-policies", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("assign: got %d, want 201; body: %s", w.Code, w.Body)
	}

	w = authedDo(t, rtr, http.MethodGet, "/api/v1/device-groups", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("list: got %d, want 200; body: %s", w.Code, w.Body)
	}
	var groups []struct {
		ID            string           `json:"id"`
		SoftwareRules []map[string]any `json:"software_rules"`
	}
	json.NewDecoder(w.Body).Decode(&groups)
	var found bool
	for _, g := range groups {
		if g.ID == groupID {
			found = true
			if len(g.SoftwareRules) != 1 {
				t.Errorf("software_rules len = %d, want 1", len(g.SoftwareRules))
			}
		}
	}
	if !found {
		t.Errorf("group %s not found in list", groupID)
	}
}

// ====== Разовый прогон скрипта на группу (#3) ======

func TestRunScriptOnGroup_Created(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	groupID := createGroup(t, rtr, tok, "grp-run")
	macScriptID := createScript(t, rtr, tok, "run-script-mac", "macOS")
	linuxScriptID := createScript(t, rtr, tok, "run-script-linux", "linux")
	deviceID, _ := createDevice(t, rtr, tok, "run-host", "macos")
	// Скрипты гоняются только на active (безопасность: pending/pending_approval не
	// исполняют скрипты). Активируем устройство — иначе fan-out его не таргетит.
	if err := db.UpdateDeviceStatus(context.Background(), deviceID, "active"); err != nil {
		t.Fatalf("activate device: %v", err)
	}

	// Добавляем устройство в группу.
	mb, _ := json.Marshal(map[string]string{"device_id": deviceID})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/members", mb, tok)
	if w.Code != http.StatusNoContent {
		t.Fatalf("add member: got %d, want 204; body: %s", w.Code, w.Body)
	}

	runScript := func(scriptID string) int {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"script_id": scriptID})
		w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/run-script", body, tok)
		if w.Code != http.StatusCreated {
			t.Fatalf("run-script: got %d, want 201; body: %s", w.Code, w.Body)
		}
		var resp map[string]int
		json.NewDecoder(w.Body).Decode(&resp)
		return resp["created"]
	}

	if created := runScript(macScriptID); created != 1 {
		t.Errorf("macOS script on macOS device: created = %d, want 1", created)
	}
	// Linux-скрипт не должен уезжать на macOS: раньше фильтр был «не-windows».
	if created := runScript(linuxScriptID); created != 0 {
		t.Errorf("linux script on macOS device: created = %d, want 0", created)
	}
}

func TestRunScriptOnGroup_UnknownGroup_404(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	scriptID := createScript(t, rtr, tok, "run-script-orphan", "linux")
	body, _ := json.Marshal(map[string]string{"script_id": scriptID})
	// Валидный по форме, но несуществующий UUID группы: раньше отдавалось 201 created:0.
	w := authedDo(t, rtr, http.MethodPost,
		"/api/v1/device-groups/00000000-0000-0000-0000-000000000000/run-script", body, tok)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404; body: %s", w.Code, w.Body)
	}
}

func TestRunScriptOnGroup_MissingScriptID_400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	groupID := createGroup(t, rtr, tok, "grp-run-missing")
	body, _ := json.Marshal(map[string]string{"priority": "high"})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/run-script", body, tok)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400; body: %s", w.Code, w.Body)
	}
}

func TestRunScriptOnGroup_ScriptNotFound_404(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	groupID := createGroup(t, rtr, tok, "grp-run-404")
	body, _ := json.Marshal(map[string]string{"script_id": "00000000-0000-0000-0000-000000000000"})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/run-script", body, tok)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404; body: %s", w.Code, w.Body)
	}
}

// Имена групп уникальны: две «Бухгалтерии» в UI неразличимы, а назначения политик
// расползаются между дублями.
func TestCreateDeviceGroup_DuplicateName_409(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	createGroup(t, rtr, tok, "Бухгалтерия")

	// Регистр и краевые пробелы не делают имя новым.
	body, _ := json.Marshal(map[string]string{"name": "  бухгалтерия "})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, tok)
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate name: got %d, want 409; body: %s", w.Code, w.Body)
	}
}

func TestCreateDeviceGroup_BlankName_400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	body, _ := json.Marshal(map[string]string{"name": "   "})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, tok)
	if w.Code != http.StatusBadRequest {
		t.Errorf("blank name: got %d, want 400; body: %s", w.Code, w.Body)
	}
}

// ====== Цвет группы (миграция 027) ======

// Цвет нормализуется к нижнему регистру ещё в хендлере: CHECK в БД принимает только
// '^#[0-9a-f]{6}$', и '#AABBCC' из color-пикера иначе улетел бы в 500.
func TestCreateDeviceGroup_ColorNormalizedToLowercase(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	body, _ := json.Marshal(map[string]string{"name": "grp-color-upper", "color": "#AABBCC"})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("got %d, want 201; body: %s", w.Code, w.Body)
	}
	var g map[string]any
	json.NewDecoder(w.Body).Decode(&g)
	if g["color"] != "#aabbcc" {
		t.Errorf("color = %v, want #aabbcc", g["color"])
	}
}

// Цвет без цвета — дефолт схемы, а не пустая строка в style-атрибуте.
func TestCreateDeviceGroup_DefaultColor(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	id := createGroup(t, rtr, tok, "grp-color-absent")
	w := authedDo(t, rtr, http.MethodGet, "/api/v1/device-groups", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("list: got %d, want 200; body: %s", w.Code, w.Body)
	}
	var groups []struct {
		ID    string `json:"id"`
		Color string `json:"color"`
	}
	json.NewDecoder(w.Body).Decode(&groups)
	for _, g := range groups {
		if g.ID == id {
			if g.Color != storage.DefaultGroupColor {
				t.Errorf("color = %q, want %q", g.Color, storage.DefaultGroupColor)
			}
			return
		}
	}
	t.Fatalf("группа %s не найдена в списке", id)
}

// «Почти цвет» обязан ловиться как 400 в хендлере, а не как 500 от нарушения CHECK.
func TestCreateDeviceGroup_BadColor_400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	for _, color := range []string{"red", "#fff", "#gggggg", "3b82f6", "#3b82f6;", "#3b82f688"} {
		t.Run(color, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"name": "grp-bad-" + color, "color": color})
			w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups", body, tok)
			if w.Code != http.StatusBadRequest {
				t.Errorf("color=%q: got %d, want 400; body: %s", color, w.Code, w.Body)
			}
		})
	}
}

func TestUpdateDeviceGroup_Returns200(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	id := createGroup(t, rtr, tok, "grp-patch")
	body, _ := json.Marshal(map[string]string{"name": "grp-patch-renamed", "color": "#FF0000"})
	w := authedDo(t, rtr, http.MethodPatch, "/api/v1/device-groups/"+id, body, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var g map[string]any
	json.NewDecoder(w.Body).Decode(&g)
	if g["name"] != "grp-patch-renamed" || g["color"] != "#ff0000" {
		t.Errorf("группа после PATCH = %v, want name=grp-patch-renamed color=#ff0000", g)
	}
}

// Пустой PATCH — ошибка клиента: «не менять ничего» и «стереть имя» неразличимы на
// уровне пустой строки, и молчаливый 200 без изменений скрывал бы баг в UI.
func TestUpdateDeviceGroup_NothingToUpdate_400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	id := createGroup(t, rtr, tok, "grp-patch-empty")
	w := authedDo(t, rtr, http.MethodPatch, "/api/v1/device-groups/"+id, []byte(`{}`), tok)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400; body: %s", w.Code, w.Body)
	}
}

func TestUpdateDeviceGroup_UnknownID_404(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	body, _ := json.Marshal(map[string]string{"color": "#123456"})
	w := authedDo(t, rtr, http.MethodPatch,
		"/api/v1/device-groups/00000000-0000-0000-0000-000000000000", body, tok)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404; body: %s", w.Code, w.Body)
	}
}

func TestUpdateDeviceGroup_BadColor_400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	id := createGroup(t, rtr, tok, "grp-patch-badcolor")
	body, _ := json.Marshal(map[string]string{"color": "rebeccapurple"})
	w := authedDo(t, rtr, http.MethodPatch, "/api/v1/device-groups/"+id, body, tok)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400; body: %s", w.Code, w.Body)
	}
}

// Переименование в занятое имя — 409, как и при создании: иначе две «Бухгалтерии».
func TestUpdateDeviceGroup_DuplicateName_409(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	createGroup(t, rtr, tok, "grp-patch-taken")
	id := createGroup(t, rtr, tok, "grp-patch-free")

	body, _ := json.Marshal(map[string]string{"name": "  GRP-PATCH-TAKEN "})
	w := authedDo(t, rtr, http.MethodPatch, "/api/v1/device-groups/"+id, body, tok)
	if w.Code != http.StatusConflict {
		t.Errorf("got %d, want 409; body: %s", w.Code, w.Body)
	}
}

// PATCH — мутация, значит только it_admin. Viewer читает группы, но не красит их.
func TestUpdateDeviceGroup_Viewer_403(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)
	viewer := tokenForRole(t, rtr, db, "viewer", "viewer_")

	id := createGroup(t, rtr, tok, "grp-patch-rbac")
	body, _ := json.Marshal(map[string]string{"color": "#123456"})
	w := authedDo(t, rtr, http.MethodPatch, "/api/v1/device-groups/"+id, body, viewer)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer: got %d, want 403; body: %s", w.Code, w.Body)
	}
}

// Ссылка на несуществующее устройство — ошибка клиента, а не «internal error».
func TestAddGroupMember_UnknownDevice_400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	groupID := createGroup(t, rtr, tok, "grp-fk")
	body, _ := json.Marshal(map[string]string{"device_id": "00000000-0000-0000-0000-000000000000"})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/device-groups/"+groupID+"/members", body, tok)
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown device: got %d, want 400; body: %s", w.Code, w.Body)
	}
}
