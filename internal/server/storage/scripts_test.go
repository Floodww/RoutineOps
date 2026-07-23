package storage_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

func TestCreateScript_ReturnsScript(t *testing.T) {
	db := newDB(t)
	s, err := db.CreateScript(context.Background(), fmt.Sprintf("myscript-%s", uniq(t)), "macos", "echo hello")
	if err != nil {
		t.Fatalf("CreateScript: %v", err)
	}
	if s.ID == "" {
		t.Error("expected non-empty script ID")
	}
	if s.Platform != "macos" {
		t.Errorf("platform = %q, want macos", s.Platform)
	}
}

func TestGetScript_Found(t *testing.T) {
	db := newDB(t)
	created, _ := db.CreateScript(context.Background(), fmt.Sprintf("getscript-%s", uniq(t)), "windows", "dir")

	got, err := db.GetScript(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetScript: %v", err)
	}
	if got == nil || got.ID != created.ID {
		t.Errorf("got %v, want script %s", got, created.ID)
	}
}

func TestGetScript_NotFound_ReturnsNil(t *testing.T) {
	db := newDB(t)
	got, err := db.GetScript(context.Background(), "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GetScript: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestUpdateScript(t *testing.T) {
	db := newDB(t)
	s, _ := db.CreateScript(context.Background(), fmt.Sprintf("updscript-%s", uniq(t)), "macos", "echo old")

	updated, err := db.UpdateScript(context.Background(), s.ID, s.Name, "windows", "echo new")
	if err != nil {
		t.Fatalf("UpdateScript: %v", err)
	}
	if updated == nil {
		t.Fatal("got nil from UpdateScript")
	}
	if updated.Content != "echo new" {
		t.Errorf("content = %q, want 'echo new'", updated.Content)
	}
	if updated.Platform != "windows" {
		t.Errorf("platform = %q, want windows", updated.Platform)
	}
}

func TestDeleteScript_RemovesIt(t *testing.T) {
	db := newDB(t)
	s, _ := db.CreateScript(context.Background(), fmt.Sprintf("delscript-%s", uniq(t)), "macos", "echo bye")

	if err := db.DeleteScript(context.Background(), s.ID); err != nil {
		t.Fatalf("DeleteScript: %v", err)
	}
	got, _ := db.GetScript(context.Background(), s.ID)
	if got != nil {
		t.Error("script should be deleted")
	}
}

func TestListScripts_ContainsCreated(t *testing.T) {
	db := newDB(t)
	name := fmt.Sprintf("listscript-%s", uniq(t))
	s, _ := db.CreateScript(context.Background(), name, "linux", "uname -a")

	scripts, err := db.ListScripts(context.Background())
	if err != nil {
		t.Fatalf("ListScripts: %v", err)
	}
	found := false
	for _, sc := range scripts {
		if sc.ID == s.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("created script %s not found in list", s.ID)
	}
}

func TestCreateScriptPolicy_And_Toggle(t *testing.T) {
	db := newDB(t)
	s, _ := db.CreateScript(context.Background(), fmt.Sprintf("pol-script-%s", uniq(t)), "macos", "date")

	pol, err := db.CreateScriptPolicy(context.Background(),
		fmt.Sprintf("pol-%s", uniq(t)), s.ID, "schedule",
		[]byte(`{"cron":"*/5 * * * *"}`), nil)
	if err != nil {
		t.Fatalf("CreateScriptPolicy: %v", err)
	}
	if pol.ID == "" {
		t.Error("expected policy ID")
	}
	if !pol.IsActive {
		t.Error("new policy should be active")
	}

	// disable it
	if err := db.ToggleScriptPolicy(context.Background(), pol.ID, false); err != nil {
		t.Fatalf("ToggleScriptPolicy: %v", err)
	}

	policies, _ := db.ListScriptPolicies(context.Background())
	for _, p := range policies {
		if p.ID == pol.ID && p.IsActive {
			t.Error("policy should be inactive after toggle")
		}
	}
}

func TestDeleteScriptPolicy(t *testing.T) {
	db := newDB(t)
	s, _ := db.CreateScript(context.Background(), fmt.Sprintf("delpol-script-%s", uniq(t)), "windows", "ver")
	pol, _ := db.CreateScriptPolicy(context.Background(),
		fmt.Sprintf("delpol-%s", uniq(t)), s.ID, "event", nil, []byte(`{"event":"startup"}`))

	if err := db.DeleteScriptPolicy(context.Background(), pol.ID); err != nil {
		t.Fatalf("DeleteScriptPolicy: %v", err)
	}

	policies, _ := db.ListScriptPolicies(context.Background())
	for _, p := range policies {
		if p.ID == pol.ID {
			t.Error("deleted policy should not appear in list")
		}
	}
}

func TestCreateDeviceGroup_And_AddRemoveMember(t *testing.T) {
	db := newDB(t)
	d := mustCreateDevice(t, db, fmt.Sprintf("host-grp-%s", uniq(t)), "macos")

	g, err := db.CreateDeviceGroup(context.Background(), fmt.Sprintf("group-%s", uniq(t)), "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}

	if err := db.AddDeviceToGroup(context.Background(), d.ID, g.ID); err != nil {
		t.Fatalf("AddDeviceToGroup: %v", err)
	}

	groups, err := db.ListDeviceGroups(context.Background())
	if err != nil {
		t.Fatalf("ListDeviceGroups: %v", err)
	}
	var found bool
	for _, grp := range groups {
		if grp.ID == g.ID {
			found = true
			hasMember := false
			for _, did := range grp.DeviceIDs {
				if did == d.ID {
					hasMember = true
				}
			}
			if !hasMember {
				t.Errorf("device %s not in group members", d.ID)
			}
		}
	}
	if !found {
		t.Error("group not found in list")
	}

	// remove member
	if err := db.RemoveDeviceFromGroup(context.Background(), d.ID, g.ID); err != nil {
		t.Fatalf("RemoveDeviceFromGroup: %v", err)
	}

	groups2, _ := db.ListDeviceGroups(context.Background())
	for _, grp := range groups2 {
		if grp.ID == g.ID {
			for _, did := range grp.DeviceIDs {
				if did == d.ID {
					t.Error("device should not be in group after removal")
				}
			}
		}
	}
}

// Имя скрипта/скрипт-политики — идентичность ресурса для YAML-apply (миграция 033),
// поэтому дубли обязаны отбиваться, причём нечувствительно к регистру и краевым
// пробелам: именно так люди создают «второй такой же» и потом не понимают, какой из
// них правит apply.
func TestDuplicateNames_ScriptsAndPolicies(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	name := fmt.Sprintf("Проверка антивируса %s", uniq(t))
	s, err := db.CreateScript(ctx, name, "windows", "echo ok")
	if err != nil {
		t.Fatalf("CreateScript: %v", err)
	}
	if _, err := db.CreateScript(ctx, "  "+strings.ToUpper(name)+" ", "windows", "echo dup"); !errors.Is(err, storage.ErrDuplicateName) {
		t.Errorf("дубль имени скрипта = %v, want ErrDuplicateName", err)
	}

	// Переименование в занятое имя — тот же конфликт, что и создание.
	other, err := db.CreateScript(ctx, name+" второй", "windows", "echo other")
	if err != nil {
		t.Fatalf("CreateScript (второй): %v", err)
	}
	if _, err := db.UpdateScript(ctx, other.ID, name, "windows", "echo other"); !errors.Is(err, storage.ErrDuplicateName) {
		t.Errorf("переименование в занятое = %v, want ErrDuplicateName", err)
	}

	polName := fmt.Sprintf("Ежедневная проверка %s", uniq(t))
	if _, err := db.CreateScriptPolicy(ctx, polName, s.ID, "manual", nil, nil); err != nil {
		t.Fatalf("CreateScriptPolicy: %v", err)
	}
	if _, err := db.CreateScriptPolicy(ctx, strings.ToLower(polName), s.ID, "manual", nil, nil); !errors.Is(err, storage.ErrDuplicateName) {
		t.Errorf("дубль имени скрипт-политики = %v, want ErrDuplicateName", err)
	}
}

// UpdateScriptPolicy сохраняет id (на него ссылаются назначения групп) и историю, меняя
// только содержимое политики. Без этой ручки apply правил бы расписание через
// delete+create — с потерей и того, и другого.
func TestUpdateScriptPolicy_KeepsIDChangesFields(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	s1, _ := db.CreateScript(ctx, fmt.Sprintf("upd-pol-script-a-%s", uniq(t)), "linux", "echo a")
	s2, _ := db.CreateScript(ctx, fmt.Sprintf("upd-pol-script-b-%s", uniq(t)), "linux", "echo b")

	name := fmt.Sprintf("Политика %s", uniq(t))
	p, err := db.CreateScriptPolicy(ctx, name, s1.ID, "schedule", []byte(`{"cron":"0 9 * * *"}`), nil)
	if err != nil {
		t.Fatalf("CreateScriptPolicy: %v", err)
	}

	upd, err := db.UpdateScriptPolicy(ctx, p.ID, name+" (новое имя)", s2.ID, "on_connect", nil, nil)
	if err != nil {
		t.Fatalf("UpdateScriptPolicy: %v", err)
	}
	if upd.ID != p.ID {
		t.Errorf("id изменился: %s → %s", p.ID, upd.ID)
	}
	if upd.ScriptID != s2.ID || upd.TriggerType != "on_connect" {
		t.Errorf("поля не обновились: %+v", upd)
	}
	if string(upd.ScheduleConfig) != "null" {
		t.Errorf("расписание не сброшено: %s", upd.ScheduleConfig)
	}

	// Несуществующая политика — (nil, nil), хендлер отдаёт 404, а не 500.
	got, err := db.UpdateScriptPolicy(ctx, "00000000-0000-0000-0000-000000000000", "x", s1.ID, "on_connect", nil, nil)
	if err != nil || got != nil {
		t.Errorf("UpdateScriptPolicy(нет такой) = %v, %v; want nil, nil", got, err)
	}

	// Переименование в занятое имя — 409, а не 500.
	other, _ := db.CreateScriptPolicy(ctx, name+" сосед", s1.ID, "on_connect", nil, nil)
	if _, err := db.UpdateScriptPolicy(ctx, other.ID, name+" (новое имя)", s1.ID, "on_connect", nil, nil); !errors.Is(err, storage.ErrDuplicateName) {
		t.Errorf("переименование в занятое = %v, want ErrDuplicateName", err)
	}
}
