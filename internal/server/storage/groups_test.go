package storage_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

func TestFetchPolicyRules_GroupScope(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	// Устройство с отпечатком (FetchPolicyRules резолвит device по fingerprint).
	fp := "fp-grp-" + suffix
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, "cn-"+suffix, "cn-"+suffix, "1.2.3.4")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}
	deviceID, err := db.GetDeviceIDByFingerprint(ctx, fp)
	if err != nil || deviceID == "" {
		t.Fatalf("GetDeviceIDByFingerprint: id=%q err=%v", deviceID, err)
	}

	group, err := db.CreateDeviceGroup(ctx, "grp-scope-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}

	// Глобальное и device-правила видны всегда (сохраняем старое поведение).
	globalName := "global-" + suffix
	if _, err := db.CreatePolicyRule(ctx, globalName, "allowed", nil, nil); err != nil {
		t.Fatalf("CreatePolicyRule global: %v", err)
	}
	deviceName := "device-" + suffix
	if _, err := db.CreatePolicyRule(ctx, deviceName, "forbidden", &deviceID, nil); err != nil {
		t.Fatalf("CreatePolicyRule device: %v", err)
	}

	groupName := "group-" + suffix
	if _, err := db.AssignSoftwarePolicyToGroup(ctx, group.ID, groupName, "forbidden"); err != nil {
		t.Fatalf("AssignSoftwarePolicyToGroup: %v", err)
	}

	names := func() map[string]bool {
		res, err := db.FetchPolicyRules(ctx, fp)
		if err != nil {
			t.Fatalf("FetchPolicyRules: %v", err)
		}
		m := map[string]bool{}
		for _, r := range res.Rules {
			m[r.SoftwareName] = true
		}
		return m
	}

	// До членства в группе: global+device видны, group — нет.
	before := names()
	if !before[globalName] {
		t.Errorf("global rule %q not visible", globalName)
	}
	if !before[deviceName] {
		t.Errorf("device rule %q not visible", deviceName)
	}
	if before[groupName] {
		t.Errorf("group rule %q visible before membership", groupName)
	}

	// После добавления в группу: групповое правило становится видимым.
	if err := db.AddDeviceToGroup(ctx, deviceID, group.ID); err != nil {
		t.Fatalf("AddDeviceToGroup: %v", err)
	}
	after := names()
	if !after[groupName] {
		t.Errorf("group rule %q not visible after membership", groupName)
	}
	if !after[globalName] || !after[deviceName] {
		t.Errorf("global/device rule disappeared after membership: %v", after)
	}

	// После удаления из группы: групповое правило снова невидимо.
	if err := db.RemoveDeviceFromGroup(ctx, deviceID, group.ID); err != nil {
		t.Fatalf("RemoveDeviceFromGroup: %v", err)
	}
	if names()[groupName] {
		t.Errorf("group rule %q still visible after removal", groupName)
	}
}

func TestAssignUnassignSoftwarePolicyToGroup(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	group, err := db.CreateDeviceGroup(ctx, "grp-assign-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	other, err := db.CreateDeviceGroup(ctx, "grp-other-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup other: %v", err)
	}

	rule, err := db.AssignSoftwarePolicyToGroup(ctx, group.ID, "app-"+suffix, "forbidden")
	if err != nil {
		t.Fatalf("AssignSoftwarePolicyToGroup: %v", err)
	}
	if rule.ID == "" {
		t.Fatal("assigned rule has empty id")
	}
	if rule.GroupID == nil || *rule.GroupID != group.ID {
		t.Errorf("rule.GroupID = %v, want %s", rule.GroupID, group.ID)
	}

	countRules := func(groupID string) int {
		groups, err := db.ListDeviceGroups(ctx)
		if err != nil {
			t.Fatalf("ListDeviceGroups: %v", err)
		}
		for _, g := range groups {
			if g.ID == groupID {
				return len(g.SoftwareRules)
			}
		}
		t.Fatalf("group %s not found in ListDeviceGroups", groupID)
		return -1
	}

	if n := countRules(group.ID); n != 1 {
		t.Errorf("software_rules len = %d, want 1", n)
	}

	// Снятие с ЧУЖОЙ группой не удаляет правило.
	if err := db.UnassignSoftwarePolicyFromGroup(ctx, other.ID, rule.ID); err != nil {
		t.Fatalf("UnassignSoftwarePolicyFromGroup wrong group: %v", err)
	}
	if n := countRules(group.ID); n != 1 {
		t.Errorf("after wrong-group unassign len = %d, want 1", n)
	}

	// Снятие с правильной группой удаляет.
	if err := db.UnassignSoftwarePolicyFromGroup(ctx, group.ID, rule.ID); err != nil {
		t.Fatalf("UnassignSoftwarePolicyFromGroup: %v", err)
	}
	if n := countRules(group.ID); n != 0 {
		t.Errorf("after unassign len = %d, want 0", n)
	}
}

func TestFanOutScriptToGroup_PlatformFilter(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	group, err := db.CreateDeviceGroup(ctx, "grp-fanout-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	winDev := mustCreateActiveDevice(t, db, "win-"+suffix, "Windows")
	macDev := mustCreateActiveDevice(t, db, "mac-"+suffix, "macos")
	linuxDev := mustCreateActiveDevice(t, db, "lin-"+suffix, "linux")
	for _, d := range []string{winDev.ID, macDev.ID, linuxDev.ID} {
		if err := db.AddDeviceToGroup(ctx, d, group.ID); err != nil {
			t.Fatalf("AddDeviceToGroup %s: %v", d, err)
		}
	}

	// Каждая платформа должна поймать РОВНО своё устройство: до фикса матчинг был
	// бинарным (windows / не-windows), и macOS-скрипт улетал ещё и на Linux.
	for _, tc := range []struct {
		platform string
		wantDev  string
	}{
		{"Windows", winDev.ID},
		{"macOS", macDev.ID},
		{"linux", linuxDev.ID},
	} {
		tasks, err := db.FanOutScriptToGroup(ctx, group.ID, "echo "+tc.platform, tc.platform, "medium")
		if err != nil {
			t.Fatalf("FanOutScriptToGroup %s: %v", tc.platform, err)
		}
		if len(tasks) != 1 {
			t.Fatalf("%s fan-out created %d tasks, want 1", tc.platform, len(tasks))
		}
		if tasks[0].DeviceID != tc.wantDev {
			t.Errorf("%s task device = %s, want %s", tc.platform, tasks[0].DeviceID, tc.wantDev)
		}
		if tasks[0].Platform != tc.platform {
			t.Errorf("%s task platform = %q, want %q", tc.platform, tasks[0].Platform, tc.platform)
		}
	}

	// Пустая группа → 0 задач.
	empty, err := db.CreateDeviceGroup(ctx, "grp-empty-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup empty: %v", err)
	}
	tasks, err := db.FanOutScriptToGroup(ctx, empty.ID, "echo none", "linux", "medium")
	if err != nil {
		t.Fatalf("FanOutScriptToGroup empty: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("empty group fan-out created %d tasks, want 0", len(tasks))
	}
}

// Версия набора правил обязана меняться при удалении ЛЮБОГО правила, а не только
// самого свежего. Пока версией был MAX(updated_at), удаление не-новейшего правила
// оставляло версию прежней, агент видел Unchanged и вечно блокировал разрешённое ПО.
func TestFetchPolicyRules_VersionTracksSetMembership(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	fp := "fp-ver-" + suffix
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, "cn-"+suffix, "cn-"+suffix, "1.2.3.4")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}
	deviceID, err := db.GetDeviceIDByFingerprint(ctx, fp)
	if err != nil || deviceID == "" {
		t.Fatalf("GetDeviceIDByFingerprint: id=%q err=%v", deviceID, err)
	}

	var ruleIDs []string
	for i, name := range []string{"first-" + suffix, "second-" + suffix, "third-" + suffix} {
		rule, err := db.CreatePolicyRule(ctx, name, "forbidden", &deviceID, nil)
		if err != nil {
			t.Fatalf("CreatePolicyRule %d: %v", i, err)
		}
		ruleIDs = append(ruleIDs, rule.ID)
	}

	version := func() int64 {
		res, err := db.FetchPolicyRules(ctx, fp)
		if err != nil {
			t.Fatalf("FetchPolicyRules: %v", err)
		}
		return res.Version
	}

	full := version()
	if full == 0 {
		t.Fatal("version of a non-empty rule set must be non-zero")
	}

	// Удаляем СРЕДНЕЕ правило — MAX(updated_at) при этом не двигается.
	if err := db.DeletePolicyRule(ctx, ruleIDs[1]); err != nil {
		t.Fatalf("DeletePolicyRule: %v", err)
	}
	if after := version(); after == full {
		t.Fatalf("version unchanged (%d) after deleting a non-newest rule", after)
	}
}

func TestCreateDeviceGroup_DuplicateName(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	name := "grp-dup-" + uniq(t)

	if _, err := db.CreateDeviceGroup(ctx, name, ""); err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	// Регистр и краевые пробелы не делают имя новым.
	if _, err := db.CreateDeviceGroup(ctx, "  "+strings.ToUpper(name)+" ", ""); !errors.Is(err, storage.ErrDuplicateGroupName) {
		t.Fatalf("duplicate group name err = %v, want ErrDuplicateGroupName", err)
	}
}

// Пустой цвет — не ошибка, а «на усмотрение схемы»: группу создают и миграции, и psql,
// и старый клиент, который про цвет ничего не знает. Значение обязано совпасть с
// DEFAULT'ом колонки, иначе UI покрасит рамку в пустоту.
func TestCreateDeviceGroup_Color(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	explicit, err := db.CreateDeviceGroup(ctx, "grp-color-"+suffix, "#a1b2c3")
	if err != nil {
		t.Fatalf("CreateDeviceGroup с цветом: %v", err)
	}
	if explicit.Color != "#a1b2c3" {
		t.Errorf("color = %q, want #a1b2c3", explicit.Color)
	}

	def, err := db.CreateDeviceGroup(ctx, "grp-nocolor-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup без цвета: %v", err)
	}
	if def.Color != storage.DefaultGroupColor {
		t.Errorf("color = %q, want DefaultGroupColor %q", def.Color, storage.DefaultGroupColor)
	}
}

// Пустая строка в UpdateDeviceGroup означает «поле не трогать»: PATCH из UI шлёт только
// то, что человек поменял, и переименование не должно сбрасывать цвет (и наоборот).
func TestUpdateDeviceGroup_PartialUpdate(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	group, err := db.CreateDeviceGroup(ctx, "grp-upd-"+suffix, "#111111")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}

	// Только цвет: имя остаётся прежним.
	got, err := db.UpdateDeviceGroup(ctx, group.ID, "", "#222222")
	if err != nil {
		t.Fatalf("UpdateDeviceGroup (цвет): %v", err)
	}
	if got.Color != "#222222" || got.Name != group.Name {
		t.Errorf("после смены цвета = {%q %q}, want {%q #222222}", got.Name, got.Color, group.Name)
	}

	// Только имя: цвет остаётся прежним.
	renamed := "grp-upd-renamed-" + suffix
	got, err = db.UpdateDeviceGroup(ctx, group.ID, renamed, "")
	if err != nil {
		t.Fatalf("UpdateDeviceGroup (имя): %v", err)
	}
	if got.Name != renamed || got.Color != "#222222" {
		t.Errorf("после переименования = {%q %q}, want {%q #222222}", got.Name, got.Color, renamed)
	}

	// Оба поля сразу.
	both := "grp-upd-both-" + suffix
	got, err = db.UpdateDeviceGroup(ctx, group.ID, both, "#333333")
	if err != nil {
		t.Fatalf("UpdateDeviceGroup (оба): %v", err)
	}
	if got.Name != both || got.Color != "#333333" {
		t.Errorf("после смены обоих = {%q %q}, want {%q #333333}", got.Name, got.Color, both)
	}
}

// Несуществующая и просто кривая группа — это (nil, nil), а не ошибка: хендлер обязан
// отдать 404. Сравнение идёт по id::text, поэтому мусор вместо UUID не даёт 22P02 → 500.
func TestUpdateDeviceGroup_NotFound(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	for _, id := range []string{
		"00000000-0000-0000-0000-000000000000",
		"не-uuid-вовсе",
		"",
	} {
		got, err := db.UpdateDeviceGroup(ctx, id, "new-name-"+uniq(t), "#abcdef")
		if err != nil {
			t.Errorf("UpdateDeviceGroup(%q): err = %v, want nil", id, err)
		}
		if got != nil {
			t.Errorf("UpdateDeviceGroup(%q) = %+v, want nil", id, got)
		}
	}
}

// Переименование в уже занятое имя — конфликт, а не 500 от 23505.
func TestUpdateDeviceGroup_DuplicateName(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	taken, err := db.CreateDeviceGroup(ctx, "grp-taken-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup taken: %v", err)
	}
	group, err := db.CreateDeviceGroup(ctx, "grp-free-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup free: %v", err)
	}

	// Регистр и краевые пробелы не спасают: уникальность по lower(trim(name)) (026).
	if _, err := db.UpdateDeviceGroup(ctx, group.ID, "  "+strings.ToUpper(taken.Name)+" ", ""); !errors.Is(err, storage.ErrDuplicateGroupName) {
		t.Fatalf("duplicate rename err = %v, want ErrDuplicateGroupName", err)
	}
}

// Цвет уезжает прямо в inline-style фронта, поэтому формат стережёт не только хендлер,
// но и CHECK из миграции 027: строку в БД пишут и psql, и будущие миграции. Заодно
// фиксируем, что верхний регистр НЕ проходит — значит нормализация в хендлере
// обязательна, а не косметика.
func TestDeviceGroupColor_CheckConstraintRejectsGarbage(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	group, err := db.CreateDeviceGroup(ctx, "grp-check-"+uniq(t), "#123abc")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}

	// Пул storage.DB не экспортирован — открываем собственное соединение на тот же DSN.
	conn, err := pgx.Connect(ctx, sharedDSN)
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(ctx)

	for _, bad := range []string{"red", "#fff", "#gggggg", "#3B82F6", "3b82f6", "#3b82f6;"} {
		t.Run(bad, func(t *testing.T) {
			_, err := conn.Exec(ctx, `UPDATE device_groups SET color = $2 WHERE id = $1`, group.ID, bad)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("color=%q принят базой (err = %v), ожидали нарушение CHECK", bad, err)
			}
			if pgErr.Code != "23514" || pgErr.ConstraintName != "device_groups_color_hex" {
				t.Errorf("color=%q: code=%s constraint=%s, want 23514/device_groups_color_hex",
					bad, pgErr.Code, pgErr.ConstraintName)
			}
		})
	}
}

// Отпечаток набора обязан различать наборы, отличающиеся только границами полей.
// Имя ПО приходит от человека: байт-разделитель внутри имени раньше склеивал два
// разных набора в одну версию, и агент навсегда оставался на старом (Unchanged).
func TestFetchPolicyRules_VersionResistsSeparatorInjection(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	version := func(fp string) int64 {
		t.Helper()
		res, err := db.FetchPolicyRules(ctx, fp)
		if err != nil {
			t.Fatalf("FetchPolicyRules: %v", err)
		}
		return res.Version
	}

	// Устройство A: одно правило, чьё имя содержит разделители полей и элементов.
	fpA := "fp-inj-a-" + suffix
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fpA, "cn-a-"+suffix, "cn-a-"+suffix, "1.2.3.4")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat A: %v", err)
	}
	idA, err := db.GetDeviceIDByFingerprint(ctx, fpA)
	if err != nil {
		t.Fatalf("GetDeviceIDByFingerprint A: %v", err)
	}
	if _, err := db.CreatePolicyRule(ctx, "a\x1fforbidden\x1fz"+suffix, "forbidden", &idA, nil); err != nil {
		t.Fatalf("CreatePolicyRule A: %v", err)
	}

	// Устройство B: два правила, дающие тот же поток байт при наивной склейке.
	fpB := "fp-inj-b-" + suffix
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fpB, "cn-b-"+suffix, "cn-b-"+suffix, "1.2.3.5")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat B: %v", err)
	}
	idB, err := db.GetDeviceIDByFingerprint(ctx, fpB)
	if err != nil {
		t.Fatalf("GetDeviceIDByFingerprint B: %v", err)
	}
	if _, err := db.CreatePolicyRule(ctx, "a", "forbidden", &idB, nil); err != nil {
		t.Fatalf("CreatePolicyRule B1: %v", err)
	}
	if _, err := db.CreatePolicyRule(ctx, "z"+suffix, "forbidden", &idB, nil); err != nil {
		t.Fatalf("CreatePolicyRule B2: %v", err)
	}

	if version(fpA) == version(fpB) {
		t.Error("разные наборы правил дали одинаковую версию — границы полей размыты")
	}
}
