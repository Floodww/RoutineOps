package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/api"
	"github.com/Floodww/RoutineOps/internal/server/mailer"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"github.com/Floodww/RoutineOps/internal/server/uninstall"
)

// Удаление ПО — open-core на всех редакциях (перенос из enterprise 13.08.2026): ни
// build-тега, ни лицензионного энтайтлмента, и тесты тоже без тега.
//
// 🔴 Тег с них снят 17.08.2026, и это не косметика. Пока он стоял, ручка ехала в открытую
// сборку БЕЗ единого теста: `_ent_test.go` в неё не компилируется, покрытие пакета в
// open-core падало до 6.4% при поле 55%, и гейт покрытия Free-среза был красным с 15.08.
// Держал тег ровно один повод — четыре хелпера (activeDeviceID, markEnrolled,
// auditCountForTarget, taskCount) лежали в enterprise-файлах; они переехали в
// helpers_test.go. Урок общий: перенос фичи между редакциями — это и перенос её тестов,
// иначе открытая сборка получает непокрытый код, а суперсет этого не показывает.

func newRouterWithUninstall(t *testing.T, db *storage.DB) http.Handler {
	t.Helper()
	svc := uninstall.NewService(db, nil, // asynq nil: worker.Enqueue его проверяет,
		// а доставка тут не проверяется — задача уже в БД, её добьёт реконсайлер.
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	return api.NewRouter(db, nil, []byte("test-secret"), nil, "https://test.local", t.TempDir(),
		mailer.New("", "", "", "", "", false), false, uninstall.Routes(svc))
}

// insertSoftware кладёт запись в инвентарь устройства. method="" означает «снять нечем»
// (per-user установки Windows, защищённое SIP на macOS) — это отдельная ветка отказа.
func insertSoftware(t *testing.T, db *storage.DB, deviceID, name, uninstallID, method string) {
	t.Helper()
	ctx, finish, err := db.BindTenant(context.Background(), tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	defer finish(true)
	if _, err := db.Scoped(ctx).Exec(ctx, `
		INSERT INTO device_software
		    (tenant_id, device_id, software_name, version, uninstall_id, install_location, uninstall_method, scope)
		VALUES ($1, $2, $3, '1.0', $4, '/Applications/X.app', $5, 'machine')`,
		tenancy.DefaultTenantID, deviceID, name, uninstallID, method); err != nil {
		t.Fatalf("инвентарь: %v", err)
	}
}

func uninstallBody(t *testing.T, name, uninstallID, reason string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"software_name": name, "uninstall_id": uninstallID, "reason": reason,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func uninstallPath(deviceID string) string {
	return "/api/v1/devices/" + deviceID + "/software/uninstall"
}

// Счастливый путь: задача создана, селектор в ней собран СЕРВЕРОМ из инвентаря, и
// запись в журнале появилась до постановки в очередь.
func TestUninstallCreatesTaskAndAudits(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterWithUninstall(t, db)
	tok := authToken(t, rtr, db)
	deviceID := activeDeviceID(t, rtr, db, tok, "uninst-ok")
	insertSoftware(t, db, deviceID, "Толстый Клиент", "{GUID-1}", "msiexec")

	w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID),
		uninstallBody(t, "Толстый Клиент", "{GUID-1}", "запрещён политикой"), tok)
	if w.Code != http.StatusAccepted {
		t.Fatalf("код %d, ожидался 202: %s", w.Code, w.Body)
	}
	var resp struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	if resp.TaskID == "" || resp.Status != "pending" {
		t.Fatalf("ответ разъехался: %+v", resp)
	}

	// Метод в задаче — из инвентаря, а не из тела запроса: селектор собирает сервер.
	ctx, finish, err := db.BindTenant(context.Background(), tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	defer finish(true)
	var method, scope, reason string
	if err := db.Scoped(ctx).QueryRow(ctx,
		`SELECT uninstall_method, uninstall_scope, uninstall_reason FROM tasks WHERE id = $1`,
		resp.TaskID).Scan(&method, &scope, &reason); err != nil {
		t.Fatalf("чтение задачи: %v", err)
	}
	if method != "msiexec" || scope != "machine" {
		t.Errorf("селектор задачи %q/%q — не из инвентаря сервера", method, scope)
	}
	if reason != "запрещён политикой" {
		t.Errorf("повод не доехал: %q", reason)
	}
	if n := auditCountForTarget(t, db, "uninstall_software", deviceID); n != 1 {
		t.Fatalf("строк аудита %d, ожидалась одна: удаление ПО без следа недопустимо", n)
	}
}

// Отказы по состоянию цели. Каждый — своя ветка, и каждая должна отдавать оператору
// РАЗНЫЙ повод: «обновите инвентарь» и «снять нечем» требуют разных действий.
func TestUninstallTargetStates(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterWithUninstall(t, db)
	tok := authToken(t, rtr, db)

	t.Run("нет в инвентаре → 409", func(t *testing.T) {
		deviceID := activeDeviceID(t, rtr, db, tok, "uninst-absent")
		w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID),
			uninstallBody(t, "Которого Нет", "{GUID-X}", "проверка"), tok)
		if w.Code != http.StatusConflict {
			t.Fatalf("код %d, ожидался 409: %s", w.Code, w.Body)
		}
	})

	t.Run("снять нечем → 409", func(t *testing.T) {
		deviceID := activeDeviceID(t, rtr, db, tok, "uninst-nomethod")
		insertSoftware(t, db, deviceID, "Пользовательский", "{GUID-2}", "")
		w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID),
			uninstallBody(t, "Пользовательский", "{GUID-2}", "проверка"), tok)
		if w.Code != http.StatusConflict {
			t.Fatalf("код %d, ожидался 409: %s", w.Code, w.Body)
		}
		if n := taskCount(t, db, deviceID, "uninstall"); n != 0 {
			t.Fatalf("создано %d задач на неудаляемое ПО", n)
		}
	})

	t.Run("устройство не active → 409", func(t *testing.T) {
		deviceID, _ := createDevice(t, rtr, tok, "uninst-pending", "windows")
		insertSoftware(t, db, deviceID, "Толстый Клиент", "{GUID-3}", "msiexec")
		w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID),
			uninstallBody(t, "Толстый Клиент", "{GUID-3}", "проверка"), tok)
		if w.Code != http.StatusConflict {
			t.Fatalf("код %d, ожидался 409: %s", w.Code, w.Body)
		}
	})
}

// Разбор запроса: имя обязательно, мусорное тело — 400, а не 500.
func TestUninstallRejectsMalformedRequest(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterWithUninstall(t, db)
	tok := authToken(t, rtr, db)
	deviceID := activeDeviceID(t, rtr, db, tok, "uninst-bad")

	for name, body := range map[string][]byte{
		"не JSON":            []byte(`{не json`),
		"пустое имя":         uninstallBody(t, "", "{GUID-1}", "проверка"),
		"имя из пробелов":    uninstallBody(t, "   ", "{GUID-1}", "проверка"),
		"вообще пустое тело": nil,
	} {
		t.Run(name, func(t *testing.T) {
			w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID), body, tok)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("код %d, ожидался 400: %s", w.Code, w.Body)
			}
		})
	}
}

// Роль: it_admin БЕЗ requireHuman — удаление ПО не выдаёт и не повышает права, а
// массовая зачистка запрещённого софта автоматикой законна. Но viewer его не берёт.
func TestUninstallRejectsViewerAndAllowsServiceToken(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterWithUninstall(t, db)
	adminTok := authToken(t, rtr, db)
	deviceID := activeDeviceID(t, rtr, db, adminTok, "uninst-roles")
	insertSoftware(t, db, deviceID, "Толстый Клиент", "{GUID-1}", "msiexec")

	viewerTok := tokenForRole(t, rtr, db, "viewer", "uninst_viewer_")
	if w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID),
		uninstallBody(t, "Толстый Клиент", "{GUID-1}", "проверка"), viewerTok); w.Code != http.StatusForbidden {
		t.Fatalf("viewer получил %d — на ручке нет гейта роли: %s", w.Code, w.Body)
	}

	user, err := db.CreateUser(context.Background(), tenancy.DefaultTenantID,
		"Uninst Svc", "uninst-svc@test.local", "x", "it_admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	secret := serviceTokenSecret(t)
	if _, err := db.CreateAPIToken(context.Background(), tenancy.DefaultTenantID,
		"uninst", "it_admin", "", user.ID, secret, nil); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if w := authedDo(t, rtr, http.MethodPost, uninstallPath(deviceID),
		uninstallBody(t, "Толстый Клиент", "{GUID-1}", "автозачистка"), "Bearer "+secret); w.Code != http.StatusAccepted {
		t.Fatalf("сервисный токен получил %d, ожидался 202 — автозачистка тут законна: %s", w.Code, w.Body)
	}
}
