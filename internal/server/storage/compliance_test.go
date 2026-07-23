package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// mustRuleWithDeviceAndGroup вставляет правило, у которого заполнены И device_id, И
// group_id. Ни один метод storage такую строку не создаёт (CreatePolicyRule ставит
// только device_id, AssignSoftwarePolicyToGroup — только group_id), но схема это
// позволяет, а FetchPolicyRules такие правила агенту отдаёт. Пул не экспортирован —
// открываем собственное соединение на тот же DSN.
func mustRuleWithDeviceAndGroup(t *testing.T, softwareName, deviceID, groupID string) string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, sharedDSN)
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(ctx)

	var id string
	if err := conn.QueryRow(ctx, `
		INSERT INTO software_policy_rules (software_name, rule_type, device_id, group_id)
		VALUES ($1, 'forbidden', $2, $3)
		RETURNING id
	`, softwareName, deviceID, groupID).Scan(&id); err != nil {
		t.Fatalf("INSERT software_policy_rules: %v", err)
	}
	return id
}

// activeDevice — не-pending устройство с заданной ОС и инвентарём ПО.
//
// Идём через heartbeat + UpsertInventory, а не через mustCreateDevice: тот создаёт
// устройство в статусе pending, которое compliance по определению не считает, а
// device_software пишется ТОЛЬКО инвентарём (матчится по fingerprint). Иначе говоря,
// «просто вставить устройство» для этих тестов недостаточно.
//
// IP из TEST-NET-1 (192.0.2.0/24) — синтетика, как того требует leak-guard.
func activeDevice(t *testing.T, db *storage.DB, name, os string, software ...string) string {
	t.Helper()
	ctx := context.Background()
	fp := "fp-" + name
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, name, name, "192.0.2.10")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat %s: %v", name, err)
	}
	if err := db.UpsertInventory(ctx, storageInventoryData(fp, name, os, "1.0", software)); err != nil {
		t.Fatalf("UpsertInventory %s: %v", name, err)
	}
	id, err := db.GetDeviceIDByFingerprint(ctx, fp)
	if err != nil || id == "" {
		t.Fatalf("GetDeviceIDByFingerprint %s: id=%q err=%v", name, id, err)
	}
	return id
}

// softwareCompliance достаёт строку по конкретному правилу. Пакет делит одну БД, поэтому
// в выдаче всегда лежат ещё и правила соседних тестов — фильтруем по своему rule_id.
func softwareCompliance(t *testing.T, db *storage.DB, ruleID string) storage.SoftwarePolicyCompliance {
	t.Helper()
	rows, err := db.ListSoftwarePolicyCompliance(context.Background())
	if err != nil {
		t.Fatalf("ListSoftwarePolicyCompliance: %v", err)
	}
	for _, r := range rows {
		if r.RuleID == ruleID {
			return r
		}
	}
	t.Fatalf("правило %s отсутствует в выдаче compliance", ruleID)
	return storage.SoftwarePolicyCompliance{}
}

func scriptCompliance(t *testing.T, db *storage.DB, policyID string) storage.ScriptPolicyCompliance {
	t.Helper()
	rows, err := db.ListScriptPolicyCompliance(context.Background())
	if err != nil {
		t.Fatalf("ListScriptPolicyCompliance: %v", err)
	}
	for _, r := range rows {
		if r.PolicyID == policyID {
			return r
		}
	}
	t.Fatalf("политика %s отсутствует в выдаче compliance", policyID)
	return storage.ScriptPolicyCompliance{}
}

// checkCompliance сравнивает все четыре счётчика разом — иначе при регрессии видно
// только первое расхождение, а не картину целиком.
func checkCompliance(t *testing.T, got storage.SoftwarePolicyCompliance, inScope, pass, fail int, checked bool) {
	t.Helper()
	if got.InScope != inScope || got.Pass != pass || got.Fail != fail || got.Checked != checked {
		t.Errorf("compliance = {in_scope:%d pass:%d fail:%d checked:%v}, want {in_scope:%d pass:%d fail:%d checked:%v}",
			got.InScope, got.Pass, got.Fail, got.Checked, inScope, pass, fail, checked)
	}
}

func TestListSoftwarePolicyCompliance(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	// Глобальное правило по определению действует на ВЕСЬ парк, а парк в этом пакете —
	// общая БД со всеми устройствами соседних тестов. Поэтому in_scope сверяем с реальным
	// списком не-pending устройств, а не с константой 2. Уникальное имя ПО гарантирует,
	// что нарушитель ровно один — наш.
	t.Run("глобальное forbidden-правило: pass+fail покрывают весь парк", func(t *testing.T) {
		suffix := uniq(t)
		app := "globalapp-" + suffix
		activeDevice(t, db, "gclean-"+suffix, "Windows 11")
		activeDevice(t, db, "gdirty-"+suffix, "Windows 11", app)

		rule, err := db.CreatePolicyRule(ctx, app, "forbidden", nil, nil)
		if err != nil {
			t.Fatalf("CreatePolicyRule: %v", err)
		}
		all, _, err := db.ListEnrolledDevices(ctx, "", "", 0, 0)
		if err != nil {
			t.Fatalf("ListEnrolledDevices: %v", err)
		}
		if len(all) < 2 {
			t.Fatalf("в парке %d не-pending устройств, ожидали минимум 2 наших", len(all))
		}
		checkCompliance(t, softwareCompliance(t, db, rule.ID), len(all), len(all)-1, 1, true)
	})

	// Агент ищет запрещённое ПО подстрокой без учёта регистра (findForbidden), значит
	// правило "chrome" обязано ловить инвентарную запись "Google Chrome 120". Правило
	// device-scoped: иначе в in_scope приедут чужие устройства с Chrome из соседних тестов.
	t.Run("подстрока без учёта регистра", func(t *testing.T) {
		suffix := uniq(t)
		dev := activeDevice(t, db, "sub-"+suffix, "Windows 11", "Google Chrome 120")
		rule, err := db.CreatePolicyRule(ctx, "chrome", "forbidden", &dev, nil)
		if err != nil {
			t.Fatalf("CreatePolicyRule: %v", err)
		}
		checkCompliance(t, softwareCompliance(t, db, rule.ID), 1, 0, 1, true)
	})

	// allowed-правила агент в кэш не пишет и не проверяет, поэтому pass/fail для них
	// смысла не имеют: Checked=false, счётчики нулевые ДАЖЕ когда ПО установлено.
	// in_scope при этом считается — UI показывает охват правила.
	t.Run("allowed-правило не проверяется", func(t *testing.T) {
		suffix := uniq(t)
		app := "allowedapp-" + suffix
		dev := activeDevice(t, db, "allow-"+suffix, "Windows 11", app)
		rule, err := db.CreatePolicyRule(ctx, app, "allowed", &dev, nil)
		if err != nil {
			t.Fatalf("CreatePolicyRule: %v", err)
		}
		checkCompliance(t, softwareCompliance(t, db, rule.ID), 1, 0, 0, false)
	})

	// Device-оверрайд не расползается на парк: сколько бы устройств ни было, in_scope=1.
	t.Run("device-scoped правило видит одно устройство", func(t *testing.T) {
		suffix := uniq(t)
		app := "devapp-" + suffix
		target := activeDevice(t, db, "dtarget-"+suffix, "Windows 11", app)
		activeDevice(t, db, "dother1-"+suffix, "Windows 11", app)
		activeDevice(t, db, "dother2-"+suffix, "Windows 11", app)

		rule, err := db.CreatePolicyRule(ctx, app, "forbidden", &target, nil)
		if err != nil {
			t.Fatalf("CreatePolicyRule: %v", err)
		}
		checkCompliance(t, softwareCompliance(t, db, rule.ID), 1, 0, 1, true)
	})

	// Групповое правило действует только на членов группы — даже если ровно тот же софт
	// стоит на устройстве за её пределами.
	t.Run("group-scoped правило видит только членов группы", func(t *testing.T) {
		suffix := uniq(t)
		app := "grpapp-" + suffix
		group, err := db.CreateDeviceGroup(ctx, "grp-comp-"+suffix, "")
		if err != nil {
			t.Fatalf("CreateDeviceGroup: %v", err)
		}
		member := activeDevice(t, db, "gmember-"+suffix, "Windows 11", app)
		activeDevice(t, db, "goutsider-"+suffix, "Windows 11", app)
		if err := db.AddDeviceToGroup(ctx, member, group.ID); err != nil {
			t.Fatalf("AddDeviceToGroup: %v", err)
		}

		rule, err := db.AssignSoftwarePolicyToGroup(ctx, group.ID, app, "forbidden")
		if err != nil {
			t.Fatalf("AssignSoftwarePolicyToGroup: %v", err)
		}
		checkCompliance(t, softwareCompliance(t, db, rule.ID), 1, 0, 1, true)
	})

	// Платформенный фильтр — SQL-двойник normalizePlatform, включая fail-safe: если ОС
	// не сообщена ('' от старого агента) или ещё 'unknown' (устройство только что дало
	// heartbeat), устройство ОСТАЁТСЯ в области действия. Иначе правило молча перестало
	// бы покрывать машины, про которые мы просто пока ничего не знаем.
	t.Run("платформенный фильтр", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			os          string
			wantInScope int
		}{
			{"windows попадает", "Windows 11", 1},
			{"linux отсекается", "Ubuntu 24.04", 0},
			{"macOS отсекается", "macOS 14", 0},
			{"пустая ОС остаётся в области (fail-safe)", "", 1},
			{"unknown остаётся в области (fail-safe)", "unknown", 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				inner := uniq(t)
				app := "platapp-" + inner
				dev := activeDevice(t, db, "plat-"+inner, tc.os, app)
				rule, err := db.CreatePolicyRule(ctx, app, "forbidden", &dev, []string{"Windows"})
				if err != nil {
					t.Fatalf("CreatePolicyRule: %v", err)
				}
				got := softwareCompliance(t, db, rule.ID)
				if got.InScope != tc.wantInScope {
					t.Errorf("os=%q: in_scope = %d, want %d", tc.os, got.InScope, tc.wantInScope)
				}
				// Раз устройство в области — софт на нём стоит, значит это fail.
				if got.Fail != tc.wantInScope {
					t.Errorf("os=%q: fail = %d, want %d", tc.os, got.Fail, tc.wantInScope)
				}
			})
		}
	})

	// Pending-устройство ещё не наше: сертификата нет, инвентарь мог остаться от прошлой
	// жизни. Считать его нарушителем — врать в UI. Проверяем ОБА направления, иначе тест
	// прошёл бы и на запросе, который вообще ничего не находит.
	t.Run("pending-устройство не считается", func(t *testing.T) {
		suffix := uniq(t)
		app := "pendapp-" + suffix
		dev := activeDevice(t, db, "pend-"+suffix, "Windows 11", app)
		rule, err := db.CreatePolicyRule(ctx, app, "forbidden", &dev, nil)
		if err != nil {
			t.Fatalf("CreatePolicyRule: %v", err)
		}
		checkCompliance(t, softwareCompliance(t, db, rule.ID), 1, 0, 1, true)

		if err := db.UpdateDeviceStatus(ctx, dev, "pending"); err != nil {
			t.Fatalf("UpdateDeviceStatus: %v", err)
		}
		checkCompliance(t, softwareCompliance(t, db, rule.ID), 0, 0, 0, true)
	})

	// Правило с ОБОИМИ полями (device_id и group_id) — область действия объединение, а не
	// пересечение: ровно так его резолвит FetchPolicyRules (device_id = $1 OR group_id IN
	// (группы устройства)), значит агент применит его и к оверрайд-устройству, и к членам
	// группы. Compliance обязан считать тот же набор, иначе UI разойдётся с агентом.
	t.Run("правило с device_id и group_id: объединение областей", func(t *testing.T) {
		suffix := uniq(t)
		app := "bothapp-" + suffix
		group, err := db.CreateDeviceGroup(ctx, "grp-both-"+suffix, "")
		if err != nil {
			t.Fatalf("CreateDeviceGroup: %v", err)
		}
		override := activeDevice(t, db, "bover-"+suffix, "Windows 11", app)
		member := activeDevice(t, db, "bmember-"+suffix, "Windows 11")
		activeDevice(t, db, "boutsider-"+suffix, "Windows 11", app)
		if err := db.AddDeviceToGroup(ctx, member, group.ID); err != nil {
			t.Fatalf("AddDeviceToGroup: %v", err)
		}

		ruleID := mustRuleWithDeviceAndGroup(t, app, override, group.ID)
		// override (софт стоит) + member (софта нет); посторонний с тем же софтом — мимо.
		checkCompliance(t, softwareCompliance(t, db, ruleID), 2, 1, 1, true)
	})

	// Устройство, попавшее в область И как оверрайд, И как член группы, обязано считаться
	// ОДИН раз: сейчас scope — это JOIN по devices, но стоит переписать его на UNION
	// подзапросов, и появится двойной счёт (in_scope=3 при двух устройствах).
	t.Run("устройство в обеих ветках не двоится", func(t *testing.T) {
		suffix := uniq(t)
		app := "dupapp-" + suffix
		group, err := db.CreateDeviceGroup(ctx, "grp-dup-scope-"+suffix, "")
		if err != nil {
			t.Fatalf("CreateDeviceGroup: %v", err)
		}
		override := activeDevice(t, db, "dover-"+suffix, "Windows 11", app)
		member := activeDevice(t, db, "dmember-"+suffix, "Windows 11")
		// override состоит в той же группе — совпадают обе ветки предиката.
		for _, d := range []string{override, member} {
			if err := db.AddDeviceToGroup(ctx, d, group.ID); err != nil {
				t.Fatalf("AddDeviceToGroup %s: %v", d, err)
			}
		}

		ruleID := mustRuleWithDeviceAndGroup(t, app, override, group.ID)
		checkCompliance(t, softwareCompliance(t, db, ruleID), 2, 1, 1, true)
	})

	// strpos(x, '') = 1 — то есть пустая подстрока «находится» в любой строке. Без явного
	// отсева software_name = '' правило с пустым именем объявило бы нарушителями всех.
	// Хендлер такое имя не пропустит, но правило может приехать миграцией или из psql.
	t.Run("правило с пустым software_name никого не валит", func(t *testing.T) {
		suffix := uniq(t)
		dev := activeDevice(t, db, "empty-"+suffix, "Windows 11", "SomeApp-"+suffix)
		rule, err := db.CreatePolicyRule(ctx, "", "forbidden", &dev, nil)
		if err != nil {
			t.Fatalf("CreatePolicyRule с пустым именем: %v", err)
		}
		checkCompliance(t, softwareCompliance(t, db, rule.ID), 1, 1, 0, true)
	})
}

func TestListSoftwarePolicyDeviceCompliance(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	// Построчный разрез должен сходиться с агрегатом: нарушитель — с именем и версией
	// совпавшего ПО, чистое устройство — installed=false с пустым совпадением.
	// Нарушители сортируются первыми.
	t.Run("нарушитель с совпавшим ПО первым, чистый следом", func(t *testing.T) {
		suffix := uniq(t)
		dirty := activeDevice(t, db, "ddirty-"+suffix, "Windows 11", "Google Chrome 120")
		clean := activeDevice(t, db, "aclean-"+suffix, "Windows 11") // 'a…' — по алфавиту раньше dirty
		group, err := db.CreateDeviceGroup(ctx, "grp-detail-"+suffix, "")
		if err != nil {
			t.Fatalf("CreateDeviceGroup: %v", err)
		}
		for _, d := range []string{dirty, clean} {
			if err := db.AddDeviceToGroup(ctx, d, group.ID); err != nil {
				t.Fatalf("AddDeviceToGroup: %v", err)
			}
		}
		rule, err := db.AssignSoftwarePolicyToGroup(ctx, group.ID, "chrome", "forbidden")
		if err != nil {
			t.Fatalf("AssignSoftwarePolicyToGroup: %v", err)
		}

		rows, err := db.ListSoftwarePolicyDeviceCompliance(ctx, rule.ID)
		if err != nil {
			t.Fatalf("ListSoftwarePolicyDeviceCompliance: %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("получено %d строк, want 2: %+v", len(rows), rows)
		}
		// Нарушитель первым — несмотря на то, что чистый раньше по алфавиту.
		if rows[0].DeviceID != dirty || !rows[0].Installed {
			t.Errorf("rows[0] = %+v, ожидали нарушителя %s первым", rows[0], dirty)
		}
		if rows[0].MatchedSoftware != "Google Chrome 120" {
			t.Errorf("matched_software = %q, want %q", rows[0].MatchedSoftware, "Google Chrome 120")
		}
		if rows[1].DeviceID != clean || rows[1].Installed || rows[1].MatchedSoftware != "" {
			t.Errorf("rows[1] = %+v, ожидали чистое устройство %s без совпадения", rows[1], clean)
		}
	})

	// Скоуп и платформенный фильтр — тот же SQL, что в агрегате; здесь достаточно
	// смок-проверки, что device-оверрайд не тащит чужие устройства, а платформа режет.
	t.Run("device-скоуп и платформенный фильтр", func(t *testing.T) {
		suffix := uniq(t)
		app := "detapp-" + suffix
		target := activeDevice(t, db, "dtgt-"+suffix, "macOS 14", app)
		activeDevice(t, db, "dout-"+suffix, "macOS 14", app) // вне скоупа

		rule, err := db.CreatePolicyRule(ctx, app, "forbidden", &target, []string{"macOS"})
		if err != nil {
			t.Fatalf("CreatePolicyRule: %v", err)
		}
		rows, err := db.ListSoftwarePolicyDeviceCompliance(ctx, rule.ID)
		if err != nil {
			t.Fatalf("ListSoftwarePolicyDeviceCompliance: %v", err)
		}
		if len(rows) != 1 || rows[0].DeviceID != target || !rows[0].Installed {
			t.Fatalf("rows = %+v, want ровно один нарушитель %s", rows, target)
		}

		// Правило только для Windows — mac-устройство выпадает из области действия.
		winRule, err := db.CreatePolicyRule(ctx, app, "forbidden", &target, []string{"Windows"})
		if err != nil {
			t.Fatalf("CreatePolicyRule (Windows): %v", err)
		}
		rows, err = db.ListSoftwarePolicyDeviceCompliance(ctx, winRule.ID)
		if err != nil {
			t.Fatalf("ListSoftwarePolicyDeviceCompliance (Windows): %v", err)
		}
		if len(rows) != 0 {
			t.Fatalf("rows = %+v, want пусто (платформа не совпала)", rows)
		}
	})

	// Несуществующее правило — пустой список, не ошибка: хендлер отдаст [].
	// Мусор вместо UUID — тоже пусто, не 22P02: id приходит сырым из URL
	// (/policies/garbage/compliance), сравнение идёт через id::text.
	t.Run("несуществующее правило и мусорный id — пусто", func(t *testing.T) {
		for _, id := range []string{"00000000-0000-0000-0000-000000000000", "garbage"} {
			rows, err := db.ListSoftwarePolicyDeviceCompliance(ctx, id)
			if err != nil {
				t.Fatalf("ListSoftwarePolicyDeviceCompliance(%q): %v", id, err)
			}
			if len(rows) != 0 {
				t.Fatalf("rows(%q) = %+v, want пусто", id, rows)
			}
		}
	})
}

// mustScriptPolicy создаёт скрипт + политику и возвращает id политики.
func mustScriptPolicy(t *testing.T, db *storage.DB, suffix string) string {
	t.Helper()
	ctx := context.Background()
	scr, err := db.CreateScript(ctx, "sc-comp-"+suffix, "linux", "echo hi")
	if err != nil {
		t.Fatalf("CreateScript: %v", err)
	}
	pol, err := db.CreateScriptPolicy(ctx, "pol-comp-"+suffix, scr.ID, "schedule", nil, nil)
	if err != nil {
		t.Fatalf("CreateScriptPolicy: %v", err)
	}
	return pol.ID
}

func mustSaveResult(t *testing.T, db *storage.DB, policyID, deviceID string, exitCode int32) {
	t.Helper()
	now := time.Now()
	if err := db.SaveScriptResult(context.Background(), storage.ScriptResultInput{
		PolicyID:   policyID,
		DeviceID:   deviceID,
		RunID:      "run-" + uniq(t),
		ExitCode:   exitCode,
		Trigger:    "schedule",
		StartedAt:  now,
		FinishedAt: now,
	}); err != nil {
		t.Fatalf("SaveScriptResult (exit %d): %v", exitCode, err)
	}
}

func TestListScriptPolicyCompliance(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	// Устройство без результата — не «прошло» и не «упало», а Unknown: политика назначена,
	// но агент ещё не отчитался. Схлопывать Unknown в Pass значило бы рисовать зелёный
	// щит машине, на которой скрипт вообще не запускался.
	t.Run("pass/fail/unknown по назначенной группе", func(t *testing.T) {
		suffix := uniq(t)
		policyID := mustScriptPolicy(t, db, suffix)
		group, err := db.CreateDeviceGroup(ctx, "grp-sc-"+suffix, "")
		if err != nil {
			t.Fatalf("CreateDeviceGroup: %v", err)
		}
		if err := db.AssignPolicyToGroup(ctx, policyID, group.ID); err != nil {
			t.Fatalf("AssignPolicyToGroup: %v", err)
		}
		ok := activeDevice(t, db, "scok-"+suffix, "Ubuntu 24.04")
		bad := activeDevice(t, db, "scbad-"+suffix, "Ubuntu 24.04")
		silent := activeDevice(t, db, "scsilent-"+suffix, "Ubuntu 24.04")
		for _, d := range []string{ok, bad, silent} {
			if err := db.AddDeviceToGroup(ctx, d, group.ID); err != nil {
				t.Fatalf("AddDeviceToGroup %s: %v", d, err)
			}
		}
		mustSaveResult(t, db, policyID, ok, 0)
		mustSaveResult(t, db, policyID, bad, 1)

		got := scriptCompliance(t, db, policyID)
		if got.InScope != 3 || got.Pass != 1 || got.Fail != 1 || got.Unknown != 1 {
			t.Errorf("compliance = %+v, want {in_scope:3 pass:1 fail:1 unknown:1}", got)
		}
	})

	// Побеждает ПОСЛЕДНИЙ прогон: машину починили, старый exit 1 не должен вечно красить
	// её в красный. Порядок задаёт created_at (серверное время), поэтому сначала
	// убеждаемся, что БД реально проставила разные метки, — иначе DISTINCT ON выбрал бы
	// строку случайно и тест был бы зелёным по совпадению.
	t.Run("последний прогон перекрывает предыдущий", func(t *testing.T) {
		suffix := uniq(t)
		policyID := mustScriptPolicy(t, db, suffix)
		group, err := db.CreateDeviceGroup(ctx, "grp-sc-latest-"+suffix, "")
		if err != nil {
			t.Fatalf("CreateDeviceGroup: %v", err)
		}
		if err := db.AssignPolicyToGroup(ctx, policyID, group.ID); err != nil {
			t.Fatalf("AssignPolicyToGroup: %v", err)
		}
		dev := activeDevice(t, db, "sclatest-"+suffix, "Ubuntu 24.04")
		if err := db.AddDeviceToGroup(ctx, dev, group.ID); err != nil {
			t.Fatalf("AddDeviceToGroup: %v", err)
		}

		mustSaveResult(t, db, policyID, dev, 1) // старый: упал
		mustSaveResult(t, db, policyID, dev, 0) // новый: починили

		results, err := db.ListScriptResultsByPolicy(ctx, policyID, 10)
		if err != nil {
			t.Fatalf("ListScriptResultsByPolicy: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("сохранено %d результатов, want 2", len(results))
		}
		if !results[0].CreatedAt.After(results[1].CreatedAt) {
			t.Fatalf("created_at не различил прогоны (%v vs %v) — DISTINCT ON выбрал бы строку наугад",
				results[0].CreatedAt, results[1].CreatedAt)
		}
		if results[0].ExitCode != 0 {
			t.Fatalf("самый свежий результат имеет exit_code %d, ожидали 0", results[0].ExitCode)
		}

		got := scriptCompliance(t, db, policyID)
		if got.InScope != 1 || got.Pass != 1 || got.Fail != 0 || got.Unknown != 0 {
			t.Errorf("compliance = %+v, want {in_scope:1 pass:1 fail:0 unknown:0}", got)
		}
	})

	// Не назначенная никуда политика: все нули, а не отрицательный Unknown.
	t.Run("не назначенная политика даёт нули", func(t *testing.T) {
		policyID := mustScriptPolicy(t, db, uniq(t))
		got := scriptCompliance(t, db, policyID)
		if got.InScope != 0 || got.Pass != 0 || got.Fail != 0 || got.Unknown != 0 {
			t.Errorf("compliance = %+v, want все нули", got)
		}
	})

	// Устройство отчиталось и потом выпало из группы: авторитетен in_scope, поэтому его
	// результат не должен попадать в pass/fail — иначе Unknown уходит в минус.
	t.Run("результат вне области действия не учитывается", func(t *testing.T) {
		suffix := uniq(t)
		policyID := mustScriptPolicy(t, db, suffix)
		dev := activeDevice(t, db, "scorphan-"+suffix, "Ubuntu 24.04")
		mustSaveResult(t, db, policyID, dev, 0)

		got := scriptCompliance(t, db, policyID)
		if got.InScope != 0 || got.Pass != 0 || got.Fail != 0 || got.Unknown != 0 {
			t.Errorf("compliance = %+v, want все нули", got)
		}
	})
}
