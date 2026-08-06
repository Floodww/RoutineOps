package tenancy_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// createTableRe ловит обе формы, встречающиеся в migrations/: с IF NOT EXISTS и без.
// Имя без схемы и кавычек — в проекте таких нет, и появление любой из этих форм
// сознательно уронит парсер, а не молча пропустит таблицу мимо классификации.
var createTableRe = regexp.MustCompile(`(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\(`)

// migrationTables собирает имена всех таблиц из migrations/*.sql.
func migrationTables(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("не читается %s: %v", dir, err)
	}
	found := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("не читается %s: %v", e.Name(), err)
		}
		for _, m := range createTableRe.FindAllStringSubmatch(string(body), -1) {
			// Первое вхождение — файл, где таблица заведена; повторные CREATE TABLE
			// IF NOT EXISTS в более поздних миграциях его не перебивают.
			if _, seen := found[m[1]]; !seen {
				found[m[1]] = e.Name()
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("в migrations/ не найдено ни одной таблицы — сломался парсер, а не схема")
	}
	return found
}

// reparentArrayRe вытаскивает элементы массива таблиц из FOREACH ... IN ARRAY ARRAY[...]
// в теле миграции. Разбор грубый и намеренно такой: массив жёстко зашит в plpgsql, и
// «правильного» способа прочитать его без запущенной БД не существует. Промах парсера
// делает список пустым, а пустой список валит тест — не молча пропускает.
var reparentArrayRe = regexp.MustCompile(`(?s)FOREACH\s+t\s+IN\s+ARRAY\s+ARRAY\[(.*?)\]`)

// tablesInArrays собирает объединение всех массивов таблиц из файла миграции.
func tablesInArrays(t *testing.T, file string) map[string]bool {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", file))
	if err != nil {
		t.Fatalf("не читается %s: %v", file, err)
	}
	out := map[string]bool{}
	for _, m := range reparentArrayRe.FindAllStringSubmatch(string(body), -1) {
		for _, raw := range strings.Split(m[1], ",") {
			name := strings.Trim(strings.TrimSpace(raw), "'")
			if name != "" {
				out[name] = true
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("в %s не найдено ни одного массива таблиц — сломался парсер, а не миграция", file)
	}
	return out
}

// movedByMigrations — где сегодня живут актуальные тела admin_reparent_tenant и
// admin_move_device_tenant.
//
// Тела ПЕРЕСОЗДАЮТСЯ более поздними миграциями (CREATE OR REPLACE), поэтому смотреть надо
// на последнюю версию, а не на ту, где функция появилась. Добавляешь таблицу в массив
// новой миграцией — правь и эти константы, иначе гейт продолжит проверять устаревшее тело
// и зазеленеет на пустом месте.
const (
	reparentTenantFile = "073_screen_control.sql"
	moveDeviceFile     = "073_screen_control.sql"
)

// reparentExempt — тенантские таблицы, которых в массивах переноса НЕТ, и это
// зафиксированное состояние на момент миграции 067, а не разрешение так делать.
//
// Список существует ровно затем, чтобы гейт ловил НОВЫЕ пропуски. Всё, что здесь
// перечислено, унаследовано и относится к серверной зоне: решение по каждой строке —
// за владельцем серверной части, а не за этим тестом.
var reparentExempt = map[string]string{
	"audit_log":     "журнал с хеш-цепочкой на тенанта; перенос строк порвал бы цепочку — вероятно, намеренно",
	"audit_anchors": "якоря той же цепочки, что audit_log",
	"saml_providers": "рядом стоящий oidc_providers в массиве ЕСТЬ, а этот нет — похоже на пропуск, " +
		"вопрос к серверной зоне",
	"siem_integrations":      "заведена позже массива (061), в него не дописана",
	"device_vulnerabilities": "производная от devices, но при переносе устройства не едет — похоже на пропуск",
}

// TestScopedTablesAreReparented — вторая половина гейта тенантности.
//
// TestEveryTableClassified проверяет, что у таблицы ЕСТЬ решение о скоупе. Этого мало:
// классификация живёт в Go, а перенос тенанта и перенос устройства — в жёстко зашитых
// массивах внутри plpgsql, которых Go не видит вовсе. Таблицу можно классифицировать,
// гейт зазеленеет, а строки при переносе тихо останутся в старом тенанте — под RLS они
// станут невидимы, но никуда не денутся (§6 контракта удалёнки).
func TestScopedTablesAreReparented(t *testing.T) {
	reparent := tablesInArrays(t, reparentTenantFile)
	moved := tablesInArrays(t, moveDeviceFile)

	for name, tbl := range tenancy.Tables {
		if tbl.Scope != tenancy.ScopeOwn && tbl.Scope != tenancy.ScopeDerived {
			continue
		}
		if why, ok := reparentExempt[name]; ok {
			if reparent[name] {
				t.Errorf("таблица %s есть в массиве переноса тенанта, но числится исключением (%q) — "+
					"список исключений устарел", name, why)
			}
			continue
		}
		if !reparent[name] {
			t.Errorf("таблица %s тенантская, но НЕ входит в массив admin_reparent_tenant (%s): "+
				"при слиянии тенанта её строки останутся в старом", name, reparentTenantFile)
		}
		// Производные от devices обязаны переезжать и при переносе ОДНОГО устройства.
		if tbl.Scope == tenancy.ScopeDerived && tbl.Parent == "devices" && !moved[name] {
			t.Errorf("таблица %s производна от devices, но НЕ входит в массив "+
				"admin_move_device_tenant (%s): при переносе устройства её строки останутся "+
				"в старом тенанте", name, moveDeviceFile)
		}
	}
}

// TestEveryTableClassified — гейт ретрофита мультитенантности.
//
// Новая таблица в migrations/ без записи в tenancy.Tables роняет этот тест. Это
// единственный способ сделать решение о тенантности обязательным для КАЖДОЙ будущей
// сущности, а не только для тех 25, что разбирались вручную 27.07.2026.
//
// Обратная проверка не менее важна: запись в карте для таблицы, которой в схеме нет,
// означает опечатку или удалённую миграцию — и тогда предикат скоупа где-то
// применяется не к тому, к чему собирались.
func TestEveryTableClassified(t *testing.T) {
	found := migrationTables(t)

	var unclassified []string
	for table, file := range found {
		if _, ok := tenancy.Tables[table]; !ok {
			unclassified = append(unclassified, table+" ("+file+")")
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("таблицы без классификации по тенанту:\n\t%s\n\n"+
			"Добавь запись в internal/server/tenancy/tables.go. Решение обязательно: "+
			"таблица без FK на devices/users НЕ является глобальной по умолчанию — "+
			"отсутствие связи это отсутствие информации. См. docs/multitenancy-contract.md §7.",
			strings.Join(unclassified, "\n\t"))
	}

	var phantom []string
	for table := range tenancy.Tables {
		if _, ok := found[table]; !ok {
			phantom = append(phantom, table)
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("классифицированы таблицы, которых нет в migrations/: %s", strings.Join(phantom, ", "))
	}
}

// TestClassificationConsistent проверяет внутреннюю согласованность карты: чтобы
// нельзя было объявить производную таблицу без родителя, назначить родителем
// глобальную таблицу (тенанта не с чего выводить) или оставить глобальную запись
// без объяснения, почему изоляции нет.
func TestClassificationConsistent(t *testing.T) {
	for name, tbl := range tenancy.Tables {
		switch tbl.Scope {
		case tenancy.ScopeDerived:
			if tbl.Parent == "" {
				t.Errorf("%s: derived без Parent — не с чего выводить тенант", name)
				continue
			}
			parent, ok := tenancy.Tables[tbl.Parent]
			if !ok {
				t.Errorf("%s: Parent=%q не классифицирован", name, tbl.Parent)
				continue
			}
			if parent.Scope != tenancy.ScopeOwn && parent.Scope != tenancy.ScopeDerived {
				t.Errorf("%s: Parent=%q имеет scope %q — у глобальной таблицы нет тенанта, "+
					"выводить не из чего", name, tbl.Parent, parent.Scope)
			}
		case tenancy.ScopeOwn:
			if tbl.Parent != "" {
				t.Errorf("%s: own с Parent=%q — собственная колонка не выводится из родителя", name, tbl.Parent)
			}
		case tenancy.ScopeGlobal, tenancy.ScopeMixed:
			if tbl.Parent != "" {
				t.Errorf("%s: scope %q с Parent=%q", name, tbl.Scope, tbl.Parent)
			}
			if strings.TrimSpace(tbl.Why) == "" {
				t.Errorf("%s: scope %q без Why — отсутствие изоляции обязано быть объяснено", name, tbl.Scope)
			}
		default:
			t.Errorf("%s: неизвестный scope %q", name, tbl.Scope)
		}
	}
}

// TestNoParentCycles ловит цикл в цепочке производных таблиц: он означал бы, что
// тенант выводится сам из себя и не резолвится ни для одной строки цепочки.
func TestNoParentCycles(t *testing.T) {
	for name := range tenancy.Tables {
		seen := map[string]bool{name: true}
		cur := name
		for {
			tbl, ok := tenancy.Tables[cur]
			if !ok || tbl.Scope != tenancy.ScopeDerived {
				break
			}
			cur = tbl.Parent
			if seen[cur] {
				t.Errorf("%s: цикл в цепочке Parent (повтор на %q)", name, cur)
				break
			}
			seen[cur] = true
		}
	}
}

// TestScoped фиксирует поведение хелпера, по которому будущий гард решает, нужен ли
// запросу тенантный предикат. Незнакомая таблица — false: гард не должен требовать
// скоуп там, где решение ещё не принято, иначе TestEveryTableClassified теряет смысл
// как единственная точка отказа.
func TestScoped(t *testing.T) {
	cases := []struct {
		table string
		want  bool
	}{
		{"devices", true},
		{"alerts", true},
		{"software_policy_rules", true},
		{"tenants", false},
		{"agent_releases", false},
		{"revoked_fingerprints", false},
		{"token_blocklist", false},
		{"system_settings", false},
		{"no_such_table", false},
	}
	for _, c := range cases {
		if got := tenancy.Scoped(c.table); got != c.want {
			t.Errorf("Scoped(%q) = %v, want %v", c.table, got, c.want)
		}
	}
}
