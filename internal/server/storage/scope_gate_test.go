package storage_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Гейт соответствия «класс таблицы ↔ способ обращения». Разбирает КАЖДЫЙ запрос в
// internal/ и cmd/, достаёт из SQL имена таблиц и сверяет с классификацией
// internal/server/tenancy.
//
// 🔴 Зачем статика, когда есть тип. TenantScope делает невозможным ТИХИЙ уход запроса
// мимо скоупа: непривязанный контекст теперь отдаёт ErrTenantScopeMissing вместо нуля
// строк. Но сам по себе тип не мешает написать db.pool.Exec(...) по тенантской таблице —
// это по-прежнему компилируется и по-прежнему молчит. Ровно этот шаг и проверяется здесь.
//
// Почему не forbidigo/ruleguard, как обсуждали: линтер умеет запрещать конструкцию по
// пути файла, а весь риск живёт внутри пакета storage, где прямой db.pool законен и
// нужен (машинерия скоупа, SECURITY DEFINER-резолв до тенанта, глобальные таблицы).
// Исключив storage, линтер стал бы зелёным ровно там, где нужен, — то есть гейтом на
// бумаге. Решение принимается по ТАБЛИЦЕ, а не по пути, поэтому и проверка по таблице.
//
// Что гейт НЕ ловит и не может: динамически собранный SQL (запрос лежит в переменной) —
// таких мест два десятка, все они идут через TenantScope, а скоуп безопасен для любой
// таблицы. Опасное направление (тенантская таблица мимо скоупа) требует явного db.pool
// или своей транзакции, и оба ловятся.

// tableRe — имена таблиц из SQL: FROM/JOIN/INTO/UPDATE/DELETE FROM. Промахи (CTE, алиасы,
// SET) безвредны: значение имеет только совпадение с ИЗВЕСТНОЙ тенантской таблицей.
var tableRe = regexp.MustCompile(`(?is)\b(?:from|join|into|update|delete\s+from)\s+([a-z_][a-z0-9_]*)`)

// Списка исключений здесь намеренно НЕТ. Своя транзакция (db.Pool().Begin) законна ровно
// до тех пор, пока в ней нет тенантских таблиц, и это проверяется по самим таблицам —
// поимённое разрешение функции давало бы ей карт-бланш на всё, что в неё допишут потом.
// Проверено подсадкой: запрос к alerts внутри UpsertCVE обязан валить гейт.

type querySite struct {
	file, fn string
	line     int
	accessor string // "scoped" | "pool" | "rawtx" | "other"
	tables   []string
}

func TestRLSTablesReachedOnlyThroughScope(t *testing.T) {
	root := moduleRoot(t)
	sites := collectQuerySites(t, root)
	if len(sites) < 150 {
		t.Fatalf("найдено всего %d запросов — сломался разбор, а не код", len(sites))
	}

	var bad []string
	for _, s := range sites {
		scoped := scopedTables(s.tables)
		if len(scoped) == 0 {
			continue
		}
		switch s.accessor {
		case "pool":
			bad = append(bad, formatViolation(s, scoped,
				"прямой db.pool: соединение из пула не знает тенанта, под FORCE RLS это ноль строк молча"))
		case "rawtx":
			bad = append(bad, formatViolation(s, scoped,
				"своя транзакция (Pool().Begin) — в ней routineops.tenant_id не выставлен"))
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("тенантская таблица достаётся мимо скоупа (%d):\n  %s\n\n"+
			"Правильный путь — db.Scoped(ctx) под открытым BindTenant. Если скоуп открыть "+
			"неоткуда, функция обязана связать тенанта сама (BindTenantForDevice/ForTask) "+
			"или получить его параметром.",
			len(bad), strings.Join(bad, "\n  "))
	}

}

// scopedTables — только те имена, которые tenancy знает как тенантские.
func scopedTables(names []string) []string {
	var out []string
	for _, n := range names {
		if tenancy.Scoped(n) {
			out = append(out, n)
		}
	}
	return out
}

func formatViolation(s querySite, scoped []string, why string) string {
	return s.file + ":" + strconv.Itoa(s.line) + " " + s.fn + " → " + strings.Join(scoped, ",") + " — " + why
}

func collectQuerySites(t *testing.T, root string) []querySite {
	t.Helper()
	var sites []querySite
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("разбор %s: %v", path, perr)
			}
			rel, _ := filepath.Rel(root, path)
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				rawTx := opensRawTx(fn)
				ast.Inspect(fn, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch sel.Sel.Name {
					case "Query", "QueryRow", "Exec", "SendBatch", "CopyFrom":
					default:
						return true
					}
					acc := accessorOf(sel.X, rawTx)
					if acc == "" {
						return true
					}
					sites = append(sites, querySite{
						file: rel, fn: fn.Name.Name, line: fset.Position(call.Pos()).Line,
						accessor: acc, tables: tablesIn(call.Args),
					})
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("обход %s: %v", dir, err)
		}
	}
	return sites
}

// accessorOf — чем сделан запрос. rawTx=true означает, что функция сама открыла
// транзакцию мимо BindTenant, и любая переменная-транзакция в ней ведёт туда же.
func accessorOf(x ast.Expr, rawTx bool) string {
	switch v := x.(type) {
	case *ast.CallExpr:
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Scoped" {
			return "scoped"
		}
	case *ast.SelectorExpr:
		if v.Sel.Name == "pool" {
			return "pool"
		}
	case *ast.Ident:
		// Переменная: либо результат Scoped(...) (q := db.Scoped(ctx)), либо транзакция.
		// Различаем по тому, открывала ли функция транзакцию сама.
		if rawTx {
			return "rawtx"
		}
		return "other"
	}
	return ""
}

// opensRawTx — функция берёт транзакцию у пула напрямую (db.Pool().Begin / db.pool.Begin),
// то есть без set_config тенанта.
func opensRawTx(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Begin" {
			return true
		}
		switch inner := sel.X.(type) {
		case *ast.CallExpr: // db.Pool().Begin(...)
			if s2, ok := inner.Fun.(*ast.SelectorExpr); ok && s2.Sel.Name == "Pool" {
				found = true
			}
		case *ast.SelectorExpr: // db.pool.Begin(...)
			if inner.Sel.Name == "pool" {
				found = true
			}
		}
		return true
	})
	return found
}

func tablesIn(args []ast.Expr) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range args {
		lit, ok := a.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			continue
		}
		for _, m := range tableRe.FindAllStringSubmatch(s, -1) {
			name := strings.ToLower(m[1])
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// moduleRoot — каталог с go.mod: тест лежит глубоко в дереве, а смотреть должен на всё.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod не найден вверх по дереву")
		}
		dir = parent
	}
}
