package tenancy_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Гейт адресности уведомлений: ни одна рассылка не имеет права уйти с контекстом,
// который не несёт тенанта.
//
// 🔴 Зачем статика, когда рассылка уже fail-closed. Bot.inTenant отказывает
// непривязанному контексту, и это ловит УТЕЧКУ — чужие администраторы уведомление
// больше не получат. Но само по себе это не мешает написать
// `NotifyAlert(context.Background(), …)` в новом хендлере: код скомпилируется,
// пройдёт ревью и будет молча НЕ слать уведомление вообще. Тишина в канале, где
// раньше был алерт безопасности, — отказ дороже утечки, и ловить его надо здесь, а
// не в поле.
//
// Проверяется ровно первый аргумент вызова: `context.Background()` и
// `context.TODO()` запрещены, всё остальное (ctx запроса, storage.DetachTenant(ctx),
// storage.WithTenantID(...)) разрешено. Гейт не доказывает, что переданный контекст
// действительно привязан, — это доказывают тесты рассылки в internal/server/notifier.
// Он закрывает единственный способ обойти их, не сломав ни одного.
//
// Тесты пропускаются намеренно: MockNotifier в тестах шлёт куда угодно, и требовать
// от него скоуп значит проверять заглушку.

// notifyMethods — методы, у которых первый аргумент обязан нести тенанта.
var notifyMethods = map[string]bool{
	"NotifyAlert":    true,
	"NotifyITAdmins": true,
}

// minNotifySites — нижняя граница числа найденных вызовов.
//
// Без неё сломанный разбор (переименовали метод, съехал путь, поменялась форма
// вызова) давал бы зелёный гейт на нуле проверенных мест — то есть ровно ту
// «зелень на бумаге», ради которой гейт и написан. На 05.08.2026 вызовов десять.
const minNotifySites = 10

type notifySite struct {
	file string
	line int
	name string
	arg  string
}

func TestNotificationsCarryTenant(t *testing.T) {
	root := repoRoot(t)
	sites := collectNotifySites(t, root)

	if len(sites) < minNotifySites {
		t.Fatalf("найдено всего %d вызовов рассылки (ожидалось не меньше %d) — сломался разбор, а не код",
			len(sites), minNotifySites)
	}

	for _, s := range sites {
		if s.arg == "context.Background()" || s.arg == "context.TODO()" {
			t.Errorf("%s:%d: %s(%s, …) — рассылка уйдёт без тенанта и потому не уйдёт вовсе; "+
				"перенеси тенанта из контекста запроса через storage.DetachTenant(ctx)",
				s.file, s.line, s.name, s.arg)
		}
	}
}

// collectNotifySites разбирает non-test .go под internal/ и cmd/ и достаёт вызовы
// методов рассылки вместе с текстом первого аргумента.
func collectNotifySites(t *testing.T, root string) []notifySite {
	t.Helper()
	var sites []notifySite
	fset := token.NewFileSet()

	for _, sub := range []string{"internal", "cmd"} {
		dir := filepath.Join(root, sub)
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "testdata" {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// Файлы под build-тегами разбираются тоже: enterprise-хендлеры шлют
			// уведомления ровно так же, а обычный `go test` их не компилирует —
			// то есть без этого гейт был бы слеп именно к платной половине.
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("разбор %s: %v", path, perr)
			}
			rel, _ := filepath.Rel(root, path)
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !notifyMethods[sel.Sel.Name] || len(call.Args) == 0 {
					return true
				}
				sites = append(sites, notifySite{
					file: rel,
					line: fset.Position(call.Lparen).Line,
					name: sel.Sel.Name,
					arg:  exprText(call.Args[0]),
				})
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("обход %s: %v", dir, err)
		}
	}
	return sites
}

// exprText — текст выражения в форме, достаточной для сравнения с
// context.Background()/context.TODO(). Всё, что сложнее, отдаётся как есть и гейтом
// не запрещается.
func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprText(v.Fun) + "()"
	default:
		return "?"
	}
}

func repoRoot(t *testing.T) string {
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
