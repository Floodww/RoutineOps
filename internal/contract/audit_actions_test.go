package contract

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
)

// Каждый код действия, который умеет прислать СЕРВЕР, обязан иметь подпись в интерфейсе.
//
// 🔴 Гейт заведён потому, что встречное направление уже было закрыто, а это — нет.
// web/src/lib/auditActions.test.ts проверяет, что у кода ИЗ КАРТЫ есть перевод в ru и en.
// Что каждый код, который пишет сервер, попал в карту, не проверял никто — и журнал
// показывал оператору сырые машинные идентификаторы вроде
// screen_session_control_returned. На момент заведения гейта таких нашлось 33.
//
// Чинить переименованием кодов НЕЛЬЗЯ: это идентификаторы, они лежат в строках БД, по ним
// фильтруют и по ним уходит выгрузка в SIEM. Русский текст живёт в словаре, код остаётся
// машинным.
//
// Почему гейт на стороне Go, а не в vitest: источник истины — call site в Go. Список,
// выписанный руками в TypeScript, протухнет на следующей фиче ровно так же, как протух
// нынешний.
func TestEveryServerAuditActionHasLabel(t *testing.T) {
	root := repoRootOrSkip(t)

	codes, unresolved := serverAuditActions(t, root)
	if len(codes) == 0 {
		t.Fatal("в дереве не найдено ни одного кода аудита — извлекатель сломан, а не сервер молчит")
	}

	// 🔴 Нерезолвимый аргумент — это НЕ повод промолчать. Гейт, который тихо пропускает
	// то, чего не понял, отвечает «всё покрыто» на неполном обходе; именно так дыра и
	// прожила до полевого отчёта. Если код действия собирается выражением, его нужно либо
	// сделать литералом, либо (осознанно) добавить в карту руками.
	if len(unresolved) > 0 {
		t.Errorf("код действия не выводится из исходника в %d месте(ах) — гейт не может ручаться за покрытие:\n  %s",
			len(unresolved), strings.Join(unresolved, "\n  "))
	}

	labels := webActionLabels(t, root)
	if len(labels) == 0 {
		t.Fatal("в web/src/lib/auditActions.ts не разобрано ни одного ключа — разборщик сломан")
	}

	var missing []string
	for _, c := range codes {
		if !labels[c] {
			missing = append(missing, c)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("сервер умеет прислать %d код(ов), которых нет в ACTION_LABELS — журнал покажет их сырыми:\n  %s\n"+
			"Добавьте код в web/src/lib/auditActions.ts и подпись в i18n (ru и en). Переименовывать код нельзя: "+
			"по нему фильтруют и он уезжает в SIEM.", len(missing), strings.Join(missing, "\n  "))
	}
}

// Корневые писатели аудита: имя функции → позиция аргумента с кодом действия.
//
// Обёртки над ними НЕ перечисляются руками, а находятся сами (см. discoverWriters):
// список, выписанный вручную, устаревает молча и ровно тем же способом, что и карта
// подписей, ради которой всё это и затевалось.
var auditWriters = map[string]int{
	"WriteAuditLog": 3, // storage.(*DB).WriteAuditLog(ctx, userID, email, action, …)
}

type goFile struct {
	rel  string
	fset *token.FileSet
	ast  *ast.File
}

// serverAuditActions собирает коды из всех call site'ов аудита в дереве.
func serverAuditActions(t *testing.T, root string) (codes []string, unresolved []string) {
	t.Helper()
	files := parseTree(t, root)
	writers := discoverWriters(files)
	seen := map[string]bool{}

	forEachAuditCall(files, writers, func(f *goFile, fn *ast.FuncDecl, call *ast.CallExpr, pos int) {
		where := f.rel + ":" + strconv.Itoa(f.fset.Position(call.Pos()).Line)
		switch a := call.Args[pos].(type) {
		case *ast.BasicLit:
			if a.Kind == token.STRING {
				if v, err := strconv.Unquote(a.Value); err == nil {
					seen[v] = true
					return
				}
			}
			unresolved = append(unresolved, where+" (нестроковый литерал)")
		case *ast.Ident:
			if lits := literalAssignments(fn.Body)[a.Name]; len(lits) > 0 {
				for _, v := range lits {
					seen[v] = true
				}
				return
			}
			// Параметр функции = обёртка; её собственные call site'ы уже разобраны
			// (discoverWriters). Иначе — переменная неизвестного происхождения.
			if paramIndex(fn, a.Name) >= 0 {
				return
			}
			unresolved = append(unresolved, where+" (переменная "+a.Name+" неизвестного происхождения)")
		default:
			unresolved = append(unresolved, where+" (выражение)")
		}
	})

	for c := range seen {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	sort.Strings(unresolved)
	return codes, unresolved
}

// discoverWriters находит ОБЁРТКИ: функция, пробрасывающая свой параметр в код действия
// известного писателя, сама становится писателем с позицией этого параметра.
//
// До неподвижной точки, потому что обёртки бывают в два звена: api.Handler.audit →
// WriteAuditLog, а screen.Service.auditView/auditSecurity и escrow.Service.audit —
// отдельные обёртки в своих пакетах. Без этого их call site'ы (а там как раз лежат
// screen_session_control_granted/returned) в набор не попадают вовсе.
func discoverWriters(files []*goFile) map[string]int {
	writers := map[string]int{}
	for k, v := range auditWriters {
		writers[k] = v
	}
	for changed := true; changed; {
		changed = false
		forEachAuditCall(files, writers, func(f *goFile, fn *ast.FuncDecl, call *ast.CallExpr, pos int) {
			id, ok := call.Args[pos].(*ast.Ident)
			if !ok {
				return
			}
			if i := paramIndex(fn, id.Name); i >= 0 {
				name := fn.Name.Name
				if _, known := writers[name]; !known {
					writers[name] = i
					changed = true
				}
			}
		})
	}
	return writers
}

// forEachAuditCall обходит все вызовы известных писателей во всех файлах.
func forEachAuditCall(files []*goFile, writers map[string]int, visit func(*goFile, *ast.FuncDecl, *ast.CallExpr, int)) {
	for _, f := range files {
		ast.Inspect(f.ast, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					name = fun.Sel.Name
				case *ast.Ident:
					name = fun.Name
				default:
					return true
				}
				pos, ok := writers[name]
				if !ok || len(call.Args) <= pos {
					return true
				}
				visit(f, fn, call, pos)
				return true
			})
			return true
		})
	}
}

// paramIndex — позиция параметра с этим именем в списке аргументов вызова (получатель
// метода в аргументы не входит). -1, если такого параметра нет.
func paramIndex(fn *ast.FuncDecl, name string) int {
	i := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			i++
			continue
		}
		for _, n := range field.Names {
			if n.Name == name {
				return i
			}
			i++
		}
	}
	return -1
}

func parseTree(t *testing.T, root string) []*goFile {
	t.Helper()
	var out []*goFile
	for _, dir := range []string{"internal", "cmd"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue // каталога нет (усечённое дерево) — не повод падать
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			out = append(out, &goFile{rel: rel, fset: fset, ast: f})
			return nil
		})
		if err != nil {
			t.Fatalf("обход %s: %v", base, err)
		}
	}
	return out
}

// literalAssignments собирает строковые литералы, присваиваемые переменным внутри тела
// функции, включая ветвления: `action := "a"; if x { action = "b" }` даёт обе строки.
func literalAssignments(body *ast.BlockStmt) map[string][]string {
	out := map[string][]string{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i := range as.Lhs {
			id, ok := as.Lhs[i].(*ast.Ident)
			if !ok {
				continue
			}
			lit, ok := as.Rhs[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if v, err := strconv.Unquote(lit.Value); err == nil {
				out[id.Name] = append(out[id.Name], v)
			}
		}
		return true
	})
	return out
}

// Ключ может быть и в кавычках: имена с точкой (tenant.create) иначе не записать.
var actionKeyRe = regexp.MustCompile(`(?m)^\s{2}"?([a-zA-Z0-9_.]+)"?:\s*"auditAction\.`)

// webActionLabels разбирает ключи ACTION_LABELS.
func webActionLabels(t *testing.T, root string) map[string]bool {
	t.Helper()
	path := filepath.Join(root, "web", "src", "lib", "auditActions.ts")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("нет %s — сверять не с чем", path)
	}
	out := map[string]bool{}
	for _, m := range actionKeyRe.FindAllStringSubmatch(string(raw), -1) {
		out[m[1]] = true
	}
	return out
}
