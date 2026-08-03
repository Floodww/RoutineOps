#!/bin/bash
# CI-guard спецификации HTTP API (docs/openapi.yaml). Падает, если:
#  1) YAML не разбирается;
#  2) какой-то $ref не резолвится внутри документа;
#  3) множество (метод, путь) в спецификации разошлось с маршрутами в коде.
#
# Пункт 3 — главный. Спецификация написана руками, и единственный её реальный
# риск — тихо разойтись с реальностью: добавили эндпоинт, забыли описать.
# Гард ловит расхождение в ОБЕ стороны, включая описанные, но удалённые ручки.
#
# Гард намеренно НЕ проверяет тела запросов и ответов: сверять схемы с Go-типами
# без генератора — это и есть генератор, только хуже. Расхождение по полям ловится
# ревью, расхождение по эндпоинтам — здесь.
#
# Open-core: маршруты Enterprise объявлены не в handler.go, а в своих пакетах под
# //go:build enterprise (escrow, license) и монтируются RouterOption'ами. Гард
# подхватывает такие файлы по build-тегу. Во Free-срезе их нет вообще — тогда пути,
# помеченные в спецификации `x-enterprise: true`, пропускаются с явной строкой в логе.
# Публичная спецификация описывает и ручки Enterprise (как и docs/rbac-matrix.md) —
# читатель должен видеть, что возможность существует, а не гадать.
#
# Read-only, зависимости: python3 + PyYAML. Запуск из любого cwd:
#   bash scripts/check-openapi.sh
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

python3 - "$ROOT" <<'PY'
import re, sys, os

root = sys.argv[1]
spec_path = os.path.join(root, "docs", "openapi.yaml")
src_path = os.path.join(root, "internal", "server", "api", "handler.go")

try:
    import yaml
except ImportError:
    # Fail-closed. Раньше здесь стоял sys.exit(0): при отсутствии PyYAML CI-шаг
    # «guards» проходил ЗЕЛЁНЫМ на заведомо сломанной спецификации — проверено
    # живьём (одна и та же битая спека: с PyYAML EXIT=1, без него EXIT=0). Гард
    # держался на том, что образ ubuntu-latest СЛУЧАЙНО комплектуется python3-yaml;
    # любой setup-python или смена образа тихо превращали его в no-op навсегда.
    print("ОШИБКА: PyYAML не установлен — проверка спецификации НЕ выполнена.", file=sys.stderr)
    print("  Установить:    python3 -m pip install --user PyYAML", file=sys.stderr)
    print("  Debian/Ubuntu: sudo apt-get install -y python3-yaml", file=sys.stderr)
    if os.environ.get("OPENAPI_GUARD_SKIP") == "1":
        # Осознанный опт-аут для внешнего контрибьютора Free-среза: пропуск должен
        # быть ДЕЙСТВИЕМ человека, а не поведением по умолчанию.
        print("ПРОПУСК по OPENAPI_GUARD_SKIP=1", file=sys.stderr)
        sys.exit(0)
    sys.exit(1)

try:
    spec = yaml.safe_load(open(spec_path, encoding="utf-8"))
except Exception as e:
    print(f"ОШИБКА: {spec_path} не разбирается как YAML: {e}")
    sys.exit(1)

fail = 0

# ── 1. $ref резолвятся ────────────────────────────────────────────────────
broken = []
def walk(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str) and v.startswith("#/"):
                cur = spec
                for part in v[2:].split("/"):
                    if not isinstance(cur, dict) or part not in cur:
                        broken.append(v)
                        break
                    cur = cur[part]
            else:
                walk(v)
    elif isinstance(node, list):
        for v in node:
            walk(v)
walk(spec)

print("== 1. $ref резолвятся ==")
if broken:
    fail = 1
    for r in sorted(set(broken)):
        print(f"  БИТЫЙ $ref: {r}")
else:
    print("  OK: все ссылки на месте")

# ── 2. набор эндпоинтов совпадает с кодом ─────────────────────────────────
METHODS = ("get", "post", "put", "patch", "delete")

spec_ops = {
    f"{m.upper()} {path}"
    for path, item in (spec.get("paths") or {}).items()
    for m in item
    if m in METHODS
}

# Ручки Enterprise помечены в спецификации `x-enterprise: true` на уровне пути. Их код
# лежит под //go:build enterprise, и во Free-срезе его физически нет — см. ниже.
ent_ops = {
    f"{m.upper()} {path}"
    for path, item in (spec.get("paths") or {}).items()
    if item.get("x-enterprise")
    for m in item
    if m in METHODS
}

# ── Разбор маршрутов ──────────────────────────────────────────────────────
#
# 🔴 Раньше маршруты вынимались одним регекспом по ПЛОСКОМУ тексту, и у этого было
# два молчаливых провала, из-за которых гард годами зеленел на разошедшейся спеке:
#
#   1) Вложенный r.Route("/oidc", func(r chi.Router){ r.Get("/providers", …) })
#      давал путь «/api/v1/providers» — то есть НЕ ТОТ, что в спецификации. Такая
#      ручка не находилась ни как описанная, ни как лишняя: она просто жила своей
#      жизнью под выдуманным именем.
#   2) Сканировались только handler.go и файлы под //go:build enterprise. Швы вроде
#      oidc_seam.go — обычный файл открытого пакета, регистрирующий роуты
#      RouterOption'ом, — не попадали НИ В ОДНУ категорию, и все ручки /oidc/* были
#      для гарда невидимы целиком.
#
# Поэтому здесь настоящий разбор с учётом вложенности: сканер идёт по тексту,
# пропускает строки и комментарии, считает фигурные скобки и держит стек префиксов
# r.Route(...). А файлы отбираются по признаку «импортирует chi и регистрирует
# маршрут», а не по списку имён, который надо помнить.

ROUTE_GROUP = re.compile(r'\.Route\(\s*"([^"]*)"')
ROUTE_CALL = re.compile(r'\.(Get|Post|Put|Patch|Delete|Head|Options)\(\s*"([^"]*)"')
METHOD_CALL = re.compile(
    r'\.Method(?:Func)?\(\s*(?:http\.Method([A-Za-z]+)|"([A-Za-z]+)")\s*,\s*"([^"]*)"'
)
# r.Handle/r.HandleFunc/r.Mount HTTP-метод не называют — сопоставить их со
# спецификацией принципиально нельзя. Молчаливый пропуск здесь = ручка проезжает мимо
# гарда, поэтому всё, что не статика, — жёсткая ошибка с файлом и строкой.
OPAQUE_CALL = re.compile(r'\.(Handle|HandleFunc|Mount)\(\s*"([^"]*)"')
STATIC_PREFIXES = ("/*", "/downloads")

IDENT_TAIL = re.compile(r'[A-Za-z0-9_]$')

def is_router_call(text, dot):
    """Правда ли, что вызов в позиции dot сделан НА РОУТЕРЕ, а не на чём попало.

    🔴 Без этой проверки под шаблон `.Get("…")` попадает `r.URL.Query().Get("arch")`
    и `req.Header.Get("…")` — то есть гард начинает считать имена query-параметров
    маршрутами и требовать описать «GET /api/v1arch». Мусор в выводе гарда хуже,
    чем его отсутствие: его перестают читать.

    Принимаются две формы:
      r.Get(…)            — получатель это одиночный идентификатор;
      r.With(…).Get(…)    — цепочка через With, штатная в этом проекте.
    Всё, что стоит после закрывающей скобки ЛЮБОГО другого вызова, отвергается.
    """
    j = dot - 1
    while j >= 0 and text[j] in " \t\r\n":
        j -= 1
    if j < 0:
        return False
    if text[j] == ")":
        # Цепочка вызовов: принимаем только .With(...) — на нём в chi и строятся
        # маршруты с миддлварами.
        level, k = 0, j
        while k >= 0:
            if text[k] == ")":
                level += 1
            elif text[k] == "(":
                level -= 1
                if level == 0:
                    break
            k -= 1
        if k < 0:
            return False
        e = k - 1
        while e >= 0 and IDENT_TAIL.match(text[e]):
            e -= 1
        return text[e + 1:k] == "With"
    if not IDENT_TAIL.match(text[j]):
        return False
    e = j
    while e >= 0 and IDENT_TAIL.match(text[e]):
        e -= 1
    # Получатель — часть более длинной цепочки (req.Header.Get): не роутер.
    return not (e >= 0 and text[e] == ".")

def join_path(prefixes, path):
    joined = "".join(prefixes) + path
    joined = re.sub(r'/{2,}', '/', joined)
    if len(joined) > 1 and joined.endswith("/"):
        joined = joined[:-1]
    return joined or "/"

def scan_routes(text):
    """Возвращает (ops, opaque): ops — [(METHOD, path, line)], opaque — [(call, path, line)]."""
    ops, opaque = [], []
    stack = []      # [(prefix, depth)] — префиксы активных r.Route
    pending = None  # префикс, ждущий своей '{'
    depth = 0
    i, n = 0, len(text)
    line = 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1; i += 1; continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            seg = text[i:(n if j < 0 else j + 2)]
            line += seg.count("\n")
            i = n if j < 0 else j + 2
            continue
        if c == "`":
            j = text.find("`", i + 1)
            seg = text[i:(n if j < 0 else j + 1)]
            line += seg.count("\n")
            i = n if j < 0 else j + 1
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2; continue
                if text[j] == '"':
                    break
                j += 1
            i = j + 1
            continue
        if c == "{":
            depth += 1
            if pending is not None:
                stack.append((pending, depth)); pending = None
            i += 1; continue
        if c == "}":
            while stack and stack[-1][1] == depth:
                stack.pop()
            depth -= 1; i += 1; continue
        if c == ".":
            m = ROUTE_GROUP.match(text, i)
            if m and is_router_call(text, i):
                pending = m.group(1); i = m.end(); continue
            m = METHOD_CALL.match(text, i)
            if m and is_router_call(text, i):
                meth = (m.group(1) or m.group(2)).upper()
                ops.append((meth, join_path([p for p, _ in stack], m.group(3)), line))
                i = m.end(); continue
            m = ROUTE_CALL.match(text, i)
            if m and is_router_call(text, i):
                ops.append((m.group(1).upper(), join_path([p for p, _ in stack], m.group(2)), line))
                i = m.end(); continue
            m = OPAQUE_CALL.match(text, i)
            if m and is_router_call(text, i):
                opaque.append((m.group(1), join_path([p for p, _ in stack], m.group(2)), line))
                i = m.end(); continue
        i += 1
    return ops, opaque

SKIP_DIRS = {".git", "node_modules", "web", "build", "vendor", "releases", "docs"}

# Go разрешает комментарии и пустые строки ПЕРЕД //go:build (лицензионная шапка), а сам
# тег бывает составным (`linux && enterprise`). Прежний startswith() ни того, ни другого
# не видел: одна шапка над build-тегом — и ПОЛНОЕ дерево объявлялось «Free-срезом», после
# чего реально неописанная enterprise-ручка пропускалась по маркеру x-enterprise.
# Семантика ровно как в export-free.sh, шаг 2.
BUILD_LINE = re.compile(r'^//go:build[ \t]+(.+)$', re.M)
def has_enterprise_tag(text):
    head = text.split("\npackage ", 1)[0]
    m = BUILD_LINE.search(head)
    return bool(m) and re.search(r'(^|[^!])\benterprise\b', m.group(1))

# Файл интересен, если он импортирует chi И регистрирует хотя бы один маршрут.
# Признак, а не список имён: список пришлось бы помнить при каждом новом шве, а
# забытый файл выглядел бы как «ручек нет».
CHI_IMPORT = re.compile(r'"github\.com/go-chi/chi/v\d+(?:/\w+)?"')

route_files, ent_files = [], []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in sorted(filenames):
        if not fn.endswith(".go") or fn.endswith("_test.go"):
            continue
        p = os.path.join(dirpath, fn)
        try:
            text = open(p, encoding="utf-8").read()
        except OSError:
            continue
        if not CHI_IMPORT.search(text):
            continue
        ops, opaque_hits = scan_routes(text)
        if not ops and not opaque_hits:
            continue
        route_files.append(p)
        if has_enterprise_tag(text):
            ent_files.append(p)

if not route_files:
    print("ОШИБКА: не найдено ни одного файла с маршрутами — гард проверял бы пустоту.")
    sys.exit(1)

code_ops = set()
opaque = []
for path_ in route_files:
    text = open(path_, encoding="utf-8").read()
    ops, opaque_hits = scan_routes(text)
    rel = os.path.relpath(path_, root)
    for call, path, line in opaque_hits:
        if path.startswith(STATIC_PREFIXES):
            continue  # статика SPA и файловая раздача — не API
        opaque.append(f'{rel}:{line}: r.{call}("{path}")')
    for meth, path, _ in ops:
        if path.startswith(STATIC_PREFIXES):
            continue
        # Роуты внутри r.Route("/api/v1", …) объявлены без префикса, и enterprise-опции
        # монтируются в ту же группу из своих пакетов — там префикса нет лексически.
        if not path.startswith("/api/v1") and path not in ("/healthz", "/ca.crt"):
            path = "/api/v1" + path
        code_ops.add(f"{meth} {path}")

missing = sorted(code_ops - spec_ops)   # есть в коде, не описано
extra = sorted(spec_ops - code_ops)     # описано, но в коде нет

# Во Free-срезе enterprise-исходников нет вообще — тогда помеченные ручки пропускаем.
# Именно «нет вообще»: если хоть один enterprise-файл на месте, мы в полном дереве, и
# отсутствие описанной ручки снова становится ошибкой, а не поблажкой по маркеру.
skipped = []
if not ent_files:
    skipped = [x for x in extra if x in ent_ops]
    extra = [x for x in extra if x not in ent_ops]

print(f"== 2. эндпоинты: в коде {len(code_ops)}, в спецификации {len(spec_ops)} ==")
if skipped:
    # Громко, а не молча: пропуск — это заявление «мы в срезе», и оно должно быть
    # видно в логе CI, иначе маркером x-enterprise можно спрятать реальное расхождение.
    print(f"  Free-срез (enterprise-исходников нет): пропущено ручек Enterprise — {len(skipped)}")
    for x in sorted(skipped):
        print(f"    ~ {x}")
if opaque:
    fail = 1
    print("  МАРШРУТ БЕЗ ЯВНОГО HTTP-МЕТОДА — гард не может сверить его со спецификацией.")
    print("  Перерегистрируйте через r.Get/r.Post/... или r.Method(http.MethodX, ...):")
    for x in opaque:
        print(f"    {x}")
if missing:
    fail = 1
    print("  НЕ ОПИСАНО в docs/openapi.yaml:")
    for x in missing:
        print(f"    {x}")
if extra:
    fail = 1
    print("  ОПИСАНО, но в коде отсутствует (удалили ручку — уберите из спецификации;")
    print("  ручка Enterprise — пометьте путь `x-enterprise: true`):")
    for x in extra:
        print(f"    {x}")
if not missing and not extra:
    print("  OK: расхождений нет")

print()
if fail:
    print("OPENAPI: FAIL — спецификация разошлась с кодом ❌")
    sys.exit(1)
print("OPENAPI: PASS — спецификация соответствует маршрутам ✅")
PY
