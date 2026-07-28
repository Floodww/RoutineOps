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

# r.Get(...), r.With(...).Post(...) — внутренние скобки у With непусты (httprate),
# поэтому допускаем один уровень вложенности вместо нежадного .*?. re.S обязателен:
# gofmt переносит r.With(...) на несколько строк, стоит списку middleware стать длиннее
# строки, и однострочный регексп переставал видеть такой маршрут вообще.
pattern = re.compile(
    r'r\.(?:With\((?:[^()]|\([^()]*\))*\)\.)?'
    r'(Get|Post|Put|Patch|Delete|Head|Options)\(\s*"([^"]+)"',
    re.S,
)
# chi-регистрация готового http.Handler (а не HandlerFunc): r.Method / r.MethodFunc.
# Штатная форма, которой гард не видел вовсе.
method_pattern = re.compile(
    r'r\.Method(?:Func)?\(\s*(?:http\.Method([A-Za-z]+)|"([A-Za-z]+)")\s*,\s*"([^"]+)"'
)
# r.Handle/r.HandleFunc/r.Mount HTTP-метод не называют — сопоставить их со
# спецификацией принципиально нельзя. Молчаливый пропуск здесь = ручка проезжает мимо
# гарда, поэтому всё, что не статика, — жёсткая ошибка с файлом и строкой.
opaque_pattern = re.compile(r'r\.(Handle|HandleFunc|Mount)\(\s*"([^"]+)"')
STATIC_PREFIXES = ("/*", "/downloads")

# Enterprise-роуты монтируются RouterOption'ами из СВОИХ пакетов (escrow, license), а
# не из handler.go — без них гард видел только часть реальности, из-за чего
# /escrow/status и /license годами жили неописанными, а описанный reveal ронял CI Free.
# Ищем их по build-тегу, а не списком путей: список пришлось бы помнить при каждой новой
# ручке, а забытый файл выглядел бы как «ручка не описана».
SKIP_DIRS = {".git", "node_modules", "web", "build", "vendor", "releases"}

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

ent_files = []
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
        if has_enterprise_tag(text) and pattern.search(text):
            ent_files.append(p)

def norm(path):
    # Роуты внутри r.Route("/api/v1", ...) объявлены без префикса.
    if not path.startswith("/api/v1") and path not in ("/healthz", "/ca.crt"):
        return "/api/v1" + path
    return path

code_ops = set()
opaque = []
for path_ in [src_path] + ent_files:
    src = open(path_, encoding="utf-8").read()
    for m in opaque_pattern.finditer(src):
        if m.group(2).startswith(STATIC_PREFIXES):
            continue  # статика SPA и файловая раздача — не API
        line = src.count("\n", 0, m.start()) + 1
        opaque.append(f'{os.path.relpath(path_, root)}:{line}: r.{m.group(1)}("{m.group(2)}")')
    for hm, lm, mpath in method_pattern.findall(src):
        code_ops.add(f"{(hm or lm).upper()} {norm(mpath)}")
    for method, path in pattern.findall(src):
        if path.startswith("/*") or path.startswith("/downloads"):
            continue  # статика SPA и файловая раздача — не API
        # Роуты внутри r.Route("/api/v1", ...) объявлены без префикса. Enterprise-роуты
        # монтируются в ту же группу, поэтому правило одно на всех.
        if not path.startswith("/api/v1") and path not in ("/healthz", "/ca.crt"):
            path = "/api/v1" + path
        code_ops.add(f"{method.upper()} {path}")

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
