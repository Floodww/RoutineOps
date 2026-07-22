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
    print("ПРОПУСК: PyYAML не установлен — проверка спецификации не выполнена", file=sys.stderr)
    sys.exit(0)

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

src = open(src_path, encoding="utf-8").read()
# r.Get(...), r.With(...).Post(...) — внутренние скобки у With непусты (httprate),
# поэтому нежадный .*? до первого ").".
pattern = re.compile(r'r\.(?:With\(.*?\)\.)?(Get|Post|Put|Patch|Delete)\("([^"]+)"')
code_ops = set()
for method, path in pattern.findall(src):
    if path.startswith("/*") or path.startswith("/downloads"):
        continue  # статика SPA и файловая раздача — не API
    # Роуты внутри r.Route("/api/v1", ...) объявлены без префикса.
    if not path.startswith("/api/v1") and path not in ("/healthz", "/ca.crt"):
        path = "/api/v1" + path
    code_ops.add(f"{method.upper()} {path}")

missing = sorted(code_ops - spec_ops)   # есть в коде, не описано
extra = sorted(spec_ops - code_ops)     # описано, но в коде нет

print(f"== 2. эндпоинты: в коде {len(code_ops)}, в спецификации {len(spec_ops)} ==")
if missing:
    fail = 1
    print("  НЕ ОПИСАНО в docs/openapi.yaml:")
    for x in missing:
        print(f"    {x}")
if extra:
    fail = 1
    print("  ОПИСАНО, но в коде отсутствует (удалили ручку — уберите из спецификации):")
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
