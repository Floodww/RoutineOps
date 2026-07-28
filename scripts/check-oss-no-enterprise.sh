#!/bin/sh
# CI-guard от утечки enterprise-кода в open-core (free) сборку. Падает, если:
#  1) free-граф зависимостей содержит canary-либы enterprise-фич (filippo.io/age — escrow;
#     github.com/go-ldap/ldap — каталог): каждая тянется ровно одним enterprise-пакетом,
#     её наличие во free = фича затянута в open-core;
#  2) free-сборка сервера/агента импортирует enterprise-пакеты
#     (crypto/escrow/filevault/shamir/directory).
#
# Запуск (open-core CI, без -tags enterprise):
#   sh scripts/check-oss-no-enterprise.sh
set -e

fail=0

# Транзитивное замыкание зависимостей ШИПАЕМЫХ free-бинарей (сервер + агент). НЕ
# `./internal/...` — там enterprise-пакеты существуют как пустые free-заглушки
# (doc_free.go) и попали бы в листинг, хотя ничем free не ИМПОРТИРУЮТСЯ.
# Перечислять обязаны ВСЕ шипаемые open-core-бинари, а не только сервер с агентом.
# cmd/routineops — CLI управления парком (`make cli` -> bin/routineops, документирован
# в docs/config-as-code.md), cmd/routineops-license и cmd/routineops-unseal имеют
# free-варианты (main_free.go под //go:build !enterprise). Все они уезжают в срез
# как есть. Пропущенный здесь бинарь — это дыра, через которую age или enterprise-пакет
# проезжает под зелёное «open-core чист ✅»: проверено подсадкой в cmd/routineops.
FREE_CMDS="./cmd/server ./cmd/agent ./cmd/routineops ./cmd/routineops-license ./cmd/routineops-unseal"

# stderr НЕ гасим. Утечка enterprise-пакета БЕЗ free-заглушки (escrow, directory,
# uninstall) роняет сам `go list` («build constraints exclude all Go files»), а не
# попадает в граф. С прежним 2>/dev/null под set -e гард выходил кодом 1, не напечатав
# ни байта: оператор видел пустой экран, а проверки ниже не исполнялись вовсе — то есть
# для этих пакетов пункт 2 был мёртвым кодом.
ERRLOG=$(mktemp -t leakguard-golist.XXXXXX.log)
trap 'rm -f "$ERRLOG"' EXIT INT TERM
# shellcheck disable=SC2086 — FREE_CMDS намеренно разворачивается в список пакетов.
if ! BINDEPS=$(go list -deps $FREE_CMDS 2>"$ERRLOG"); then
  echo "LEAK-GUARD: НЕ ВЫПОЛНЕН — go list -deps упал, граф зависимостей не построен." >&2
  echo "  (частая причина: free-код импортирует enterprise-пакет без free-заглушки," >&2
  echo "   напр. internal/server/escrow, internal/server/directory, internal/server/uninstall)" >&2
  sed 's/^/  go list: /' "$ERRLOG" >&2
  exit 1
fi
if [ -z "$BINDEPS" ]; then
  echo "LEAK-GUARD: НЕ ВЫПОЛНЕН — go list -deps вернул пустой граф зависимостей." >&2
  exit 1
fi

echo "== 1. canary-либы enterprise-фич не в free-графе (age → escrow, go-ldap → каталог) =="
if printf '%s\n' "$BINDEPS" | grep -Eq '^(filippo.io/age|github.com/go-ldap/ldap)'; then
  echo "  ОШИБКА: canary-либа enterprise-фичи в графе open-core-бинарей — фича затянута в free!" >&2
  printf '%s\n' "$BINDEPS" | grep -E '^(filippo.io/age|github.com/go-ldap/ldap)' >&2
  fail=1
else
  echo "  OK: age и go-ldap отсутствуют в open-core"
fi

echo "== 2. enterprise-пакеты не импортируются free-бинарями =="
# Список обязан совпадать с набором пакетов-библиотек под //go:build enterprise.
# internal/license (весь слой лицензий и энтайтлментов) и internal/server/uninstall
# в нём отсутствовали, а ни одной canary-либы они не тянут — значит их утечка
# не ловилась вообще ничем. Якорь на module path и граница (/|$) — чтобы имя пакета
# не матчилось подстрокой в постороннем пути.
ent='^github\.com/Floodww/RoutineOps/(internal/server/crypto|internal/server/escrow|internal/agent/filevault|internal/offline/shamir|internal/server/directory|internal/license|internal/server/uninstall)(/|$)'
if printf '%s\n' "$BINDEPS" | grep -Eq "$ent"; then
  echo "  ОШИБКА: enterprise-пакет в графе open-core-бинарей:" >&2
  printf '%s\n' "$BINDEPS" | grep -E "$ent" >&2
  fail=1
else
  echo "  OK: enterprise-пакеты не в графе open-core"
fi

if [ "$fail" -ne 0 ]; then
  echo "LEAK-GUARD: enterprise-код просочился в open-core-сборку." >&2
  exit 1
fi
echo "LEAK-GUARD: open-core чист от enterprise ✅"
