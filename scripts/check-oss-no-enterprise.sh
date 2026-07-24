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
BINDEPS=$(go list -deps ./cmd/server ./cmd/agent 2>/dev/null)

echo "== 1. canary-либы enterprise-фич не в free-графе (age → escrow, go-ldap → каталог) =="
if printf '%s\n' "$BINDEPS" | grep -Eq '^(filippo.io/age|github.com/go-ldap/ldap)'; then
  echo "  ОШИБКА: canary-либа enterprise-фичи в графе open-core-бинарей — фича затянута в free!" >&2
  printf '%s\n' "$BINDEPS" | grep -E '^(filippo.io/age|github.com/go-ldap/ldap)' >&2
  fail=1
else
  echo "  OK: age и go-ldap отсутствуют в open-core"
fi

echo "== 2. enterprise-пакеты не импортируются free-бинарями =="
ent='internal/server/crypto|internal/server/escrow|internal/agent/filevault|internal/offline/shamir|internal/server/directory'
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
