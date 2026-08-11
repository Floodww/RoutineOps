#!/usr/bin/env bash
#
# Регрессия из поля (10.08.2026): на enterprise-инсталляции кнопки «Скачать MSI/PKG»
# отдавали OPEN-CORE установщики. update.sh в конце копировал в releases/ трекнутые в git
# артефакты — безусловно, без единой проверки BUILD_TAGS, — а трекнутые ОБЯЗАНЫ быть
# open-core (иначе enterprise-бинарь уехал бы в публичный Free-срез).
#
# Канал self-update при этом был исправен, поэтому дефект не проявлялся ничем: свежая
# машина до первого обновления (до 6 часов) просто жила с агентом, где экран и FileVault
# не выключены, а НЕ СКОМПИЛИРОВАНЫ. Подтверждено на проде сравнением сумм:
# releases/RoutineOps-agent.pkg совпадал с трекнутым build/pkg/RoutineOps-agent.pkg.
#
# Проверяем ОБЕ стороны, иначе гейт был бы зелёным и у скрипта, не делающего ничего:
#   А. enterprise без приватных путей — releases/ НЕ ТРОНУТ (подложенный руками
#      enterprise-пакет переживает выкат);
#   Б. enterprise с путями — копируется именно приватный артефакт;
#   В. open-core — прежнее поведение, трекнутые артефакты копируются;
#   Г. enterprise с НЕСУЩЕСТВУЮЩИМ путём — громкий отказ, а не тихий пропуск.
#
# Запуск: bash scripts/test-update-installer-edition.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO/scripts/publish-installers.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# Каталог деплоя: трекнутые артефакты (всегда open-core), приватный канал и releases/ с
# уже подложенным вручную enterprise-пакетом — ровно то состояние, в котором прод оказался
# после ручной подмены.
setup() {
  rm -rf "$WORK/deploy"
  mkdir -p "$WORK/deploy/build/msi" "$WORK/deploy/build/pkg" \
           "$WORK/deploy/enterprise" "$WORK/deploy/releases" "$WORK/deploy/scripts"
  echo "OPEN-CORE-MSI"   > "$WORK/deploy/build/msi/RoutineOps-agent.msi"
  echo "OPEN-CORE-PKG"   > "$WORK/deploy/build/pkg/RoutineOps-agent.pkg"
  echo "ENTERPRISE-MSI"  > "$WORK/deploy/enterprise/RoutineOps-agent-enterprise.msi"
  echo "ENTERPRISE-PKG"  > "$WORK/deploy/enterprise/RoutineOps-agent-enterprise.pkg"
  echo "PODLOZHENO-RUKAMI" > "$WORK/deploy/releases/RoutineOps-agent.pkg"
  cp "$SCRIPT" "$WORK/deploy/scripts/publish-installers.sh"
}

run() { # <BUILD_TAGS> <ENTERPRISE_MSI> <ENTERPRISE_PKG> [RELEASE_CHANNEL]
  ( cd "$WORK/deploy" && BUILD_TAGS="$1" ENTERPRISE_MSI="$2" ENTERPRISE_PKG="$3" \
      RELEASE_CHANNEL="${4:-stable}" \
      sh scripts/publish-installers.sh > "$WORK/out.txt" 2>&1 )
}

content() { cat "$WORK/deploy/releases/RoutineOps-agent.$1" 2>/dev/null || echo "НЕТ ФАЙЛА"; }

echo "== А. enterprise без приватных путей: releases/ не трогаем =="
setup
run enterprise "" "" || bad "скрипт упал там, где обязан лишь предупредить"
got=$(content pkg)
[ "$got" = "PODLOZHENO-RUKAMI" ] || bad "PKG перезаписан ('$got') — ручная подмена не пережила выкат"
[ "$(content msi)" = "НЕТ ФАЙЛА" ] || bad "MSI подложен open-core там, где файла не было вовсе"
grep -q "НЕ ТРОНУТ" "$WORK/out.txt" || bad "пропуск не назван вслух — оператор решит, что кнопки обновились"

echo "== Б. enterprise с приватными путями: копируется приватный артефакт =="
setup
run enterprise enterprise/RoutineOps-agent-enterprise.msi enterprise/RoutineOps-agent-enterprise.pkg \
  || bad "скрипт упал на корректных путях"
[ "$(content msi)" = "ENTERPRISE-MSI" ] || bad "MSI взят не из приватного канала: '$(content msi)'"
[ "$(content pkg)" = "ENTERPRISE-PKG" ] || bad "PKG взят не из приватного канала: '$(content pkg)'"

echo "== В. open-core: прежнее поведение сохранено =="
setup
run "" "" "" || bad "скрипт упал на open-core инсталляции"
[ "$(content msi)" = "OPEN-CORE-MSI" ] || bad "на open-core MSI не обновлён: '$(content msi)'"
[ "$(content pkg)" = "OPEN-CORE-PKG" ] || bad "на open-core PKG не обновлён: '$(content pkg)'"

echo "== Г. enterprise с несуществующим путём: громкий отказ =="
setup
rc=0
run enterprise enterprise/net-takogo-fajla.msi "" || rc=$?
[ "$rc" -ne 0 ] || bad "опечатка в пути принята молча — оператор уверен, что кнопка обновилась"
[ "$(content pkg)" = "PODLOZHENO-RUKAMI" ] || bad "после отказа PKG всё равно перезаписан"

echo "== Д. канареечный канал: кнопки «Скачать» не трогаем =="
setup
run "" "" "" beta || bad "скрипт упал на канареечной выкатке"
[ "$(content msi)" = "НЕТ ФАЙЛА" ] || bad "beta подложила установщик всем: '$(content msi)'"
[ "$(content pkg)" = "PODLOZHENO-RUKAMI" ] || bad "beta перезаписала releases/: '$(content pkg)'"
grep -q "не трогаем" "$WORK/out.txt" || bad "пропуск по каналу не назван вслух"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "Последний вывод скрипта:"
  cat "$WORK/out.txt"
  exit 1
fi
echo ""
echo "OK: редакция установщиков в releases/ соблюдается на обеих инсталляциях."
