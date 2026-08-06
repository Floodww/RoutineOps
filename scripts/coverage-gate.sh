#!/usr/bin/env bash
# coverage-gate.sh — гейт покрытия: агрегат + пол на пакет.
#
# Вынесен из .github/workflows/ci.yml, потому что джоб теперь два: open-core и
# enterprise. Дублировать двадцать строк awk в двух местах значит гарантированно
# получить два РАЗНЫХ гейта — исключения разъедутся при первой же правке, и
# заметит это никто.
#
# Использование:
#   scripts/coverage-gate.sh coverage.out <агрегат-%> <пол-на-пакет-%> [метка]
#
# Профиль обязан быть снят с -coverpkg=./...: тогда интеграционные тесты
# (gateway→storage и т.п.) считаются в агрегате, а не пропадают.
#
# 🔴 Из-за -coverpkg один и тот же файл/строка попадает в профиль НЕСКОЛЬКО раз —
# по разу на каждый тест-бинарь, который его инструментирует. Блоки мержатся по
# (file:range) суммированием count ДО подсчёта процентов, иначе total задваивается и
# проценты становятся бессмысленными.
set -euo pipefail

PROFILE=${1:?нужен путь к coverage-профилю}
AGG_MIN=${2:?нужен порог агрегата в процентах}
PKG_MIN=${3:?нужен пол на пакет в процентах}
LABEL=${4:-}

if [ ! -s "$PROFILE" ]; then
  echo "ОШИБКА: профиль $PROFILE пуст или не существует — тесты не собрали покрытие" >&2
  exit 2
fi

[ -n "$LABEL" ] && echo "== гейт покрытия: $LABEL =="

ROOT=$(cd "$(dirname "$0")/.." && pwd)

# ── Исключения ПО ФАЙЛАМ ─────────────────────────────────────────────────────────
#
# Формат строки: путь-от-корня-репозитория|почему.
#
# Зачем отдельно от списка пакетов ниже: исключить пакет целиком дёшево и почти всегда
# слишком широко. Под «directory требует живого контроллера домена» уезжали и разбор
# GUID/SID, и валидация конфига, и перематч владельцев — код, который к AD отношения не
# имеет и тестами покрыт. Гейт про него молчал, то есть регресс в нём никто бы не поймал.
# Правило: исключаем ровно тот файл, где недостижимость физическая, а остальное пакета
# остаётся под полом.
#
# Список проверяется на протухание: файла нет в дереве → гейт падает. Иначе исключение
# переживает переписанный код и продолжает молча вычитать чужие строки.
EXCLUDED_FILES="
internal/server/directory/conn.go|провод LDAP: dial/StartTLS, сервисный bind, пейджинг-search и оба потребителя живого соединения (fetchLDAP, Authenticate/resolveDN, TestConnection). Поднять контроллер домена на раннере нечем, а подделка LDAP проверяла бы собственную заглушку. Живое покрытие — live_stand_test.go против настоящего Samba AD DC (по ROUTINEOPS_LDAP_STAND_URL)
"

excl_re=""
excl_stale=0
while IFS='|' read -r excl_path excl_why; do
  [ -z "$excl_path" ] && continue
  if [ ! -f "$ROOT/$excl_path" ]; then
    echo "FAIL: в списке исключений файл $excl_path, которого в дереве нет — строку надо снять либо поправить путь" >&2
    excl_stale=1
    continue
  fi
  if [ -z "$excl_why" ]; then
    echo "FAIL: исключение $excl_path без причины (формат: путь|почему)" >&2
    excl_stale=1
    continue
  fi
  esc=$(printf '%s' "$excl_path" | sed 's/\./\\./g')
  excl_re=${excl_re:+$excl_re|}$esc
done <<EOF
$EXCLUDED_FILES
EOF
[ "$excl_stale" -eq 0 ] || exit 2

# Исключения из ОБОИХ гейтов (агрегат и пол). Пакеты, где ветки физически недостижимы
# на linux CI, и инфра-пакеты без бизнес-логики:
#   status   — windows DefaultPath + fs-error ветки Write
#   service  — launchd/SCM install paths
#   keystore — CGO Security.framework / Windows NCrypt
#   mailer   — SMTP без внешнего сервиса не тестируется
#   lockui   — X11-оверлей: захват клавиатуры и указателя, переподнятие окна и
#              выключение хранителя экрана требуют живого дисплея с оконным менеджером
#   x11ui    — те же примитивы, вынесенные ИЗ lockui, чтобы их переиспользовала плашка
#              наблюдения за экраном. Исключение унаследовано вместе с кодом и по той же
#              причине: ListFonts/OpenFont/QueryTextExtents/ImageText и чтение раскладки
#              — это запросы к X-серверу, которого на раннере нет. Чистая часть (разбор
#              таблицы глифов, перевод в UCS-2) покрыта тестами и без дисплея — именно она
#              и ловила настоящий дефект «шрифт открылся, но рисует пустоту»
#   cmd/*, scripts/internal/* — main-пакеты утилит
#   proto, testutil, node_modules — инфра/генерённый код
#
# 🔴 Каждая строка здесь по-прежнему шире, чем нужно: под пакет уходят и чистые функции
# соседних файлов. Сузить их так же, как сужен directory (см. EXCLUDED_FILES), — работа
# на отдельный заход: сначала надо поднять тестами то, что после разреза окажется под
# полом, иначе гейт покраснеет не на дефекте, а на самой правке.
LC_ALL=C awk -v agg_min="$AGG_MIN" -v pkg_min="$PKG_MIN" -v excl_re="$excl_re" '
  NR == 1 { next }
  {
    key = $1
    stmt[key] = $2 + 0
    cnt[key] += $3 + 0
  }
  END {
    for (key in stmt) {
      split(key, a, ":"); file = a[1]
      # Файловые исключения — ДО агрегации по пакету: строки такого файла не попадают
      # ни в пол пакета, ни в агрегат, а весь остальной пакет остаётся под гейтом.
      if (excl_re != "" && file ~ ("(" excl_re ")$")) continue
      n = split(file, p, "/"); pkg = ""
      for (i = 1; i < n; i++) pkg = (pkg == "") ? p[i] : pkg "/" p[i]
      total[pkg] += stmt[key]
      if (cnt[key] > 0) covered[pkg] += stmt[key]
    }
    fail = 0
    grand_total = 0; grand_covered = 0
    for (pkg in total) {
      if (total[pkg] == 0) continue
      if (pkg ~ /\/(status|service|keystore|mailer|lockui|x11ui)$/) continue
      if (pkg ~ /\/(testutil|proto)$/) continue
      if (pkg ~ /\/cmd\//) continue
      if (pkg ~ /\/scripts\/internal\//) continue
      if (pkg ~ /node_modules/) continue
      grand_total += total[pkg]
      grand_covered += covered[pkg]
      pct = covered[pkg] / total[pkg] * 100
      if (pct < pkg_min) {
        printf "FAIL: %s %.1f%% < %g%% floor\n", pkg, pct, pkg_min
        fail = 1
      }
    }
    if (grand_total == 0) { print "FAIL: в профиле не осталось ни одного учитываемого пакета"; exit 1 }
    agg = grand_covered / grand_total * 100
    printf "Coverage aggregate (excl. platform/infra pkgs): %.1f%%\n", agg
    if (agg < agg_min) { printf "FAIL: aggregate %.1f%% < %g%%\n", agg, agg_min; fail = 1 }
    else print "OK: aggregate gate passed"
    exit fail
  }' "$PROFILE"
