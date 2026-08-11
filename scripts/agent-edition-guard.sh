#!/bin/sh
# agent-edition-guard.sh — редакция агента проверяется ПО СОБРАННОМУ БИНАРЮ, а не по
# переменной сборки.
#
# Аргументы: <BUILD_TAGS> <файл> [метка]
#   BUILD_TAGS — то же значение, которым собирали: пусто = open-core, содержит
#                "enterprise" = enterprise. Метка идёт в диагностику (windows/amd64 и т.п.).
#
# Коды возврата: 0 — редакция сошлась, 1 — разошлась, 2 — проверить нечем (fail-closed).
#
# 🔴 Зачем. Редакция публикуемого агента задаётся переменной BUILD_TAGS в .env.prod, а
# переменную можно забыть: перенос окружения, свежий .env.prod, опечатка в значении. Тогда
# enterprise-инсталляция МОЛЧА собирает и публикует парку open-core агента, и это не
# «фича выключена», а «фичи нет в бинаре»:
#   • capabilities() из cmd/agent/screen_stub.go возвращает nil → устройства перестают
#     докладывать screen_session;
#   • createSession отдаёт 409 agent_unsupported на каждую попытку — регресс Q-78;
#   • FileVault-provisioning на маках отвечает отказом навсегда.
# Выкат при этом проходит зелёным: собралось, подписалось, опубликовалось. Симметрично
# обратное — open-core инсталляция со случайно выставленным тегом раздаёт парку закрытый код.
#
# Токен — ПУТЬ ПАКЕТА. Линкер кладёт его в таблицы имён тогда и только тогда, когда пакет
# реально слинкован; единственный импортёр internal/agent/screen — cmd/agent/screen_wiring.go
# под //go:build enterprise. Токен переживает -trimpath и -s -w, которыми собирают деплойные
# бинари: проверено на windows/amd64, linux/amd64, linux/arm64 и darwin/arm64 (CGO) в обе
# стороны — 0 вхождений во free, 3 в enterprise.
#
# Почему НЕ darwin-специфичный маркер, которым проверялся macOS-бинарь: тот код darwin-only,
# в enterprise-сборке windows и linux его нет вовсе — на этих целях гейт был бы красным на
# исправном дереве. Токен пакета экрана есть во всех трёх ОС (Makefile: check-remote-tags).
set -eu

TOKEN='internal/agent/screen'

if [ "$#" -lt 2 ]; then
  echo "agent-edition-guard.sh: нужно <BUILD_TAGS> <файл> [метка]" >&2
  exit 2
fi
TAGS=$1
BIN=$2
LABEL=${3:-$2}

if [ ! -f "$BIN" ]; then
  echo "ОШИБКА [$LABEL]: $BIN не найден — редакцию проверить нечем (гейт fail-closed)." >&2
  exit 2
fi
if [ ! -s "$BIN" ]; then
  echo "ОШИБКА [$LABEL]: $BIN пуст — редакцию проверить нечем (гейт fail-closed)." >&2
  exit 2
fi

# 🔴 Гейт обязан отличать БИНАРЬ от КОНТЕЙНЕРА, внутри которого бинарь лежит сжатым.
#
# Найдено при выпуске 2.6.2, на себе: `agent-edition-guard.sh "" build/pkg/*.pkg` печатает
# «open-core ✅» для ЗАВЕДОМО enterprise-пакета. Токен ищется по сырым байтам, а payload
# внутри .pkg (xar+gzip), .msi (CFB) и .deb/.rpm сжат — совпадений нет и быть не может.
# То есть на контейнере гейт не «не нашёл», а НЕ ИСКАЛ, и молча отвечает самым опасным
# из двух исходов: «закрытого кода тут нет, публикуй».
#
# Сегодняшние вызовы все до одного передают сырой бинарь (update.sh, install.sh, Makefile,
# pre-push), а check-installer-versions.sh сначала распаковывает payload и зовёт гейт уже
# на нём — то есть дыра пока не выстрелила. Но она заряжена: следующий, кто наведёт гейт
# на инсталлятор, получит зелёное и поверит ему.
#
# Поэтому — белый список форматов исполняемого файла. Всё остальное fail-closed (код 2,
# «проверить нечем»), а не «редакция сошлась».
magic=$(od -A n -t x1 -N 4 "$BIN" 2>/dev/null | tr -d ' \n') || magic=""
case "$magic" in
  7f454c46*)                       ;; # ELF (linux)
  4d5a*)                           ;; # PE/MZ (windows)
  cffaedfe*|feedfacf*)             ;; # Mach-O 64 (darwin), LE и BE
  cefaedfe*|feedface*)             ;; # Mach-O 32
  cafebabe*|bebafeca*)             ;; # Mach-O universal
  "")
    echo "ОШИБКА [$LABEL]: не удалось прочитать первые байты $BIN — редакция не проверена." >&2
    exit 2 ;;
  *)
    case "$magic" in
      78617221*) kind="архив xar — это .pkg" ;;
      d0cf11e0*) kind="OLE-контейнер — это .msi" ;;
      1f8b*)     kind="gzip" ;;
      504b*)     kind="zip" ;;
      213c6172*) kind="ar — это .deb" ;;
      edabeedb*) kind="rpm" ;;
      *)         kind="неизвестный формат (magic $magic)" ;;
    esac
    echo "ОШИБКА [$LABEL]: $BIN — не бинарь агента, а $kind." >&2
    echo "  Внутри контейнера payload СЖАТ: токен $TOKEN там не найдётся никогда," >&2
    echo "  и гейт объявил бы open-core заведомо enterprise-пакет. Распакуйте payload и" >&2
    echo "  наведите гейт на сам бинарь — так делает scripts/check-installer-versions.sh." >&2
    exit 2 ;;
esac

# Код возврата grep различаем полностью: 1 — «не нашёл», всё остальное — «не смог прочитать».
# Свалить их в одну ветку значило бы принять нечитаемый файл за open-core.
#
# 🔴 LC_ALL=C обязателен, и это не гигиена. В UTF-8-локали grep разбирает вход как текст,
# а строку с невалидной последовательностью байт просто не сопоставляет — молча. Бинарь
# агента таких последовательностей полон (заголовок Mach-O начинается с cf fa ed fe), и
# найдётся ли токен, зависит от того, куда легли байты 0x0a вокруг него: попал токен в
# «строку» с мусором — совпадения нет. То есть гейт работал бы по удаче и отвечал бы
# «open-core» на enterprise-бинаре. Поймано фикстурой Mach-O в internal/contract, где
# весь файл — одна строка: с локалью по умолчанию токен не находился.
rc=0
LC_ALL=C grep -q "$TOKEN" "$BIN" || rc=$?
case "$rc" in
  0) have=yes ;;
  1) have=no ;;
  *) echo "ОШИБКА [$LABEL]: grep не смог прочитать $BIN (код $rc) — редакция не проверена." >&2
     exit 2 ;;
esac

case "$TAGS" in
  *enterprise*) want=yes ;;
  *)            want=no ;;
esac

if [ "$have" = "$want" ]; then
  if [ "$want" = yes ]; then
    echo "  редакция [$LABEL]: enterprise ✅ ($TOKEN слинкован)"
  else
    echo "  редакция [$LABEL]: open-core ✅ ($TOKEN не слинкован)"
  fi
  exit 0
fi

if [ "$want" = yes ]; then
  echo "ОШИБКА [$LABEL]: инсталляция enterprise (BUILD_TAGS=$TAGS), а бинарь собран как OPEN-CORE." >&2
  echo "  В $BIN нет $TOKEN — значит удалённого стола и FileVault в нём НЕТ (не выключены," >&2
  echo "  а не скомпилированы). Опубликовать его = устройства перестанут докладывать" >&2
  echo "  screen_session, а создание сеанса начнёт отдавать 409 agent_unsupported." >&2
  echo "  Проверьте BUILD_TAGS в .env.prod и что значение доехало до сборки агентов." >&2
else
  echo "ОШИБКА [$LABEL]: инсталляция open-core (BUILD_TAGS пуст), а бинарь собран как ENTERPRISE." >&2
  echo "  В $BIN есть $TOKEN. Публикация отменена: это была бы раздача закрытого кода" >&2
  echo "  всему парку, а для трекнутых артефактов — ещё и утечка в публичный Free-срез." >&2
fi
exit 1
