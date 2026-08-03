#!/usr/bin/env bash
#
# Наполнение инсталляции демо-данными для скриншотов и демонстраций.
#
# Всё создаётся ШТАТНЫМИ ручками API от имени залогиненного оператора, поэтому данные
# ложатся ровно в ЕГО тенант — сидер тенантами не управляет и управлять не должен.
# Хотите отдельный демо-тенант: заведите его, пригласите туда администратора, войдите под
# ним и запустите сидер. С 03.08.2026 приглашение наконец кладёт человека в свой тенант
# (до этого — в Default, см. историю acceptInvite).
#
# Данные полностью синтетические: example.com, нейтральные имена. Реальных доменов,
# сотрудников и названий компаний здесь быть не должно — скриншоты уходят в статью.
#
# Идемпотентность: повторный прогон НЕ чистит созданное ранее и не падает на дублях —
# сервер отвечает 409, скрипт считает это «уже есть» и идёт дальше.
#
# Запуск:
#   BASE_URL=https://mdm.example.com \
#   ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='...' \
#   bash scripts/seed-demo.sh
#
# Полезные флаги:
#   DRY_RUN=1   — показать, что будет создано, без единого запроса на запись
#   PREFIX=demo — префикс имён (по умолчанию demo), чтобы демо-объекты отличались от боевых
set -euo pipefail

BASE_URL="${BASE_URL:-https://localhost}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
PREFIX="${PREFIX:-demo}"
DRY_RUN="${DRY_RUN:-}"
INSECURE="${INSECURE:-}"   # 1 = не проверять TLS (self-signed на стенде)

[ -n "$ADMIN_EMAIL" ] && [ -n "$ADMIN_PASSWORD" ] || {
  echo "ОШИБКА: задайте ADMIN_EMAIL и ADMIN_PASSWORD." >&2
  echo "  BASE_URL=https://host ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='...' bash scripts/seed-demo.sh" >&2
  exit 1
}

JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
CURL=(curl -sS --fail-with-body -b "$JAR" -c "$JAR" -H "Content-Type: application/json")
[ -n "$INSECURE" ] && CURL+=(-k)

created=0; existed=0; failed=0

# api METHOD PATH [BODY] — печатает тело ответа; 409 (уже есть) не считается провалом.
api() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$DRY_RUN" ]; then
    echo "DRY: $method $path ${body:0:120}" >&2
    return 0
  fi
  local out code
  if [ -n "$body" ]; then
    out=$("${CURL[@]}" -w '\n%{http_code}' -X "$method" "$BASE_URL/api/v1$path" -d "$body" 2>&1) || true
  else
    out=$("${CURL[@]}" -w '\n%{http_code}' -X "$method" "$BASE_URL/api/v1$path" 2>&1) || true
  fi
  code="${out##*$'\n'}"
  local payload="${out%$'\n'*}"
  case "$code" in
    2*) created=$((created+1)); printf '%s' "$payload" ;;
    409) existed=$((existed+1)); printf '' ;;
    *)  failed=$((failed+1)); echo "  !! $method $path → HTTP $code: ${payload:0:200}" >&2; printf '' ;;
  esac
}

# jsonstr — экранирование строки для JSON без внешних зависимостей (jq на проде может
# не быть). Достаточно для наших синтетических значений.
jsonstr() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

echo "== вход =="
if [ -z "$DRY_RUN" ]; then
  "${CURL[@]}" -X POST "$BASE_URL/api/v1/auth/login" \
    -d "{\"email\":\"$(jsonstr "$ADMIN_EMAIL")\",\"password\":\"$(jsonstr "$ADMIN_PASSWORD")\"}" >/dev/null
  # Токен — в HttpOnly-cookie, поэтому дальше всё через тот же jar. Проверяем, что
  # сессия действительно есть: иначе получим гору 401 вместо одного внятного отказа.
  "${CURL[@]}" "$BASE_URL/api/v1/me" >/dev/null || {
    echo "ОШИБКА: вход не дал рабочей сессии (MFA? неверный пароль?)" >&2; exit 1; }
  echo "  ок: $ADMIN_EMAIL @ $BASE_URL"
else
  echo "  DRY: вход пропущен"
fi

echo "== карточки сотрудников =="
# Нейтральные имена: скриншоты публикуются, реальных людей в кадре быть не должно.
i=1
for name in "Алексей Орлов" "Мария Ковалёва" "Игорь Соколов" "Ольга Титова" "Павел Ершов" \
            "Наталья Гусева" "Дмитрий Панов" "Елена Зайцева" "Сергей Крылов" "Анна Морозова"; do
  api POST /persons "{\"display_name\":\"$(jsonstr "$name")\",\"email\":\"user${i}@example.com\"}" >/dev/null
  i=$((i+1))
done

echo "== группы устройств =="
# Одна группа на канале beta — витрина канареечной раскатки (миграция 065).
api POST /device-groups "{\"name\":\"${PREFIX}: бухгалтерия\",\"color\":\"#2563eb\"}" >/dev/null
api POST /device-groups "{\"name\":\"${PREFIX}: разработка\",\"color\":\"#16a34a\"}" >/dev/null
api POST /device-groups "{\"name\":\"${PREFIX}: продажи\",\"color\":\"#f59e0b\"}" >/dev/null
api POST /device-groups "{\"name\":\"${PREFIX}: ноутбуки руководителей\",\"color\":\"#dc2626\"}" >/dev/null
api POST /device-groups "{\"name\":\"${PREFIX}: канарейка\",\"color\":\"#7c3aed\",\"update_channel\":\"beta\"}" >/dev/null

echo "== скрипты =="
# Платформы — канон macOS | Windows | Linux (сервер принимает любой регистр и нормализует,
# см. canonicalPlatform; до 03.08 /scripts требовал строго строчную «linux»).
script_id() { # печатает id созданного скрипта, пусто если не создан
  printf '%s' "$1" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}
S1=$(script_id "$(api POST /scripts "{\"name\":\"${PREFIX}: сбор логов (macOS)\",\"platform\":\"macOS\",\"content\":\"#!/bin/bash\\nlog show --last 1h > /tmp/report.log\\necho готово\"}")")
S2=$(script_id "$(api POST /scripts "{\"name\":\"${PREFIX}: очистка кэшей (macOS)\",\"platform\":\"macOS\",\"content\":\"#!/bin/bash\\nrm -rf ~/Library/Caches/*\\necho очищено\"}")")
S3=$(script_id "$(api POST /scripts "{\"name\":\"${PREFIX}: инвентарь дисков (Linux)\",\"platform\":\"Linux\",\"content\":\"#!/bin/bash\\nlsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT\"}")")
S4=$(script_id "$(api POST /scripts "{\"name\":\"${PREFIX}: обновление пакетов (Linux)\",\"platform\":\"Linux\",\"content\":\"#!/bin/bash\\napt-get update -qq && apt-get -s upgrade | tail -20\"}")")
S5=$(script_id "$(api POST /scripts "{\"name\":\"${PREFIX}: статус BitLocker (Windows)\",\"platform\":\"Windows\",\"content\":\"Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus\"}")")
S6=$(script_id "$(api POST /scripts "{\"name\":\"${PREFIX}: список автозагрузки (Windows)\",\"platform\":\"Windows\",\"content\":\"Get-CimInstance Win32_StartupCommand | Select-Object Name,Command\"}")")
S7=$(script_id "$(api POST /scripts "{\"name\":\"${PREFIX}: свободное место (Windows)\",\"platform\":\"Windows\",\"content\":\"Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free\"}")")
S8=$(script_id "$(api POST /scripts "{\"name\":\"${PREFIX}: аптайм (macOS)\",\"platform\":\"macOS\",\"content\":\"#!/bin/bash\\nuptime\"}")")

echo "== политики скриптов (по расписанию) =="
sched() { # $1 — id скрипта, $2 — имя, $3 — cron
  [ -n "$1" ] || return 0   # скрипт не создан (повторный прогон) — политику не вешаем
  api POST /script-policies \
    "{\"name\":\"$(jsonstr "$2")\",\"script_id\":\"$1\",\"trigger_type\":\"schedule\",\"schedule_config\":{\"cron\":\"$3\"}}" >/dev/null
}
sched "$S1" "${PREFIX}: логи каждое утро"        "0 7 * * *"
sched "$S3" "${PREFIX}: инвентарь дисков еженедельно" "0 3 * * 1"
sched "$S5" "${PREFIX}: проверка BitLocker ежедневно" "30 8 * * *"
sched "$S7" "${PREFIX}: место на дисках дважды в день" "0 9,18 * * *"
sched "$S8" "${PREFIX}: аптайм по понедельникам"  "0 10 * * 1"

echo "== политики запрещённого ПО =="
forbid() { api POST /policies "{\"software_name\":\"$(jsonstr "$1")\",\"rule_type\":\"forbidden\",\"platforms\":$2}" >/dev/null; }
forbid "uTorrent"        '["Windows"]'
forbid "BitTorrent"      '["Windows","macOS","Linux"]'
forbid "TeamViewer"      '["Windows","macOS"]'
forbid "Hola VPN"        '["Windows"]'
forbid "CCleaner"        '["Windows"]'

echo
echo "ИТОГО: создано $created, уже существовало $existed, ошибок $failed"
[ "$failed" -eq 0 ] || { echo "Часть объектов не создана — смотри строки !! выше." >&2; exit 1; }
echo
echo "Чего сидер НЕ делает намеренно:"
echo "  • не создаёт устройства. POST /devices заводит ЗАГОТОВКУ в статусе 'pending'"
echo "    (машина, которой ещё предстоит принести CSR), и в парке она не показывается —"
echo "    это не баг списка. Настоящие карточки появляются после энроллмента агента."
echo "  • не трогает тенанты: данные ложатся в тенант того, кто вошёл."
