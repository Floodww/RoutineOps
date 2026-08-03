#!/usr/bin/env bash
#
# Регрессия из поля (13.07): install.sh идемпотентен — gen-certs.sh пропускает
# существующие серты, .env.prod не перезаписывается, — поэтому ИСПРАВЛЕННЫЙ адрес
# никуда не доезжал: перезапуск ./install.sh был молчаливым no-op, серт оставался со
# старым адресом в SAN, и enroll падал на TLS hostname mismatch. Опечатка в одной
# цифре IP стоила дня.
#
# Реконсиляция адресов опасна сама по себе (она УДАЛЯЕТ рабочий серверный серт), и
# промахнуться в ней = уронить весь парк. Поэтому проверяем обе стороны:
#   А. смена адреса ДОЕЗЖАЕТ  — серт перевыпущен, PUBLIC_WEB_URL исправлен, контейнеры
#      пересозданы (иначе nginx держит старый серт в памяти и починка не видна);
#   Б. всё остальное НЕ ТРОГАЕТСЯ — CA тот же (иначе отвалятся все энролленные
#      устройства), секреты те же (иначе ротация JWT/пароля БД = катастрофа), а прогон
#      без изменений ничего не перевыпускает.
# Отдельно ловим регрессию, найденную адверс-ревью: голый `./install.sh` БЕЗ
# PUBLIC_ADDR (штатный путь — install.env гитигнорится, ставят инлайном) не смеет
# принять внутренний IP за публичный и выкинуть внешний адрес из SAN.
#
# Docker и hostname подменены заглушками: проверяется логика адресации, а не подъём
# стека, и SAN не зависит от сети машины, где гоняют тест.
#
# Запуск: bash scripts/test-install-readdress.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

OLD_ADDR=203.0.113.10        # TEST-NET-3 (RFC 5737)
NEW_ADDR=198.51.100.7        # TEST-NET-2
DOMAIN=mdm.example.test
INTERNAL=192.0.2.5           # TEST-NET-1 — «внутренний» IP заглушки hostname

mkdir -p "$WORK/scripts" "$WORK/bin"
cp "$REPO/install.sh" "$REPO/VERSION" "$REPO/docker-compose.prod.yml" "$WORK/"
cp "$REPO/scripts/gen-certs.sh" "$REPO/scripts/env-db-roles.sh" "$WORK/scripts/"

# Заглушка docker: пишет свои аргументы в лог, но stdout держит ЧИСТЫМ — install.sh
# захватывает вывод `compose ps -q postgres` и `docker inspect` в переменные.
cat >"$WORK/bin/docker" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$WORK/docker.log"
exit 0
EOF
# Заглушка hostname: INTERNAL_IP не должен зависеть от сети хоста (в контейнере
# `hostname -I` бывает пустым → SANS="IP:" → openssl падает).
printf '#!/bin/sh\necho %s\n' "$INTERNAL" >"$WORK/bin/hostname"
chmod +x "$WORK/bin/docker" "$WORK/bin/hostname"
export PATH="$WORK/bin:$PATH"

cd "$WORK"
mk_env() { # install.env с заданным PUBLIC_ADDR (+ опциональный SERVER_HOST)
  { echo "PUBLIC_ADDR=$1"
    [ -n "${2:-}" ] && echo "SERVER_HOST=$2"
    echo "ADMIN_EMAIL=admin@example.com"
    echo "ADMIN_PASSWORD=S3cure-pass!"
  } >install.env
}

fail()    { echo "FAIL: $*" >&2; exit 1; }
san()     { openssl x509 -in certs/server.crt -noout -ext subjectAltName; }
ca_fp()   { openssl x509 -in certs/ca.crt -noout -fingerprint -sha256; }
# MIGRATION_DSN тоже секрет и тоже не смеет ротироваться: он несёт пароль владельца БД.
secrets() { grep -E '^(JWT_SECRET|POSTGRES_PASSWORD|DATABASE_DSN|MIGRATION_DSN)=' .env.prod; }
envval()  { sed -n "s/^$1=//p" .env.prod | head -1; }
# Режим доступа: BSD stat (macOS, где гоняется агентская половина) и GNU stat (CI)
# просят его разными ключами. Порядок важен: GNU-форму пробуем ПЕРВОЙ, потому что на
# macOS `stat -c` — нелегальная опция и падает громко, а вот GNU `stat -f` опция
# ВАЛИДНАЯ (статистика ФС) и на чужом формате вернула бы мусор с кодом 0, то есть
# проверка прав молча сравнивала бы не то.
perms()   { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
# Число различных байт — тот же грубый прокси энтропии, что считает сервер
# (distinctByteCount, cmd/server/main.go). Секрет ASCII, поэтому символ = байт.
distinct(){ printf '%s' "$1" | fold -w1 | sort -u | wc -l | tr -d ' '; }
web_url() { grep '^PUBLIC_WEB_URL=' .env.prod; }
recreates() { grep -c -- '--force-recreate' docker.log 2>/dev/null || true; }
# Обещание install.sh дословно: «Пересоздаём только их, БД и redis не трогаем». Ничем
# не проверялось — `--force-recreate postgres redis` проходил зелёным, а это даунтайм
# БД на КАЖДОЙ смене адреса и потеря очередей Asynq, которые redis держит в памяти.
# Список сервисов проверяем БЕЛЫМ списком, а не поиском слов postgres/redis: самая
# вероятная форма ошибки — `up -d --force-recreate` вообще без имён, а это весь стек,
# и чёрный список её не увидел бы. Печатает нарушившие строки, пусто = чисто.
bad_recreate() {
  grep -- '--force-recreate' docker.log 2>/dev/null | while IFS= read -r line; do
    svc="${line##*--force-recreate}"
    # shellcheck disable=SC2086 — намеренное разбиение на слова: это список сервисов
    set -- $svc
    if [ $# -eq 0 ]; then echo "$line (без списка сервисов = весь стек)"; continue; fi
    for s in "$@"; do
      case "$s" in server|web) ;; *) echo "$line"; break ;; esac
    done
  done
}
backups() { ls certs/server.crt.bak.* 2>/dev/null | wc -l; }
# Перевод файла в CRLF. Намеренно НЕ `sed -i`: у BSD sed (macOS) -i требует аргумент
# суффикса, и тест падал бы прямо здесь — на машине разработчика агента, где он как раз
# и гоняется. Запись через `cat >` (как и нормализация в install.sh) сохраняет права и
# inode файла с секретами, чего не даёт mv временного.
crlf() { awk '{ printf "%s\r\n", $0 }' "$1" > "$1.crlf" && cat "$1.crlf" > "$1" && rm -f "$1.crlf"; }

echo "--- 1: первичная установка на ${OLD_ADDR}"
mk_env "$OLD_ADDR"
bash install.sh >/dev/null 2>&1 || fail "первичная установка упала"
san | grep -q "$OLD_ADDR" || fail "SAN не покрывает исходный ${OLD_ADDR}"
[ "$(web_url)" = "PUBLIC_WEB_URL=https://${OLD_ADDR}" ] || fail "PUBLIC_WEB_URL не выставлен на ${OLD_ADDR}"
CA_BEFORE="$(ca_fp)"; SECRETS_BEFORE="$(secrets)"

echo "--- 1a: секреты не просто неизменны, а ПРИГОДНЫ"
# Ниже весь тест сверяет секреты «до/после» — то есть стабильно пустой или слабый
# секрет проходил бы зелёным, а установка при этом мертва. Граница отказа настоящая,
# не выдуманная: cmd/server/main.go отказывается стартовать (os.Exit(1)) на пустом или
# дефолтном JWT_SECRET, на длине <32 и на <16 различных байт. Последнее — не теория:
# секрет уже генерировался hex-ом (алфавит из 16 символов), и сервер падал
# «too few distinct bytes» примерно на каждой четвёртой установке.
JWT="$(envval JWT_SECRET)"
[ -n "$JWT" ] || fail "JWT_SECRET пуст — сервер откажется стартовать"
case "$JWT" in
  dev-secret-change-in-production|change-me-in-production)
    fail "JWT_SECRET оставлен дефолтным — сервер откажется стартовать" ;;
esac
[ "${#JWT}" -ge 32 ] || fail "JWT_SECRET короче 32 байт (${#JWT}) — сервер откажется стартовать"
[ "$(distinct "$JWT")" -ge 16 ] || fail "в JWT_SECRET меньше 16 различных байт ($(distinct "$JWT")) — сервер откажется стартовать"
# Порог сервера — 16, но проверять ровно по нему мало: hex-генератор упирается в него
# сверху (замер 200 выборок: hex-24 даёт 13..16, медиана 15 — то есть падало бы
# большинство установок, а зелёный тест этого не показал бы). base64-48 на тех же
# выборках даёт 35..48. Порог 24 разделяет их наглухо и ловит возврат к hex детерминированно.
[ "$(distinct "$JWT")" -ge 24 ] || fail "в JWT_SECRET всего $(distinct "$JWT") различных байт — генератор сидит на самом пороге сервера (16), установка падала бы через раз"
DB_PASS_GEN="$(envval POSTGRES_PASSWORD)"
[ -n "$DB_PASS_GEN" ] || fail "POSTGRES_PASSWORD пуст — БД поднимется без пароля"
# Роли разделены (scripts/env-db-roles.sh): DDL идёт под владельцем mdm, сервер — под
# mdm_app без SUPERUSER/BYPASSRLS, иначе RLS FORCE не изолирует тенантов. Проверяем обе
# строки: раньше здесь стояла одна проверка на «postgres://mdm:<пароль>», и она осталась бы
# зелёной, даже если бы сервер продолжал ходить владельцем БД.
grep -qF "MIGRATION_DSN=postgres://mdm:${DB_PASS_GEN}@" .env.prod || fail "MIGRATION_DSN не несёт сгенерированный пароль — миграции не накатятся"
APP_DSN="$(envval DATABASE_DSN)"
case "$APP_DSN" in
  postgres://mdm_app:?*@*) : ;;
  *) fail "DATABASE_DSN не под mdm_app с паролем (${APP_DSN%%@*}@...) — сервер ходил бы в БД владельцем, RLS декоративна" ;;
esac
[ "${APP_DSN#*mdm_app:}" != "${DB_PASS_GEN}@postgres:5432/mdm?sslmode=disable" ] || fail "у mdm_app пароль владельца БД — разделение ролей фиктивно"

echo "--- 1b: .env.prod закрыт от чужих глаз"
# В файле лежат JWT (корень доверия всех токенов), пароль БД и сид-пароль админа.
[ "$(perms .env.prod)" = "600" ] || fail ".env.prod с правами $(perms .env.prod) — JWT, пароль БД и пароль админа читает любой пользователь хоста"

echo "--- 1c: подписной ключ деплойера выпущен и пригоден"
# RELEASE_PUBKEY вшивается в собираемых агентов. Пустой = весь парк, энроллящийся до
# следующего рестарта сервера, молча остаётся без self-update; ключ не проверялся ничем.
[ -f release_ed25519.pem ] || fail "приватник деплойера не создан"
PUBKEY_BEFORE="$(envval RELEASE_PUBKEY)"
[ -n "$PUBKEY_BEFORE" ] || fail "RELEASE_PUBKEY пуст — парк уйдёт в поле без self-update"
[ "$(printf '%s' "$PUBKEY_BEFORE" | openssl base64 -d -A 2>/dev/null | wc -c | tr -d ' ')" = "32" ] \
  || fail "RELEASE_PUBKEY не разворачивается в 32 байта ed25519"

echo "--- 2: тот же адрес → не трогаем ничего"
R0="$(recreates)"
bash install.sh >/dev/null 2>&1 || fail "повторная установка упала"
[ "$(backups)" -eq 0 ]      || fail "серт перевыпущен без смены адреса — дёргали бы прод каждый прогон"
[ "$(recreates)" -eq "$R0" ] || fail "лишний --force-recreate без изменений конфига"

echo "--- 3: исправили PUBLIC_ADDR на ${NEW_ADDR} — та самая регрессия"
mk_env "$NEW_ADDR"
R1="$(recreates)"
bash install.sh >/dev/null 2>&1 || fail "установка после смены адреса упала"
san | grep -q "$NEW_ADDR" || fail "серт НЕ перевыпущен: SAN без ${NEW_ADDR} — enroll упадёт на TLS"
if san | grep -q "$OLD_ADDR"; then fail "в SAN остался прежний ${OLD_ADDR}"; fi
[ "$(web_url)" = "PUBLIC_WEB_URL=https://${NEW_ADDR}" ] || fail "PUBLIC_WEB_URL остался на старом адресе"
[ "$(ca_fp)" = "$CA_BEFORE" ]        || fail "CA пересоздан — все энролленные устройства отвалились бы"
[ "$(secrets)" = "$SECRETS_BEFORE" ] || fail "секреты (.env.prod) ротировались — JWT/пароль БД нельзя менять на месте"
# Второй корень доверия рядом с CA: перевыпуск подписного ключа не роняет TLS, поэтому
# заметен не был бы — уже развёрнутые агенты просто перестали бы принимать обновления.
[ "$(envval RELEASE_PUBKEY)" = "$PUBKEY_BEFORE" ] || fail "подписной ключ деплойера перевыпущен — развёрнутые агенты потеряют доверие к self-update"
[ "$(backups)" -ge 1 ]               || fail "прежний серт не сохранён в бэкап"
[ -n "$(ls certs/server.key.bak.* 2>/dev/null)" ] || fail "прежний ключ не сохранён — серт без ключа не откатить"
[ "$(recreates)" -gt "$R1" ] || fail "нет --force-recreate: nginx остался бы со старым сертом в памяти"
[ -z "$(bad_recreate)" ] || fail "пересоздано лишнее: $(bad_recreate) — БД в даунтайм и очереди Asynq в redis теряются на каждой смене адреса"

echo "--- 4: голый прогон БЕЗ install.env (инлайновая установка, DR) → строгий no-op"
rm -f install.env                       # PUBLIC_ADDR не задан: адрес живёт в .env.prod
B2="$(backups)"; R2="$(recreates)"
bash install.sh >/dev/null 2>&1 || fail "голый прогон упал"
san | grep -q "$NEW_ADDR" || fail "публичный адрес ВЫПАЛ из SAN — весь парк уходит в TLS-mismatch"
[ "$(web_url)" = "PUBLIC_WEB_URL=https://${NEW_ADDR}" ] || fail "PUBLIC_WEB_URL перебит внутренним IP"
[ "$(backups)" -eq "$B2" ]   || fail "серт перевыпущен на пустом месте"
[ "$(recreates)" -eq "$R2" ] || fail "лишний --force-recreate на голом прогоне"

echo "--- 4b: у хоста сменился внутренний IP (миграция VM / новый NIC / DHCP), install.env всё ещё нет"
# Самый опасный путь: PUBLIC_ADDR не задан, внутренний IP другой ⇒ наивная реконсиляция
# решит, что серт «не покрывает хост», перевыпустит его по текущему окружению — и
# публичный адрес, по которому живёт ВЕСЬ парк, молча выпадет из SAN. Публичный адрес
# обязан подняться из .env.prod, а не из hostname.
printf '#!/bin/sh\necho 192.0.2.77\n' >"$WORK/bin/hostname"
R3="$(recreates)"
bash install.sh >/dev/null 2>&1 || fail "прогон после смены внутреннего IP упал"
san | grep -q "$NEW_ADDR" || fail "публичный адрес ВЫПАЛ из SAN при смене внутреннего IP — парк лёг бы весь"
san | grep -q "192.0.2.77" || fail "новый внутренний IP не попал в SAN"
[ "$(web_url)" = "PUBLIC_WEB_URL=https://${NEW_ADDR}" ] || fail "PUBLIC_WEB_URL перебит внутренним IP"
[ "$(ca_fp)" = "$CA_BEFORE" ]        || fail "CA пересоздан"
[ "$(secrets)" = "$SECRETS_BEFORE" ] || fail "секреты ротировались"
[ "$(recreates)" -gt "$R3" ] || fail "серт перевыпущен, а контейнеры не пересозданы"

echo "--- 5: добавили SERVER_HOST=${DOMAIN} → домен обязан доехать в SAN"
mk_env "$NEW_ADDR" "$DOMAIN"
bash install.sh >/dev/null 2>&1 || fail "установка с SERVER_HOST упала"
san | grep -q "$DOMAIN"   || fail "DNS-имя не попало в SAN — тот же молчаливый no-op"
san | grep -q "$NEW_ADDR" || fail "перевыпуск потерял публичный IP"
[ "$(ca_fp)" = "$CA_BEFORE" ] || fail "CA пересоздан"

echo "--- 5b: PUBLIC_ADDR — ДОМЕН, а не IP (документированный путь install.sh)"
# `PUBLIC_ADDR=mdm.example.com ./install.sh` расписан в шапке install.sh, но ни один
# сценарий его не проходил: везде PUBLIC_ADDR был IP, а домен приезжал только через
# SERVER_HOST. Между ветками разница не косметическая — классификатор адреса выбирает
# DNS: против IP: в SAN, а cert_covers для домена идёт через -checkhost.
PUB_DOMAIN=web.example.test
mk_env "$PUB_DOMAIN"
R5b="$(recreates)"
bash install.sh >/dev/null 2>&1 || fail "установка с доменным PUBLIC_ADDR упала"
san | grep -q "DNS:${PUB_DOMAIN}" || fail "доменный PUBLIC_ADDR не попал в SAN как DNS — enroll по домену упадёт на TLS"
[ "$(web_url)" = "PUBLIC_WEB_URL=https://${PUB_DOMAIN}" ] || fail "PUBLIC_WEB_URL не выставлен на домен"
[ "$(ca_fp)" = "$CA_BEFORE" ]        || fail "CA пересоздан"
[ "$(secrets)" = "$SECRETS_BEFORE" ] || fail "секреты ротировались"
[ "$(recreates)" -gt "$R5b" ] || fail "нет --force-recreate после перехода на домен"

# Голый прогон на доменном деплое — самая опасная половина: сломайся -checkhost, серт
# перевыпускался бы КАЖДЫЙ прогон, а PUBLIC_WEB_URL затирался бы внутренним IP.
rm -f install.env
B5c="$(backups)"; R5c="$(recreates)"
bash install.sh >/dev/null 2>&1 || fail "голый прогон на доменном деплое упал"
san | grep -q "DNS:${PUB_DOMAIN}" || fail "домен выпал из SAN на голом прогоне — весь парк в TLS-mismatch"
[ "$(web_url)" = "PUBLIC_WEB_URL=https://${PUB_DOMAIN}" ] || fail "PUBLIC_WEB_URL перебит внутренним IP на доменном деплое"
[ "$(backups)" -eq "$B5c" ]  || fail "серт перевыпускается на каждом прогоне доменного деплоя"
[ "$(recreates)" -eq "$R5c" ] || fail "лишний --force-recreate на голом прогоне доменного деплоя"

echo "--- 6: SMTP дозаливается к УЖЕ поднятому серверу (был no-op — блок сидел под if)"
grep -q '^SMTP_HOST=' .env.prod && fail "SMTP появился раньше времени"
mk_env "$NEW_ADDR" "$DOMAIN"
{ echo "SMTP_HOST=smtp.example.test"; echo "SMTP_PORT=587"; } >>install.env
R6="$(recreates)"
bash install.sh >/dev/null 2>&1 || fail "прогон с SMTP упал"
grep -qx 'SMTP_HOST=smtp.example.test' .env.prod || fail "SMTP_HOST не дозалит в .env.prod"
grep -qx 'SMTP_PORT=587' .env.prod || fail "SMTP_PORT не дозалит"
[ "$(recreates)" -gt "$R6" ] || fail "server не пересоздан — новый SMTP не подхватится"
[ "$(secrets)" = "$SECRETS_BEFORE" ] || fail "дозаливка SMTP затронула секреты"
# upsert переписывает .env.prod через mv временного файла — это подменяет inode, и
# режим доступа теряется, если его не выставить заново. Проверяем ПОСЛЕ дозаливки.
[ "$(perms .env.prod)" = "600" ] || fail ".env.prod после дозаливки настроек стал $(perms .env.prod) — секреты открылись"

echo "--- 6b: прогон БЕЗ SMTP в env не должен стирать уже настроенный SMTP"
mk_env "$NEW_ADDR" "$DOMAIN"              # install.env снова без SMTP
R6b="$(recreates)"
bash install.sh >/dev/null 2>&1 || fail "прогон после дозаливки упал"
grep -qx 'SMTP_HOST=smtp.example.test' .env.prod || fail "SMTP стёрт прогоном без SMTP в env — потеря конфига"
[ "$(recreates)" -eq "$R6b" ] || fail "лишний --force-recreate: SMTP не менялся"

echo "--- 7: install.env и .env.prod в CRLF (файлы правятся руками и гитигнорятся → Windows)"
# Хвостовой CR невидим глазом, а PUBLIC_ADDR="1.2.3.4\r" мимо теста `*[!0-9.]*` уезжает
# в SAN как DNS вместо IP — весь парк, ходящий по IP, ловит TLS-mismatch. Хуже того,
# cert_covers на CR-адресе не матчит никогда: серт перевыпускался бы каждый прогон, а
# PUBLIC_WEB_URL переписывался бы с тем же CR обратно — само бы не починилось.
mk_env "$NEW_ADDR" "$DOMAIN"
crlf install.env
crlf .env.prod
B7="$(backups)"
bash install.sh >/dev/null 2>&1 || fail "прогон с CRLF-файлами упал"
san | grep -q "IP Address:${NEW_ADDR}" || fail "публичный IP уехал в SAN не как IP (CR обманул классификатор) — парк лёг бы на TLS"
san | grep -q "$DOMAIN" || fail "SERVER_HOST потерян: CR склеил SAN-записи"
[ "$(web_url)" = "PUBLIC_WEB_URL=https://${NEW_ADDR}" ] || fail "PUBLIC_WEB_URL остался с CR"
grep -q $'\r' .env.prod && fail ".env.prod всё ещё в CRLF — CR уедет в DATABASE_DSN и сид-пароль админа"
grep -qx 'ADMIN_PASSWORD=S3cure-pass!' install.env || fail "CR остался в ADMIN_PASSWORD — админ не залогинится, браузер CR не шлёт"
R7="$(recreates)"
bash install.sh >/dev/null 2>&1 || fail "повторный прогон после нормализации упал"
[ "$(backups)" -eq "$B7" ]   || fail "серт перевыпускается на каждом прогоне — CR-петля не разорвана"
[ "$(recreates)" -eq "$R7" ] || fail "лишний --force-recreate после нормализации CRLF"

[ -z "$(bad_recreate)" ] || fail "за весь прогон под --force-recreate попало лишнее: $(bad_recreate)"

echo "OK: смена адреса (IP и домен) и дозаливка настроек доезжают, секреты пригодны и закрыты, CA и подписной ключ целы, CRLF нормализуется, БД и redis не трогаются, без изменений ничего не перевыпускается"
