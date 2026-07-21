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
cp "$REPO/scripts/gen-certs.sh" "$WORK/scripts/"

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
secrets() { grep -E '^(JWT_SECRET|POSTGRES_PASSWORD|DATABASE_DSN)=' .env.prod; }
web_url() { grep '^PUBLIC_WEB_URL=' .env.prod; }
recreates() { grep -c -- '--force-recreate' docker.log 2>/dev/null || true; }
backups() { ls certs/server.crt.bak.* 2>/dev/null | wc -l; }

echo "--- 1: первичная установка на ${OLD_ADDR}"
mk_env "$OLD_ADDR"
bash install.sh >/dev/null 2>&1 || fail "первичная установка упала"
san | grep -q "$OLD_ADDR" || fail "SAN не покрывает исходный ${OLD_ADDR}"
[ "$(web_url)" = "PUBLIC_WEB_URL=https://${OLD_ADDR}" ] || fail "PUBLIC_WEB_URL не выставлен на ${OLD_ADDR}"
CA_BEFORE="$(ca_fp)"; SECRETS_BEFORE="$(secrets)"

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
[ "$(backups)" -ge 1 ]               || fail "прежний серт не сохранён в бэкап"
[ -n "$(ls certs/server.key.bak.* 2>/dev/null)" ] || fail "прежний ключ не сохранён — серт без ключа не откатить"
[ "$(recreates)" -gt "$R1" ] || fail "нет --force-recreate: nginx остался бы со старым сертом в памяти"

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
sed -i 's/$/\r/' install.env
sed -i 's/$/\r/' .env.prod
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

echo "OK: смена адреса и дозаливка настроек доезжают, CA и секреты целы, CRLF нормализуется, без изменений ничего не перевыпускается"
