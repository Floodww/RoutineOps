#!/bin/bash
set -e
# Секреты (.env.prod, приватник подписи, certs/*.key, дампы) создаются только для
# владельца — не world-readable на многопользовательском хосте.
umask 077

command -v docker >/dev/null 2>&1 || { echo "Docker не установлен"; exit 1; }

# Поддержка docker compose v1 и v2
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
else
  DC="docker-compose"
fi

# Host-пререквизиты (кроме docker/compose, проверенных выше): install.sh генерит
# сертификаты (openssl) и тянет обновления (git). Падаем рано с внятной ошибкой.
for _c in git openssl; do
  command -v "$_c" >/dev/null 2>&1 || { echo "ОШИБКА: не установлен '$_c' — нужен для установки. Поставь его и повтори." >&2; exit 1; }
done

echo "=== RoutineOps Server Install ==="

# install.env заполняется руками (install.env.example: «nano install.env»), .env.prod
# правится при смене адреса/SMTP — оба гитигнорятся, так что оба доезжают с Windows с
# CRLF. Хвостовой CR невидим, а последствия молчаливые: PUBLIC_ADDR="1.2.3.4\r" мимо
# теста `*[!0-9.]*` уезжает в SAN как DNS вместо IP (агенты по IP ловят TLS-mismatch),
# cert_covers не матчит — серт перевыпускается каждый прогон, а строка PUBLIC_WEB_URL
# переписывается с тем же CR обратно в .env.prod, т.е. само не чинится никогда. CR в
# ADMIN_PASSWORD ещё и запекается в сид админа: браузер CR не шлёт → вход невозможен.
# Чиним один раз на файл, ДО чтения — иначе каждый потребитель ниже пришлось бы латать
# отдельно (два `.`-сорса, sed-парсер PUBLIC_WEB_URL, grep -qxF идемпотентности).
for _f in install.env .env.prod; do
  [ -f "$_f" ] && grep -q $'\r' "$_f" && { sed -i 's/\r$//' "$_f"; echo "!! $_f был в CRLF (Windows) — привёл к LF"; }
done

# Быстрый старт: параметры берём из install.env (cp install.env.example install.env,
# заполни PUBLIC_ADDR/ADMIN_*). Так все нужные значения уходят в установку сразу и
# наверняка, а не забываются в инлайновых env. Инлайновые VAR=... ./install.sh
# переопределяют файл (set -a: всё прочитанное экспортируется дочерним процессам).
if [ -f install.env ]; then
  set -a; . ./install.env; set +a
  echo "Параметры прочитаны из install.env"
fi

INTERNAL_IP=$(hostname -I | awk '{print $1}')
# PUBLIC_ADDR — адрес, по которому к серверу ходят агенты и браузеры ИЗВНЕ. `hostname -I`
# даёт ВНУТРЕННИЙ IP (за NAT / на VPN — напр. 192.168.1.10), а не внешний, поэтому за NAT
# задавай публичный адрес ЯВНО, иначе enroll по внешнему IP упадёт на TLS (агент проверяет
# hostname enroll-эндпоинта против SAN серверного серта; SAN без внешнего IP = отказ):
#   PUBLIC_ADDR=203.0.113.10   ./install.sh   # внешний IP
#   PUBLIC_ADDR=mdm.example.com ./install.sh   # домен
# SERVER_HOST оставлен для обратной совместимости (доп. DNS-SAN).
#
# 🔴 PUBLIC_ADDR нигде НЕ персистится: при инлайновой установке (документированный путь
# выше, install.env гитигнорится) следующий — совершенно штатный — голый ./install.sh
# (перепубликовать агентов, восстановить RELEASE_PUBKEY по disaster-recovery) видел бы
# PUBLIC_ADDR пустым и принял за публичный адрес ВНУТРЕННИЙ IP. Публичный адрес деплоя
# на самом деле сохранён — в PUBLIC_WEB_URL (.env.prod); он и есть источник истины,
# `hostname -I` — последний фолбэк. Без этого реконсиляция ниже перевыпустила бы серт
# БЕЗ внешнего адреса в SAN и уронила бы весь парк ровно тем TLS-mismatch, который чиним.
if [ -z "${PUBLIC_ADDR:-}" ] && [ -f .env.prod ]; then
  PUBLIC_ADDR=$(sed -n 's#^PUBLIC_WEB_URL=https\?://##p' .env.prod | head -1 | cut -d/ -f1)
  if [ -n "$PUBLIC_ADDR" ]; then
    echo "PUBLIC_ADDR не задан — беру публичный адрес из .env.prod: ${PUBLIC_ADDR}"
  fi
fi
PUBLIC_IP="${PUBLIC_ADDR:-$INTERNAL_IP}"
# Сертификат сервера покрывает ВНУТРЕННИЙ IP всегда + PUBLIC_ADDR (IP или домен) + SERVER_HOST.
SANS="IP:${INTERNAL_IP}"
if [ "$PUBLIC_IP" != "$INTERNAL_IP" ]; then
  case "$PUBLIC_IP" in
    *[!0-9.]*) SANS="${SANS},DNS:${PUBLIC_IP}" ;;   # есть не цифра/точка → домен
    *)         SANS="${SANS},IP:${PUBLIC_IP}" ;;    # чистый IPv4
  esac
fi
export SERVER_SANS="${SANS}${SERVER_HOST:+,DNS:${SERVER_HOST}}"

# cert_covers <адрес> — покрывает ли текущий серверный серт этот адрес.
# ⚠️ openssl x509 -checkip/-checkhost ВСЕГДА выходит с кодом 0: вердикт только в stdout.
cert_covers() {
  local addr="$1" flag
  case "$addr" in
    *[!0-9.]*) flag=-checkhost ;;   # есть не цифра/точка → домен
    *)         flag=-checkip ;;     # чистый IPv4
  esac
  openssl x509 -in certs/server.crt -noout "$flag" "$addr" 2>/dev/null | grep -q "does match"
}

# Установка идемпотентна (gen-certs.sh пропускает существующие серты, .env.prod не
# перезаписывается) — поэтому исправленный адрес сам по себе НИКУДА не доедет:
# перезапуск ./install.sh был бы молчаливым no-op, серт остался бы с прежним адресом в
# SAN, и enroll по новому адресу продолжал бы падать на TLS (поле, 13.07: опечатка в
# одной цифре IP стоила дня). Значит факт надо сверять с конфигом и приводить к нему.
# RECREATE=1 => пересоздать server/web после up (bind-mount certs/ и env читаются на старте).
RECREATE=""
if [ -f certs/server.crt ]; then
  # SERVER_HOST тоже сверяем: он уходит в SERVER_SANS, и без него добавление домена
  # к работающей установке осталось бы тем же молчаливым no-op.
  for addr in "$INTERNAL_IP" "$PUBLIC_IP" ${SERVER_HOST:+"$SERVER_HOST"}; do
    if cert_covers "$addr"; then continue; fi
    echo "!! серверный сертификат не покрывает ${addr} — перевыпускаю (CA сохраняю)"
    # CA НЕ трогаем: его пересоздание отвязало бы все уже энролленные устройства.
    # Прежнюю пару складываем рядом целиком — серт без ключа откатить нельзя.
    ts=$(date +%s)
    mv certs/server.crt "certs/server.crt.bak.${ts}"
    mv certs/server.key "certs/server.key.bak.${ts}"
    RECREATE=1
    break
  done
fi

bash scripts/gen-certs.sh

if [ ! -f .env.prod ]; then
  # Пароль первого админа обязателен и должен пройти политику сложности
  # (8+ символов, 3 из 4 классов) — иначе seed молча провалится и войти будет некем.
  if [ -z "${ADMIN_PASSWORD:-}" ]; then
    echo "ОШИБКА: не задан ADMIN_PASSWORD (пароль первого администратора)." >&2
    echo "  Быстрый старт: cp install.env.example install.env → заполни → ./install.sh" >&2
    echo "  Либо инлайном: ADMIN_PASSWORD='S3cure-pass!' ADMIN_EMAIL=you@example.com ./install.sh" >&2
    exit 1
  fi
  DB_PASS=$(openssl rand -hex 16)
  # base64, а НЕ hex: сервер требует >=16 РАЗНЫХ байт (distinctByteCount, main.go),
  # а у hex алфавит ровно 16 символов (0-9a-f) → если в рандоме не выпал хоть один,
  # получаем 15 распознанных → сервер крашится "too few distinct bytes" (~1 из 4).
  # base64 (алфавит 64) даёт много различных байт с запасом. -A: без переносов строк.
  JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n')
  cat > .env.prod <<EOF
DATABASE_DSN=postgres://mdm:${DB_PASS}@postgres:5432/mdm?sslmode=disable
REDIS_ADDR=redis:6379
SERVER_CERT=certs/server.crt
SERVER_KEY=certs/server.key
CA_CERT=certs/ca.crt
CA_KEY=certs/ca.key
JWT_SECRET=${JWT_SECRET}
POSTGRES_PASSWORD=${DB_PASS}
SEED_ADMIN_EMAIL=${ADMIN_EMAIL:-admin@company.com}
SEED_ADMIN_PASSWORD=${ADMIN_PASSWORD}
PUBLIC_WEB_URL=https://${PUBLIC_IP}
EOF
  echo ".env.prod создан"
fi

# .env.prod создаётся только при отсутствии (выше) — значит смена адреса его не трогает,
# и PUBLIC_WEB_URL остаётся со старым: ломаются ссылки на скачивание агентов и инвайты.
# Критерий — не «совпадает с PUBLIC_IP», а «покрыт ли этот хост сертом»: PUBLIC_WEB_URL
# штатно бывает доменом из SERVER_HOST (docs/install.md), и затирать его голым IP нельзя.
# Не покрыт (та самая опечатка в адресе) — приводим к PUBLIC_IP. Серт к этому моменту
# уже перевыпущен, так что сверяем с АКТУАЛЬНЫМ.
web_host=$(sed -n 's#^PUBLIC_WEB_URL=https\?://##p' .env.prod | head -1 | cut -d/ -f1)
if [ -z "$web_host" ] || ! cert_covers "$web_host"; then
  grep -v '^PUBLIC_WEB_URL=' .env.prod > .env.prod.tmp
  echo "PUBLIC_WEB_URL=https://${PUBLIC_IP}" >> .env.prod.tmp
  mv .env.prod.tmp .env.prod
  echo "!! PUBLIC_WEB_URL (${web_host:-пусто}) не покрыт сертификатом — привёл к https://${PUBLIC_IP}"
  RECREATE=1
fi

# Опциональные серверные настройки (SMTP/Telegram/cookie/retention; сервер читает их из
# окружения — internal/server/config/config.go). Раньше этот блок сидел ВНУТРИ создания
# .env.prod, поэтому добавить SMTP к уже поднятому серверу через install.env было нельзя:
# перезапуск ./install.sh не трогал существующий .env.prod (тот же молчаливый no-op, что
# чинили для адреса). Теперь дозаливаем и на живой установке — upsert КАЖДОЙ ЗАДАННОЙ
# переменной; незаданные НЕ трогаем, чтобы прогон без SMTP в окружении не стёр уже
# настроенное (руками или прошлым прогоном).
opt_changed=""
for v in SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_FROM SMTP_TLS \
         TELEGRAM_BOT_TOKEN COOKIE_SECURE DATA_RETENTION_DAYS AUDIT_RETENTION_DAYS; do
  val="${!v:-}"
  [ -z "$val" ] && continue                        # не задано — не трогаем
  if grep -qxF "${v}=${val}" .env.prod; then continue; fi   # уже такое — no-op
  grep -v "^${v}=" .env.prod > .env.prod.tmp
  echo "${v}=${val}" >> .env.prod.tmp
  mv .env.prod.tmp .env.prod
  opt_changed="${opt_changed} ${v}"                # только ИМЯ (пароли не в лог)
done
if [ -n "$opt_changed" ]; then
  echo "Серверные настройки обновлены:${opt_changed}"
  RECREATE=1
fi
chmod 600 .env.prod

# --- per-deployer подписной ключ self-update (ed25519) ---
# Каждый деплойер = свой корень доверия: приватник НИКОГДА не покидает эту машину,
# публичный (RELEASE_PUBKEY) вшивается в собираемых агентов. Наш мейнтейнерский
# ключ тут ни при чём — агенты доверяют ТОЛЬКО серверу этого деплойера.
if [ ! -f release_ed25519.pem ]; then
  echo "Генерация per-deployer подписного ключа (ed25519)..."
  openssl genpkey -algorithm ed25519 -out release_ed25519.pem
  chmod 600 release_ed25519.pem
fi

# RELEASE_PUBKEY пишем в .env.prod ДО старта сервера — иначе сервер поднимется с пустым
# ключом (env_file читается на старте) и будет отдавать в enroll-ответе пустой
# release_pubkey; весь парк, энроллящийся до следующего рестарта сервера, молча останется
# без self-update (relocate: "release-pubkey НЕ НАЙДЕН", main.go). base64(raw 32b ed25519);
# SPKI DER = 12б заголовок + 32б ключа → tail -c 32. Идемпотентно (strip+append).
RELEASE_PUBKEY=$(openssl pkey -in release_ed25519.pem -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')
grep -v '^RELEASE_PUBKEY=' .env.prod > .env.prod.tmp || true
echo "RELEASE_PUBKEY=${RELEASE_PUBKEY}" >> .env.prod.tmp
mv .env.prod.tmp .env.prod
chmod 600 .env.prod

# Экспорт .env.prod + VERSION в окружение: compose интерполирует build-args
# (VERSION) только из окружения запуска — env_file на сборку не влияет.
set -a; . ./.env.prod; set +a
export VERSION="$(cat VERSION)"

$DC -f docker-compose.prod.yml up -d --build

# Серт/адрес поменялись → контейнеры держат старые в памяти (nginx читает certs/ на
# старте, сервер — env). Пересоздаём только их, БД и redis не трогаем.
if [ -n "$RECREATE" ]; then
  echo "Конфиг изменился — пересоздаю server и web..."
  $DC -f docker-compose.prod.yml up -d --force-recreate server web
fi

# --- сборка + ПОДПИСАННАЯ публикация агентов (win/linux/mac) ---
# Всё в golang-контейнере на compose-сети: postgres:5432 резолвится. В контейнер
# отдаём ТОЛЬКО нужное (DATABASE_DSN для publish-release + RELEASE_PUBKEY), не весь
# .env.prod (JWT/пароли билд-контейнеру не нужны). publish-release подписывает
# манифест и делает UPSERT в agent_releases (идемпотентно при повторе).
echo "Сборка + публикация агентов v$(cat AGENT_VERSION) (подпись per-deployer ключом)..."
mkdir -p releases
PG=$($DC -f docker-compose.prod.yml ps -q postgres)
NET=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$PG" | awk '{print $1}')
docker run --rm --network "$NET" -v "$(pwd)":/app -w /app \
  -e DATABASE_DSN="$DATABASE_DSN" -e RELEASE_PUBKEY="$RELEASE_PUBKEY" \
  golang:1.26-alpine sh -c '
    set -e
    V=$(cat AGENT_VERSION)  # версия АГЕНТА (не продукта): агент версионируется отдельно от сервера
    WMAJ=$(echo "$V" | cut -d. -f1); WMIN=$(echo "$V" | cut -d. -f2); WPAT=$(echo "$V" | cut -d. -f3)
    # darwin здесь НЕТ: macOS-агенту нужен cgo (Cocoa-замок + Keychain), а
    # `CGO_ENABLED=0 GOOS=darwin` молча собирает заглушки по тегам `!darwin || !cgo`.
    # Публикуем prebuilt из репо ниже — его собрал мейнтейнер на маке.
    for pair in "windows amd64" "linux amd64" "linux arm64"; do
      # shellcheck disable=SC2086
      set -- $pair; OS=$1; ARCH=$2
      echo "  → $OS/$ARCH"
      EXTRA_LDFLAGS=""
      if [ "$OS" = "windows" ]; then
        # Манифест Common-Controls v6: без него lxn/walk ПАНИКУЕТ при создании окна
        # лок-оверлея/трея (см. cmd/agent/agent.manifest) — оверлей не рисуется, трея
        # нет, хотя служба процесс поднимает. Встраиваем .syso, как make syso-win.
        # -H windowsgui: GUI-subsystem (иначе трей/оверлей тянут консольное окно,
        # чьё закрытие убивает агент).
        go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.7.0 -64 -arm=false \
          -o cmd/agent/rsrc_windows_amd64.syso -manifest cmd/agent/agent.manifest \
          -ver-major "$WMAJ" -ver-minor "$WMIN" -ver-patch "$WPAT" -ver-build 0 \
          -product-ver-major "$WMAJ" -product-ver-minor "$WMIN" -product-ver-patch "$WPAT" -product-ver-build 0 \
          -file-version "${V}.0" -product-version "$V" \
          -company RoutineOps -product-name "RoutineOps Agent" -description "RoutineOps Agent" \
          -internal-name RoutineOps-agent -original-name RoutineOps-agent.exe \
          cmd/agent/versioninfo.json
        EXTRA_LDFLAGS="-H windowsgui"
      fi
      # Бинари ДЖЕНЕРИК (без -X main.releasePubKey): один вариант на все деплои.
      # Ключ self-update агент берёт из enroll-ответа (server отдаёт RELEASE_PUBKEY),
      # а не из вшитого на сборке — так тот же бинарь годится для универсального MSI.
      GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=${V} ${EXTRA_LDFLAGS}" \
        -o /tmp/agent_${OS}_${ARCH} ./cmd/agent
      [ "$OS" = "windows" ] && rm -f cmd/agent/rsrc_windows_amd64.syso
      go run ./cmd/publish-release -binary /tmp/agent_${OS}_${ARCH} \
        -version "v${V}" -os "$OS" -arch "$ARCH" -key release_ed25519.pem
    done

    # macOS: prebuilt из репо (cgo-сборка мейнтейнера), подписываем ключом деплойера.
    PREBUILT=build/darwin/agent_darwin_arm64
    if [ -f "$PREBUILT" ] && [ -f "$PREBUILT.sha256" ]; then
      echo "  → darwin/arm64 (prebuilt из репо)"
      ( cd build/darwin && sha256sum -c agent_darwin_arm64.sha256 ) || {
        echo "ОШИБКА: sha256 prebuilt darwin-бинаря не сошлась — публикация отменена" >&2
        exit 1
      }
      # Вшитая версия обязана совпасть с VERSION: иначе агент качает "v${V}",
      # а после рестарта рапортует старую → петля обновления каждые 6ч.
      BAKED=$(cat "$PREBUILT.version" 2>/dev/null || echo "")
      if [ "$BAKED" != "v${V}" ]; then
        echo "ОШИБКА: prebuilt собран как '${BAKED:-неизвестно}', а VERSION=v${V}." >&2
        echo "Мейнтейнеру: пересобрать на маке (make release-darwin) и закоммитить." >&2
        exit 1
      fi
      go run ./cmd/publish-release -binary "$PREBUILT" \
        -version "v${V}" -os darwin -arch arm64 -key release_ed25519.pem
    else
      echo "  ⚠ darwin/arm64: $PREBUILT отсутствует — macOS self-update недоступен."
    fi

    # Канонические инсталляторы кладём в releases/ ЗДЕСЬ, в контейнере. Host-side cp
    # падал "Permission denied": releases/ становится root-owned после этого же
    # контейнера (publish-release пишет от root), а install.sh с umask 077 к тому же
    # создал бы 600 — сервер не прочитал бы их по /downloads. В контейнере: тот же root
    # + umask 022 → 644, читаемо. Из репо; при отсутствии — просто пропуск (варнинг ниже).
    [ -f build/msi/RoutineOps-agent.msi ] && { cp build/msi/RoutineOps-agent.msi releases/RoutineOps-agent.msi; echo "  MSI → releases/RoutineOps-agent.msi (универсальный, из репо)"; }
    [ -f build/pkg/RoutineOps-agent.pkg ] && { cp build/pkg/RoutineOps-agent.pkg releases/RoutineOps-agent.pkg; echo "  PKG → releases/RoutineOps-agent.pkg (универсальный, из репо)"; }
  '

# Канонические инсталляторы (releases/RoutineOps-agent.{msi,pkg} → /downloads/… для кнопок в
# UI) копируются В КОНТЕЙНЕРЕ выше — иначе root-owned releases/ + umask 077 ломали
# host-side cp. Здесь только предупреждаем, если исходников в репо нет.
[ -f build/msi/RoutineOps-agent.msi ] || echo "MSI: build/msi/RoutineOps-agent.msi нет — Windows-установка через MSI недоступна (собрать: build/msi/build-msi.ps1 на Windows)"
[ -f build/pkg/RoutineOps-agent.pkg ] || echo "PKG: build/pkg/RoutineOps-agent.pkg нет — macOS-установка через PKG недоступна (собрать: make pkg-mac-native НА маке)"

echo ""
echo "=== MDM запущен ==="
# PUBLIC_IP уже = PUBLIC_ADDR (внешний адрес или внутренний IP при отсутствии) — НЕ
# пересчитываем через hostname -I, иначе тут снова вылез бы внутренний IP.
echo "Web:  https://${PUBLIC_IP}"
echo "gRPC: ${PUBLIC_IP}:50051"
[ "$PUBLIC_IP" = "$INTERNAL_IP" ] && echo "  (внутренний IP; для доступа извне переустанови с PUBLIC_ADDR=<внешний IP/домен>)"
echo "Релиз: v${VERSION} (агенты подписаны локальным release_ed25519.pem — храни приватник!)"
