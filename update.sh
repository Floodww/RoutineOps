#!/bin/bash
# Обновление self-hosted MDM ОДНОЙ командой. Две ортогональные оси апдейта:
#   A. Сервер/web  — git pull + docker rebuild (мгновенно у деплойера).
#   B. Агенты парка — self-update тянет новый подписанный бинарь с ЭТОГО сервера
#      (НЕ централизованный push — это инфра деплойера).
# Порядок: бэкап БД → git pull → пересборка (migrate-сервис накатит миграции ДО
# старта server, fail-closed) → пересборка+публикация агентов новой версии.
set -e
cd "$(dirname "$0")"
umask 077  # дампы БД не world-readable

command -v docker >/dev/null 2>&1 || { echo "Docker не установлен"; exit 1; }
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi

[ -f .env.prod ]          || { echo "Нет .env.prod — сначала ./install.sh"; exit 1; }
[ -f release_ed25519.pem ] || { echo "Нет release_ed25519.pem — сначала ./install.sh"; exit 1; }

set -a; . ./.env.prod; set +a

echo "=== MDM Update ==="
CUR=$($DC -f docker-compose.prod.yml exec -T server ./routineops-server -version 2>/dev/null || echo "неизвестно")
echo "Текущая версия сервера: ${CUR}"

# 1. Бэкап БД ОБЯЗАТЕЛЕН перед миграциями (down-миграций нет — откат только из бэкапа).
#    -Fc (custom format) → восстановим через pg_restore --clean --if-exists в
#    существующую БД (plain-dump в populated БД не накатывается).
mkdir -p backups && chmod 700 backups
PG=$($DC -f docker-compose.prod.yml ps -q postgres)
if [ -n "$PG" ]; then
  BK="backups/db-$(date +%Y%m%d-%H%M%S).dump"
  docker exec "$PG" pg_dump -U mdm -Fc mdm > "$BK"
  echo "Бэкап БД: ${BK}"
else
  echo "⚠ postgres не запущен — бэкап пропущен (первый запуск?)"
fi

# 2. Новая версия из публичного репозитория.
git fetch --tags --quiet || true
git pull --ff-only
export VERSION="$(cat VERSION)"
echo "Новая версия: v${VERSION}"

# 3. Пересборка. migrate-сервис накатит pending-миграции ДО старта server.
$DC -f docker-compose.prod.yml up -d --build

# 4. Сборка + публикация агентов новой версии (self-update подхватит парк за <interval>).
#    Подпись — локальным per-deployer приватником; RegisterAgentRelease делает UPSERT
#    (повтор той же версии = no-op, не падение). В build-контейнер отдаём только нужное.
#    RELEASE_PUBKEY контейнеру НЕ передаём: в бинарь он больше не вшивается (см. ниже),
#    а серверу он приезжает из .env.prod, которую этот скрипт только читает.
PG=$($DC -f docker-compose.prod.yml ps -q postgres)
NET=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$PG" | awk '{print $1}')
docker run --rm --network "$NET" -v "$(pwd)":/app -w /app \
  -e DATABASE_DSN="$DATABASE_DSN" \
  golang:1.26-alpine sh -c '
    set -e
    V=$(cat VERSION)
    # PE-версия для Windows-VERSIONINFO: только semver-часть, иначе 0.0.0 (ср. WINVER в Makefile).
    WINVER=$(echo "$V" | grep -Eo "^[0-9]+\.[0-9]+\.[0-9]+" || echo 0.0.0)
    WV_MAJ=${WINVER%%.*}; WV_REST=${WINVER#*.}; WV_MIN=${WV_REST%%.*}; WV_PAT=${WV_REST#*.}

    # darwin здесь НЕТ: macOS-агенту нужен cgo (Cocoa-замок + Keychain), а
    # `CGO_ENABLED=0 GOOS=darwin` молча собирает заглушки по тегам `!darwin || !cgo`
    # — парк получил бы агента без оверлея блокировки. Публикуем prebuilt ниже.
    for pair in "windows amd64" "linux amd64" "linux arm64"; do
      # shellcheck disable=SC2086
      set -- $pair; OS=$1; ARCH=$2
      echo "  → $OS/$ARCH"

      # Windows требует того же, что и `make build-win`, иначе парк получит битый агент:
      #   * .syso с манифестом Common Controls — без него трей на lxn/walk падает;
      #   * -H windowsgui — иначе трей в юзер-сессии открывает консольное окно,
      #     закрытие которого убивает агента;
      #   * числовой PE-VERSIONINFO — по нему Windows Installer решает перезапись exe.
      # .syso в .gitignore (версионный артефакт), в клоне его нет — генерим здесь.
      EXTRA_LDFLAGS=""
      if [ "$OS" = windows ]; then
        go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.7.0 \
          -64 -arm=false -o cmd/agent/rsrc_windows_amd64.syso \
          -manifest cmd/agent/agent.manifest \
          -ver-major "$WV_MAJ" -ver-minor "$WV_MIN" -ver-patch "$WV_PAT" -ver-build 0 \
          -product-ver-major "$WV_MAJ" -product-ver-minor "$WV_MIN" -product-ver-patch "$WV_PAT" -product-ver-build 0 \
          -file-version "${WINVER}.0" -product-version "${WINVER}" \
          -company RoutineOps -product-name "RoutineOps Agent" -description "RoutineOps Agent" \
          -internal-name RoutineOps-agent -original-name RoutineOps-agent.exe \
          cmd/agent/versioninfo.json
        EXTRA_LDFLAGS="-H windowsgui"
      fi

      # Бинари ДЖЕНЕРИК (без -X main.releasePubKey) — ровно как в install.sh:122.
      # Вшитый ключ АВТОРИТЕТНЕЕ полученного при enroll (resolveUpdatePubKeyB64), поэтому
      # раньше каждый деплой раздавал парку deployment-specific агентов: универсальный MSI
      # переставал быть универсальным, а при потере приватника пропадал единственный путь
      # восстановления (ре-энролл с новым ключом — вшитый бы его перебил).
      # Ключ self-update агент берёт из enroll-ответа: сервер отдаёт RELEASE_PUBKEY из .env.prod.
      GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${V} ${EXTRA_LDFLAGS}" \
        -o /tmp/agent_${OS}_${ARCH} ./cmd/agent

      # Убираем сразу: .syso линкуется в ЛЮБУЮ windows-сборку, и root-овладелец
      # файла в примонтированном рабочем каталоге мешал бы `make` у деплойера.
      if [ "$OS" = windows ]; then rm -f cmd/agent/rsrc_windows_amd64.syso; fi

      go run ./cmd/publish-release -binary /tmp/agent_${OS}_${ARCH} \
        -version "v${V}" -os "$OS" -arch "$ARCH" -key release_ed25519.pem
    done

    # macOS: prebuilt из репо (собран мейнтейнером на маке с cgo), подписываем его
    # ключом ЭТОГО деплойера. Сборка и подпись развязаны — publish-release берёт
    # любой файл. sha256 сверяем до подписи: подписать битый бинарь = раздать его.
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
      echo "  ⚠ darwin/arm64: $PREBUILT отсутствует — macOS-релиз НЕ опубликован."
      echo "    Маки останутся на текущей версии. Собрать: make pkg-mac-native НА маке."
    fi

    # Обновляем канонические инсталляторы (releases/RoutineOps-agent.{msi,pkg} → кнопки
    # "Скачать" в UI) ЗДЕСЬ, в контейнере: releases/ root-owned после publish-release,
    # host-side cp упал бы Permission denied. umask контейнера 022 → 644 (читаемо сервером).
    # Раньше update.sh их НЕ обновлял → UI отдавал старый инсталлятор до ручного sudo cp.
    [ -f build/msi/RoutineOps-agent.msi ] && { cp build/msi/RoutineOps-agent.msi releases/RoutineOps-agent.msi; echo "  MSI → releases/RoutineOps-agent.msi обновлён"; }
    [ -f build/pkg/RoutineOps-agent.pkg ] && { cp build/pkg/RoutineOps-agent.pkg releases/RoutineOps-agent.pkg; echo "  PKG → releases/RoutineOps-agent.pkg обновлён"; }
  '

echo ""
echo "Готово. Сервер на v${VERSION}; парк подтянет агентов self-update'ом за <interval>."
echo "Откат сервера: git checkout <старый-tag> && ${DC} -f docker-compose.prod.yml up -d --build"
echo "Откат БД (при несовместимости схемы): docker exec -i \$(${DC} -f docker-compose.prod.yml ps -q postgres) \\"
echo "  pg_restore -U mdm -d mdm --clean --if-exists < backups/<файл>.dump"
echo "Агенты назад не даунгрейдятся — битый релиз чинится версией ВПЕРЁД (vX.Y.Z+1)."
