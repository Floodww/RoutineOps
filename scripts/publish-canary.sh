#!/usr/bin/env bash
#
# publish-canary.sh — опубликовать ОДИН уже собранный бинарь агента в канал (beta/stable).
#
# Зачем отдельный скрипт, если есть cmd/publish-release. Затем, что вызвать его на проде
# «просто go run» НЕЛЬЗЯ, и это не теория:
#
#   go: errors parsing go.mod:
#   /home/admin/RoutineOps/go.mod:3: invalid go version '1.26.4': must match format 1.23
#
# Системный Go на прод-сервере старше 1.21 и трёхкомпонентную директиву `go 1.26.4` не
# понимает. Весь деплой этого и не требует: install.sh и update.sh запускают сборку и
# публикацию В КОНТЕЙНЕРЕ (golang:1.26-alpine), поэтому хостовый Go на проде не нужен
# вовсе — и ставить его не надо.
#
# Ручная публикация канарейки была единственным местом, где штатной обёртки не существовало:
# команду приходилось собирать по памяти, и первый же вызов упирался в хостовый Go. Это тот
# же класс, что «канал есть, а пути к нему нет» — механизм, к которому не ведёт исполнимая
# команда, в поле не существует.
#
# Запускать ИЗ КАТАЛОГА ДЕПЛОЯ (там, где .env.prod и docker-compose.prod.yml).
#
# Пример:
#   ./scripts/publish-canary.sh -binary agent_windows_amd64_v2.6.7-enterprise.exe \
#       -version v2.6.7 -os windows -arch amd64 -channel beta
set -euo pipefail

BINARY=""; VERSION=""; OSNAME=""; ARCH=""; CHANNEL="beta"; KEY="release_ed25519.pem"

while [ $# -gt 0 ]; do
  case "$1" in
    -binary)  BINARY=$2; shift 2 ;;
    -version) VERSION=$2; shift 2 ;;
    -os)      OSNAME=$2; shift 2 ;;
    -arch)    ARCH=$2; shift 2 ;;
    -channel) CHANNEL=$2; shift 2 ;;
    -key)     KEY=$2; shift 2 ;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# //'; exit 0 ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

for req in BINARY VERSION OSNAME ARCH; do
  eval "v=\${$req}"
  [ -n "$v" ] || { echo "ОШИБКА: обязательны -binary -version -os -arch" >&2; exit 2; }
done

case "$CHANNEL" in
  stable|beta) ;;
  *) echo "ОШИБКА: канал '$CHANNEL' — ожидается stable|beta" >&2; exit 2 ;;
esac

# Проверки до докера: сообщение «файла нет» дешевле, чем то же самое из контейнера с
# путями, которых на хосте не видно.
if [ ! -f "$BINARY" ]; then
  # Отказ называет и то, ЧЕГО нет, и то, ОТКУДА это берут: канареечные сборки лежат вне
  # git (гейт публичного среза не пускает enterprise-бинари в дерево), поэтому «положите
  # файл рядом» без адреса — совет, который нечем исполнить.
  echo "ОШИБКА: не найден бинарь $BINARY в каталоге деплоя ($(pwd))." >&2
  echo "" >&2
  echo "Канареечные сборки лежат в приватных релизах enterprise-репозитория (в git их нет" >&2
  echo "by design). Забрать в текущий каталог:" >&2
  echo "" >&2
  echo "  gh release download <тег> --repo Floodww/RoutineOps-Enterprise \\" >&2
  echo "     -p '$(basename "$BINARY")*'" >&2
  echo "" >&2
  echo "Без gh — через API (нужен токен с доступом к приватному репозиторию):" >&2
  echo "  curl -L -H \"Authorization: Bearer \$GH_TOKEN\" -H 'Accept: application/octet-stream' \\" >&2
  echo "    https://api.github.com/repos/Floodww/RoutineOps-Enterprise/releases/assets/<ID> \\" >&2
  echo "    -o '$(basename "$BINARY")'" >&2
  echo "" >&2
  echo "После скачивания ОБЯЗАТЕЛЬНО сверить сумму с .sha256 из того же релиза:" >&2
  echo "  sha256sum -c '$(basename "$BINARY").sha256'" >&2
  exit 1
fi
[ -f "$KEY" ]    || { echo "ОШИБКА: не найден ключ подписи $KEY" >&2; exit 1; }

# 🔴 Файл есть — но ТОТ ЛИ. Полевой случай 10.08: бинарь качали через API с пустым токеном,
# GitHub ответил 112 байтами {"message":"Bad credentials"}, curl положил их под именем
# агента, и публикация подписала этот JSON релизным ключом. Дальше все защиты работают
# против нас — sha сойдётся, подпись валидна, агент заменит себя мусором.
SIZE=$(wc -c < "$BINARY" | tr -d ' ')
if [ "$SIZE" -lt 1048576 ]; then
  echo "ОШИБКА: $BINARY весит $SIZE байт — агент столько не весит." >&2
  echo "  Первые байты: $(head -c 60 "$BINARY" | tr -d '\0' | tr '\n' ' ')" >&2
  echo "  Похоже, скачалась ошибка API или HTML вместо бинаря. Проверьте токен и повторите." >&2
  exit 1
fi

# Если рядом лежит файл суммы из релиза — сверяем ОБЯЗАТЕЛЬНО. Доставка проверяется
# round-trip'ом: «скачалось без ошибки» и «скачалось то же самое» — разные утверждения.
if [ -f "$BINARY.sha256" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$BINARY.sha256" >/dev/null 2>&1 || {
      echo "ОШИБКА: sha256 не сошлась с $BINARY.sha256 — файл повреждён или подменён." >&2
      exit 1
    }
    echo "   sha256 сверена с $BINARY.sha256"
  fi
else
  echo "   ⚠ рядом нет $BINARY.sha256 — сверить нечем; сумму проверит гейт формата в publish-release" >&2
fi
[ -f .env.prod ] || { echo "ОШИБКА: нет .env.prod — запускать из каталога деплоя" >&2; exit 1; }

if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi

set -a; . ./.env.prod; set +a

PG=$($DC -f docker-compose.prod.yml ps -q postgres)
[ -n "$PG" ] || { echo "ОШИБКА: контейнер postgres не запущен — публиковать некуда" >&2; exit 1; }
NET=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$PG" | awk '{print $1}')

echo "== публикация $VERSION ($OSNAME/$ARCH) в канал $CHANNEL =="
[ "$CHANNEL" = stable ] || echo "   канареечная выкатка: парк на stable не двигается, releases/ не трогается"

docker run --rm --network "$NET" -v "$(pwd)":/app -w /app \
  -e DATABASE_DSN="$DATABASE_DSN" \
  golang:1.26-alpine \
  go run ./cmd/publish-release \
    -binary "$BINARY" -version "$VERSION" -os "$OSNAME" -arch "$ARCH" \
    -key "$KEY" -channel "$CHANNEL"

echo ""
echo "Проверка (должна отдать 200):"
echo "  curl -sk -o /dev/null -w '%{http_code}\\n' https://<адрес>/downloads/agent_${OSNAME}_${ARCH}_${VERSION}"
