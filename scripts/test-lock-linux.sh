#!/usr/bin/env bash
# Прогон экрана блокировки Linux против НАСТОЯЩЕГО X-сервера (Xvfb в контейнере).
#
# Зачем отдельный стенд: юнит-тесты покрывают разбор ввода и выбор сессии, но не
# отвечают на главный вопрос — «замок реально перекрыл экран и запер ввод?». Первый же
# прогон этого скрипта нашёл два дефекта, которые сборка и юниты пропускали: замок
# рисовал текст шрифтом без кириллицы (ряд пустых квадратов) и мерил заголовок одним
# шрифтом, а рисовал другим (заголовок уезжал влево мелким кеглем).
#
# Требует docker. Архитектура образа = архитектура машины: агент собирается под неё же.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="$REPO_ROOT/build/test/lock-linux"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

: "${LOCK_PASSWORD:=secret123}"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64 | aarch64) GOARCH=arm64 ;;
  x86_64 | amd64) GOARCH=amd64 ;;
  *)
    echo "неизвестная архитектура $ARCH" >&2
    exit 1
    ;;
esac

echo "== сборка агента (linux/$GOARCH) =="
cd "$REPO_ROOT"
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -trimpath -o "$WORK/agent" ./cmd/agent

echo "== bcrypt-хеш тестового пароля =="
LOCK_HASH="$(go run ./scripts/internal/bcrypthash "$LOCK_PASSWORD")"

echo "== сборка образа стенда =="
cp "$HARNESS/Dockerfile" "$HARNESS/run-in-container.sh" "$WORK/"
docker build -q -t routineops-locktest "$WORK" >/dev/null

echo "== прогон =="
OUT="$REPO_ROOT/build/test/lock-linux/out"
mkdir -p "$OUT"
docker run --rm \
  -e LOCK_HASH="$LOCK_HASH" \
  -e LOCK_PASSWORD="$LOCK_PASSWORD" \
  -v "$OUT:/harness/out" \
  routineops-locktest
echo "скриншоты и логи: $OUT"
