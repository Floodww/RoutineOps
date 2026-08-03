#!/usr/bin/env bash
#
# Реконсиляция ролей БД в .env.prod: сервер обязан ходить под mdm_app, миграции — под mdm.
#
# ЗАЧЕМ. Миграция 049 заводит роль mdm_app (NOSUPERUSER NOBYPASSRLS) именно затем, чтобы
# RLS FORCE из 046 реально изолировала тенантов. Но саму раскладку никто не применял:
# install.sh писал единственный DSN под ролью mdm — это POSTGRES_USER из
# docker-compose.prod.yml, то есть ВЛАДЕЛЕЦ БД, а он обходит RLS всегда. Роль mdm_app
# создавалась, права ей выдавались, и на этом всё заканчивалось: сервер ходил суперюзером,
# политики висели декорацией. Каждая свежая установка ехала с мультитенантностью, которую
# не защищает ничего. Прод чинили руками 30.07, в код это не вернулось — здесь возвращаем.
#
# ПОЧЕМУ ОТДЕЛЬНЫМ СКРИПТОМ. Точек входа две и они не вложены: первая установка идёт через
# install.sh, апгрейд — через update.sh (git pull + пересборка), и install.sh он не зовёт.
# Починка, живущая в одном из них, до второго пути не доезжает — ровно тот класс
# «молчаливого no-op», который в этом файле уже чинили для адреса сервера.
#
# ЧЕГО ЭТОТ СКРИПТ НЕ ДЕЛАЕТ. Он не ставит пароль роли mdm_app: до наката 049 роли ещё нет,
# а .env.prod пишется ДО подъёма стека. Пароль ставит scripts/migrate.sh — после того как
# миграции применены и роль существует. Здесь только раскладка DSN.
#
# Идемпотентен: раскладка уже правильная → ни одной правки, выход 0.
set -euo pipefail

ENV_FILE="${1:-.env.prod}"
[ -f "$ENV_FILE" ] || exit 0   # нечего чинить (первый прогон install.sh создаст сам)

# Значение переменной из .env.prod. Не `source`: файл может содержать пароли со
# спецсимволами, а нам нужно ровно одно поле без исполнения содержимого.
env_get() { sed -n "s/^$1=//p" "$ENV_FILE" | head -1; }

# upsert: заменяет строку целиком либо дописывает. chmod у вызывающего.
env_set() {
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  grep -v "^${key}=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

# Пользователь из DSN вида postgres[ql]://USER:PASS@host:port/db?params.
# Разбор через parameter expansion, а НЕ через sed: в BSD sed (macOS) нет `\?` в BRE,
# и регулярка молча не совпадала бы — раскладка на маке чинилась бы «в никуда».
# Поймано первым прогоном scripts/test-install-db-role.sh.
dsn_user() {
  local rest="$1"
  rest="${rest#postgresql://}"
  rest="${rest#postgres://}"
  [ "$rest" = "$1" ] && { printf ''; return; }   # не DSN известной схемы
  printf '%s' "${rest%%:*}"
}

DATABASE_DSN="$(env_get DATABASE_DSN)"
MIGRATION_DSN="$(env_get MIGRATION_DSN)"
PG_PASS="$(env_get POSTGRES_PASSWORD)"

[ -n "$DATABASE_DSN" ] || { echo "!! $ENV_FILE без DATABASE_DSN — пропускаю реконсиляцию ролей" >&2; exit 0; }

APP_USER="$(dsn_user "$DATABASE_DSN")"

# Раскладка уже разделена — не трогаем ничего. Это путь прода (чинили руками 30.07) и
# любой повторный прогон install.sh/update.sh.
if [ -n "$MIGRATION_DSN" ]; then
  if [ "$APP_USER" = "mdm" ]; then
    echo "!! DATABASE_DSN ходит под mdm (владелец БД, обходит RLS), хотя MIGRATION_DSN задан." >&2
    echo "   Изоляция тенантов не работает. Ожидается DATABASE_DSN под mdm_app." >&2
  fi
  exit 0
fi

case "$APP_USER" in
  mdm_app)
    # Сервер уже под app-ролью, но MIGRATION_DSN не записан. Так нельзя оставлять:
    # migrate.sh при отсутствии MIGRATION_DSN откатывается на DATABASE_DSN и пойдёт
    # катить DDL под ролью БЕЗ прав владельца — миграции упадут посреди наката.
    if [ -z "$PG_PASS" ]; then
      echo "ОШИБКА: DATABASE_DSN под mdm_app, но MIGRATION_DSN не задан, а POSTGRES_PASSWORD пуст." >&2
      echo "   Собрать MIGRATION_DSN не из чего. Допиши вручную:" >&2
      echo "   MIGRATION_DSN=postgres://mdm:<пароль_роли_mdm>@postgres:5432/mdm?sslmode=disable" >&2
      exit 1
    fi
    env_set MIGRATION_DSN "postgres://mdm:${PG_PASS}@postgres:5432/mdm?sslmode=disable"
    echo "MIGRATION_DSN добавлен (DDL под владельцем mdm; сервер остаётся под mdm_app)"
    ;;
  mdm)
    # Сломанная раскладка: сервер ходит владельцем БД. Разделяем.
    # Пароль app-роли — hex: он уходит и в URL DSN, и в SQL-литерал ALTER ROLE
    # (scripts/migrate.sh). Алфавит [0-9a-f] не требует ни percent-encoding, ни
    # экранирования кавычек — одна и та же строка безопасна в обоих контекстах.
    APP_PASS="$(openssl rand -hex 24)"
    env_set MIGRATION_DSN "$DATABASE_DSN"
    env_set DATABASE_DSN "postgres://mdm_app:${APP_PASS}@postgres:5432/mdm?sslmode=disable"
    echo "!! Раскладка ролей БД была сломана: сервер ходил под mdm (владелец, обходит RLS)."
    echo "   Разделено: сервер → mdm_app, миграции → mdm. Пароль роли поставит migrate."
    ;;
  *)
    # Внешний Postgres или собственная раскладка деплойера — не наше дело переписывать
    # чужие роли. Но сказать, что RLS может не действовать, обязаны.
    echo "!! DATABASE_DSN под ролью '${APP_USER:-неизвестно}' — нестандартная раскладка, не трогаю." >&2
    echo "   Убедись, что эта роль без SUPERUSER и без BYPASSRLS, иначе изоляция тенантов" >&2
    echo "   (RLS FORCE, миграция 046) не действует. Проверка:" >&2
    echo "   SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user;" >&2
    ;;
esac
