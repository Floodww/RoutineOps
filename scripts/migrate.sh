#!/bin/sh
# Идемпотентный накат миграций для self-hosted. Работает и на первой установке
# (пустая БД), и на апгрейде (существующая БД) — единый путь вместо initdb.d
# (initdb.d выполняется ТОЛЬКО при создании пустой БД → на апгрейде новые .sql
# не накатывались). Запускается как one-shot compose-сервис `migrate` ДО `server`
# (server ждёт service_completed_successfully → fail-closed: миграция упала =>
# сервер не поднимется на новой схеме кода со старой БД).
#
# Требует DATABASE_DSN в окружении (env_file: .env.prod). Миграции монтируются
# в /migrations (:ro). Каждая версия применяется в ОДНОЙ транзакции вместе с
# записью факта в schema_migrations — атомарно (все миграции 001..NNN проверены:
# нет CREATE INDEX CONCURRENTLY / явных BEGIN|COMMIT, т.е. --single-transaction безопасен).
#
# Для СУЩЕСТВУЮЩИХ инсталляций, где миграции уже накатаны вручную, СНАЧАЛА один раз
# прогнать scripts/migrate-backfill.sh (засидит schema_migrations без повторного
# выполнения). Миграции 001..NNN НЕ идемпотентны (CREATE TABLE без IF NOT EXISTS),
# поэтому повторный накат УПАЛ БЫ — ниже стоит GUARD, отказывающийся работать на
# populated-БД без schema_migrations (защита от разрушительного наката).
set -e

: "${DATABASE_DSN:?DATABASE_DSN не задан (ожидается из .env.prod)}"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-/migrations}"

# 🔴 FAIL-CLOSED: пустой или неверно смонтированный каталог миграций. Раньше цикл шёл по
# `$(ls "$DIR"/*.sql)`: под `set -e` падение подстановки в списке for НЕ считается упавшей
# командой, поэтому опечатка в монтировании (/migration вместо /migrations) давала пустой
# список, «migrations up to date» и EXIT=0. Compose ждёт service_completed_successfully →
# сервер поднимался на ПУСТОЙ схеме, то есть fail-closed из шапки не срабатывал ровно там,
# где он единственная защита. Проверяем ДО обращения к БД: нечего катить — это отказ.
set -- "$MIGRATIONS_DIR"/*.sql
if [ ! -e "$1" ]; then
  echo "ОШИБКА: в $MIGRATIONS_DIR нет ни одного .sql — каталог пуст или смонтирован не тот." >&2
  echo "Проверь volume миграций в docker-compose (ожидается ./migrations:/migrations:ro)." >&2
  exit 1
fi

# GUARD: миграции 001..NNN НЕ идемпотентны (CREATE TABLE без IF NOT EXISTS). Если БД
# уже содержит таблицы приложения, но нет schema_migrations — это СУЩЕСТВУЮЩАЯ
# инсталляция с ручными миграциями. Слепой накат 001.. упадёт на "relation already
# exists" → migrate-сервис exit≠0 → server не стартует (а старый уже снесён up --build).
# Fail-safe: отказываемся и просим один раз прогнать backfill (fresh-БД проходит: 0 таблиц).
sm_exists=$(psql "$DATABASE_DSN" -tA -c "SELECT to_regclass('public.schema_migrations') IS NOT NULL")
if [ "$sm_exists" != "t" ]; then
  other=$(psql "$DATABASE_DSN" -tA -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
  if [ "${other:-0}" != "0" ]; then
    echo "ОШИБКА: БД содержит таблицы, но нет schema_migrations." >&2
    echo "Похоже на существующую инсталляцию с миграциями, накатанными вручную." >&2
    echo "Сначала ОДИН РАЗ прогони scripts/migrate-backfill.sh (BACKFILL_UPTO=<последняя_накатанная>)," >&2
    echo "см. docs/self-hosted-deploy.md — затем повтори апдейт." >&2
    exit 1
  fi
fi

psql "$DATABASE_DSN" -v ON_ERROR_STOP=1 -c '
  CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );'

# Порядок даёт сам глоб (лексикографический, префиксы 001..NNN), `ls | sort` не нужен —
# и заодно исчезает разбиение по пробелам в путях.
for f in "$@"; do
  v=$(basename "$f")
  applied=$(psql "$DATABASE_DSN" -tA -c "SELECT 1 FROM schema_migrations WHERE version='$v'")
  if [ "$applied" = "1" ]; then
    echo "skip  $v (уже применена)"
    continue
  fi
  echo "apply $v"
  psql "$DATABASE_DSN" -v ON_ERROR_STOP=1 --single-transaction \
    -f "$f" \
    -c "INSERT INTO schema_migrations(version) VALUES ('$v')"
done

echo "migrations up to date"
