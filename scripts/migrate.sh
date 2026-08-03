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
# DDL-миграции катятся owner'ом (mdm). Приложение ходит под mdm_app (049).
# MIGRATION_DSN — явный DSN владельца; если не задан — fallback на DATABASE_DSN
# (обратная совместимость с инсталляциями до разделения ролей).
MIGRATION_DSN="${MIGRATION_DSN:-$DATABASE_DSN}"

# 🔴 FAIL-CLOSED: fallback выше безопасен ровно до тех пор, пока DATABASE_DSN — это DSN
# владельца. Как только сервер переведён на mdm_app (роль без прав на DDL), тот же fallback
# уводит накат под неё: CREATE TABLE упадёт с permission denied ПОСРЕДИ прогона, часть
# версий уже будет записана в schema_migrations, и разбирать это придётся руками на живой
# БД. Отказываемся до первой команды.
# Разбор DSN — parameter expansion, а не sed: реализации sed расходятся по BRE (в BSD sed
# нет `\?`), и промах регулярки здесь означал бы молча пропущенный гейт.
dsn_user() {
  rest="${1#postgresql://}"; rest="${rest#postgres://}"
  [ "$rest" = "$1" ] && { printf ''; return; }
  printf '%s' "${rest%%:*}"
}
dsn_pass() {
  rest="${1#postgresql://}"; rest="${rest#postgres://}"
  [ "$rest" = "$1" ] && { printf ''; return; }
  rest="${rest#*:}"          # отрезаем логин
  printf '%s' "${rest%@*}"   # и всё от ПОСЛЕДНЕГО '@' (у хоста '@' не бывает)
}
app_dsn_user=$(dsn_user "$DATABASE_DSN")
if [ "$MIGRATION_DSN" = "$DATABASE_DSN" ] && [ "$app_dsn_user" = "mdm_app" ]; then
  echo "ОШИБКА: DATABASE_DSN ходит под mdm_app (роль приложения, без прав на DDL)," >&2
  echo "        а MIGRATION_DSN не задан — миграции покатились бы под ней и упали посреди наката." >&2
  echo "        Добавь в .env.prod DSN владельца:" >&2
  echo "        MIGRATION_DSN=postgres://mdm:<пароль_роли_mdm>@postgres:5432/mdm?sslmode=disable" >&2
  echo "        Либо прогони scripts/env-db-roles.sh — он соберёт его из POSTGRES_PASSWORD." >&2
  exit 1
fi
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
sm_exists=$(psql "$MIGRATION_DSN" -tA -c "SELECT to_regclass('public.schema_migrations') IS NOT NULL")
if [ "$sm_exists" != "t" ]; then
  other=$(psql "$MIGRATION_DSN" -tA -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
  if [ "${other:-0}" != "0" ]; then
    echo "ОШИБКА: БД содержит таблицы, но нет schema_migrations." >&2
    echo "Похоже на существующую инсталляцию с миграциями, накатанными вручную." >&2
    echo "Сначала ОДИН РАЗ прогони scripts/migrate-backfill.sh (BACKFILL_UPTO=<последняя_накатанная>)," >&2
    echo "см. docs/self-hosted-deploy.md — затем повтори апдейт." >&2
    exit 1
  fi
fi

psql "$MIGRATION_DSN" -v ON_ERROR_STOP=1 -c '
  CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );'

# Порядок даёт сам глоб (лексикографический, префиксы 001..NNN), `ls | sort` не нужен —
# и заодно исчезает разбиение по пробелам в путях.
for f in "$@"; do
  v=$(basename "$f")
  applied=$(psql "$MIGRATION_DSN" -tA -c "SELECT 1 FROM schema_migrations WHERE version='$v'")
  if [ "$applied" = "1" ]; then
    echo "skip  $v (уже применена)"
    continue
  fi
  echo "apply $v"
  psql "$MIGRATION_DSN" -v ON_ERROR_STOP=1 --single-transaction \
    -f "$f" \
    -c "INSERT INTO schema_migrations(version) VALUES ('$v')"
done

echo "migrations up to date"

# --- пароль роли приложения (049) -------------------------------------------------
#
# 049 создаёт mdm_app БЕЗ пароля намеренно: секрет в .sql утёк бы через git и публичный
# срез. Значит поставить его должен кто-то после наката — и это обязано быть здесь, а не
# в install.sh: апгрейд идёт через update.sh, install.sh он не зовёт, а роль появляется
# ровно в момент, когда 049 применена. Порядок гарантирует compose: server ждёт
# service_completed_successfully от migrate.
#
# Источник пароля — сам DATABASE_DSN, а не отдельная переменная. Так рассинхрон
# «роли поставили один пароль, сервер идёт с другим» невозможен по построению.
mig_dsn_user=$(dsn_user "$MIGRATION_DSN")
if [ -n "$app_dsn_user" ] && [ "$app_dsn_user" != "$mig_dsn_user" ]; then
  # Уже логинится с этим паролем — не трогаем. Иначе каждый прогон migrate перетирал бы
  # пароль, выставленный деплойером вручную (наш прод чинили именно руками 30.07).
  if PGCONNECT_TIMEOUT=5 psql "$DATABASE_DSN" -tAc 'SELECT 1' >/dev/null 2>&1; then
    echo "роль $app_dsn_user: пароль актуален"
  else
    app_pass=$(dsn_pass "$DATABASE_DSN")
    if [ -z "$app_pass" ]; then
      echo "ОШИБКА: в DATABASE_DSN нет пароля для роли $app_dsn_user — сервер не подключится." >&2
      exit 1
    fi
    # Одинарные кавычки в SQL-литерале удваиваются. Пароль, сгенерированный
    # scripts/env-db-roles.sh, — hex и этого не требует; экранирование здесь ради
    # паролей, заданных деплойером руками.
    esc=$(printf '%s' "$app_pass" | sed "s/'/''/g")
    psql "$MIGRATION_DSN" -v ON_ERROR_STOP=1 -c "ALTER ROLE \"$app_dsn_user\" PASSWORD '$esc'" >/dev/null
    echo "роль $app_dsn_user: пароль установлен"
  fi
fi

# --- гейт изоляции тенантов -------------------------------------------------------
#
# Смысл разделения ролей — чтобы RLS FORCE (046) реально изолировала тенантов. Роль с
# SUPERUSER или BYPASSRLS обходит политики всегда, и тогда мультитенантность не защищена
# ничем, хотя все политики на месте и любая проверка «политики есть» зелёная.
#
# Предупреждение, а не отказ: бывает внешний Postgres и собственная раскладка ролей у
# деплойера, и валить ему сервер мы права не имеем. Отказ на этом стоит в тесте
# (scripts/test-install-db-role.sh), где раскладка наша и известна.
if [ -n "$app_dsn_user" ]; then
  priv=$(psql "$MIGRATION_DSN" -tA -c \
    "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = '$app_dsn_user'" 2>/dev/null || echo "")
  if [ "$priv" = "t" ]; then
    echo "!! ВНИМАНИЕ: сервер ходит в БД под ролью '$app_dsn_user' с SUPERUSER или BYPASSRLS." >&2
    echo "   RLS FORCE её не удержит — изоляция тенантов НЕ действует, политики декоративны." >&2
    echo "   Починка: scripts/env-db-roles.sh (разделит роли), затем перезапуск стека." >&2
  fi
fi
