#!/bin/bash
# Регулярный бэкап инсталляции + ПРОВЕРКА восстановимости. Запускать по расписанию
# (cron/timer, см. docs/operations.md), не только при деплое: pg_dump внутри update.sh —
# это снимок перед миграциями, а не бэкап (нет апдейтов неделю = нет копии за неделю).
#
# Снимает три части, потому что дампа БД для восстановления НЕ ХВАТАЕТ:
#   db-<ts>.dump       — pg_dump -Fc, только данные и схема ОДНОЙ базы;
#   globals-<ts>.sql   — pg_dumpall --globals-only: роли и их пароли. В дамп базы они не
#                        входят вообще. Без них восстановленная БД поднимется, а сервер к
#                        ней не подключится: миграция 049 создаёт mdm_app БЕЗ пароля
#                        (задаётся руками), и на чистом кластере пароль взять неоткуда;
#   secrets-<ts>.tar.gz — certs/, release_ed25519.pem, .env.prod, license/, directory/.
#                        Всё gitignored: git clone не восстанавливает ни один секрет,
#                        а потеря release_ed25519.pem = переустановка агентов на парке.
#
# 🔴 Копия на том же диске — не бэкап. BACKUP_DIR выносится на отдельный том, а сам
# каталог обязан уезжать с хоста (rsync/объектное хранилище): дампы, роли и секреты лежат
# рядом с тем, от чьей гибели они страхуют.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077 # дампы, роли и секреты не world-readable

DC_FILE="${DC_FILE:-docker-compose.prod.yml}"
BACKUP_DIR="${BACKUP_DIR:-backups}"
KEEP="${KEEP:-14}" # сколько поколений каждого вида держать

if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi

PG=$($DC -f "$DC_FILE" ps -q postgres 2>/dev/null || true)
[ -n "$PG" ] || { echo "ОШИБКА: контейнер postgres не запущен ($DC_FILE)" >&2; exit 1; }

TS=$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
DUMP="$BACKUP_DIR/db-$TS.dump"
GLOBALS="$BACKUP_DIR/globals-$TS.sql"
SECRETS="$BACKUP_DIR/secrets-$TS.tar.gz"

echo "=== Бэкап $TS ==="

# 1. База и роли кластера.
docker exec "$PG" sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' >"$DUMP"
docker exec "$PG" sh -c 'pg_dumpall -U "$POSTGRES_USER" --globals-only' >"$GLOBALS"
echo "БД:    $DUMP ($(du -h "$DUMP" | cut -f1))"
echo "Роли:  $GLOBALS"

# 2. Секретный state. Отсутствующее пропускаем с предупреждением, а не молча: на Free
#    нет license/, без LDAP нет directory/ — но пропавший certs/ обязан быть виден.
present=()
for f in certs release_ed25519.pem .env.prod license directory; do
  if [ -e "$f" ]; then present+=("$f"); else echo "⚠ нет $f — в бэкап не попадёт"; fi
done
if [ ${#present[@]} -gt 0 ]; then
  tar czf "$SECRETS" "${present[@]}"
  echo "Секреты: $SECRETS (${present[*]})"
fi

# 3. ПРОВЕРКА ВОССТАНОВЛЕНИЯ. Непроверенный бэкап — это надежда, а не бэкап: битый или
#    усечённый дамп обнаруживается ровно в тот момент, когда он последняя копия.
#    Восстанавливаем в одноразовую БД ТОГО ЖЕ кластера и сверяем с живой.
#
#    ponytail: тот же кластер, поэтому роли и расширения уже на месте — проверка ловит
#    битый/неполный дамп, но не «на чистой машине не хватило роли». Полный прогон на
#    пустом хосте — процедура DR (docs/disaster-recovery.md §3б), она ручная и редкая.
CHECK_DB="restorecheck_$(date +%s)"
cleanup() { docker exec "$PG" sh -c 'dropdb -U "$POSTGRES_USER" --if-exists "$1"' _ "$CHECK_DB" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker exec "$PG" sh -c 'createdb -U "$POSTGRES_USER" "$1"' _ "$CHECK_DB"
docker exec -i "$PG" sh -c 'pg_restore -U "$POSTGRES_USER" -d "$1" --no-owner --exit-on-error' _ "$CHECK_DB" <"$DUMP"

q() { docker exec "$PG" sh -c 'psql -U "$POSTGRES_USER" -d "$1" -tAc "$2"' _ "$1" "$2" | tr -d '[:space:]'; }
live_db=$(docker exec "$PG" sh -c 'echo "$POSTGRES_DB"' | tr -d '[:space:]')

live_mig=$(q "$live_db" "SELECT COALESCE(max(version), '')  FROM schema_migrations")
rest_mig=$(q "$CHECK_DB" "SELECT COALESCE(max(version), '') FROM schema_migrations")
rest_users=$(q "$CHECK_DB" "SELECT count(*) FROM users")
rest_tables=$(q "$CHECK_DB" "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")

# Сверяем то, что между дампом и проверкой не меняется. Счётчики журнала или устройств
# для этого не годятся: они растут сами по себе, и гейт мигал бы.
[ -n "$rest_mig" ] && [ "$rest_mig" = "$live_mig" ] ||
  { echo "ОШИБКА: миграции в копии ($rest_mig) ≠ живым ($live_mig)" >&2; exit 1; }
[ "${rest_users:-0}" -gt 0 ] ||
  { echo "ОШИБКА: в восстановленной БД ноль пользователей — войти будет некому" >&2; exit 1; }
[ "${rest_tables:-0}" -gt 0 ] ||
  { echo "ОШИБКА: в восстановленной БД нет таблиц" >&2; exit 1; }
echo "Проверка: восстановлено, миграции $rest_mig, таблиц $rest_tables, пользователей $rest_users"

# 4. Ротация. Отдельно по каждому виду: у трёх файлов одного поколения общий ts, но
#    секреты могут не сняться (см. выше), и общий счётчик тогда съезжал бы.
for pat in 'db-*.dump' 'globals-*.sql' 'secrets-*.tar.gz'; do
  # shellcheck disable=SC2012 # имена файлов наши, ts в имени — без пробелов и переводов строк
  ls -1t "$BACKUP_DIR"/$pat 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f "$old" && echo "ротация: удалён $old"
  done
done

echo "=== Готово. Поколений: $(ls -1 "$BACKUP_DIR"/db-*.dump 2>/dev/null | wc -l), каталог $(du -sh "$BACKUP_DIR" | cut -f1) ==="
