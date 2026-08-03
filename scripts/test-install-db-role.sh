#!/usr/bin/env bash
#
# Регрессия: свежая установка обязана ходить в БД под ролью БЕЗ SUPERUSER и BYPASSRLS.
#
# ЧТО ЛОВИМ. Миграция 049 заводит роль mdm_app ради того, чтобы RLS FORCE (046) реально
# изолировала тенантов, но install.sh про неё не знал и писал единственный DSN под mdm —
# POSTGRES_USER из docker-compose.prod.yml, то есть владельца БД, который в образе postgres
# является суперюзером. Роль создавалась, права выдавались, политики висели на всех
# таблицах — и не работали. Каждая свежая установка ехала с мультитенантностью, которую не
# защищало ничего.
#
# ПОЧЕМУ НЕ ПРОВЕРКА «ПОЛИТИКИ НА МЕСТЕ». Она зелёная и на сломанном стенде: 046
# накатывается одинаково в обоих случаях. Отличает рабочую изоляцию от декоративной ровно
# одно — привилегии роли, под которой ходит сервер. Поэтому тест проверяет их, а сверх того
# показывает последствие живьём: под app-ролью чужой тенант не виден, под владельцем — виден.
#
# Проверяются ОБА исхода, иначе гейт не считается проверенным:
#   A. install.sh пишет разделённую раскладку (сервер → mdm_app, DDL → mdm);
#   B. после наката миграций роль сервера логинится и у неё rolsuper=f, rolbypassrls=f;
#   C. изоляция действует: mdm_app видит только свой тенант, а владелец — оба (это и есть
#      дефект, который мы закрыли);
#   D. КРАСНЫЙ: возвращаем DATABASE_DSN под владельца — проверка B обязана упасть;
#   E. КРАСНЫЙ: убираем MIGRATION_DSN при сервере на mdm_app — migrate.sh обязан отказаться
#      катить DDL под ролью без прав, а не падать посреди наката.
#
# Нужен docker (поднимается настоящий postgres:16-alpine — psql на хосте не требуется).
# Запуск: bash scripts/test-install-db-role.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
SFX="$$"
NET="routineops-dbrole-$SFX"
PG="routineops-dbrole-pg-$SFX"
PGIMG="postgres:16-alpine"

cleanup() {
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "SKIP: docker не установлен"; exit 0; }

fail() { echo "  ✗ $1" >&2; exit 1; }
ok()   { echo "  ✓ $1"; }

# psql всегда в контейнере: на хосте его может не быть, а внутри сети резолвится алиас
# `postgres` — ровно тот хост, что зашит в DSN из .env.prod.
psql_net() { docker run --rm --network "$NET" "$PGIMG" psql "$@"; }

# ---------------------------------------------------------------------------
# A. install.sh создаёт разделённую раскладку
# ---------------------------------------------------------------------------
echo "== A. install.sh: раскладка ролей в .env.prod =="

mkdir -p "$WORK/scripts" "$WORK/bin"
cp "$REPO/install.sh" "$REPO/VERSION" "$REPO/AGENT_VERSION" "$REPO/docker-compose.prod.yml" "$WORK/"
cp "$REPO/scripts/gen-certs.sh" "$REPO/scripts/env-db-roles.sh" "$WORK/scripts/"

# Заглушки: install.sh поднимает стек и собирает агентов, а нам нужен только .env.prod.
# stdout заглушки docker держим чистым — install.sh читает вывод `compose ps -q` в переменную.
cat >"$WORK/bin/docker" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$WORK/docker.log"
exit 0
EOF
printf '#!/bin/sh\necho 192.0.2.5\n' >"$WORK/bin/hostname"
chmod +x "$WORK/bin/docker" "$WORK/bin/hostname"

cd "$WORK"
{ echo "PUBLIC_ADDR=203.0.113.10"      # TEST-NET-3 (RFC 5737)
  echo "ADMIN_EMAIL=admin@example.com"
  echo "ADMIN_PASSWORD=S3cure-pass!"
} >install.env

PATH="$WORK/bin:$PATH" bash install.sh >"$WORK/install.log" 2>&1 || {
  tail -20 "$WORK/install.log" >&2; fail "install.sh упал"
}

env_get() { sed -n "s/^$1=//p" "$WORK/.env.prod" | head -1; }
DATABASE_DSN="$(env_get DATABASE_DSN)"
MIGRATION_DSN="$(env_get MIGRATION_DSN)"
PG_PASS="$(env_get POSTGRES_PASSWORD)"

case "$DATABASE_DSN" in
  postgres://mdm_app:*) ok "DATABASE_DSN под mdm_app" ;;
  *) fail "DATABASE_DSN не под mdm_app: ${DATABASE_DSN%%@*}@..." ;;
esac
case "$MIGRATION_DSN" in
  postgres://mdm:*) ok "MIGRATION_DSN под владельцем mdm" ;;
  *) fail "MIGRATION_DSN отсутствует или не под mdm" ;;
esac
[ "${DATABASE_DSN#*mdm_app:}" != "${MIGRATION_DSN#*mdm:}" ] \
  && ok "пароли ролей различны" || fail "у mdm_app и mdm один пароль"

# ---------------------------------------------------------------------------
# Живая БД + накат миграций (ровно как это делает compose-сервис migrate)
# ---------------------------------------------------------------------------
echo "== B. живой Postgres: накат миграций и вход под ролью сервера =="

docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" --network-alias postgres \
  -e POSTGRES_DB=mdm -e POSTGRES_USER=mdm -e POSTGRES_PASSWORD="$PG_PASS" \
  "$PGIMG" >/dev/null

for _ in $(seq 1 30); do
  docker exec "$PG" pg_isready -U mdm >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$PG" pg_isready -U mdm >/dev/null 2>&1 || fail "postgres не поднялся"

run_migrate() { # $1 — путь к env-файлу
  docker run --rm --network "$NET" --env-file "$1" \
    -v "$REPO/migrations:/migrations:ro" \
    -v "$REPO/scripts/migrate.sh:/migrate.sh:ro" \
    "$PGIMG" sh /migrate.sh
}

run_migrate "$WORK/.env.prod" >"$WORK/migrate.log" 2>&1 || {
  tail -20 "$WORK/migrate.log" >&2; fail "migrate.sh упал"
}
grep -q "migrations up to date" "$WORK/migrate.log" || fail "миграции не доехали"
ok "миграции накачены под владельцем"

# Пароль mdm_app ставит migrate.sh — до него роль существует, но войти под ней нельзя.
psql_net "$DATABASE_DSN" -tAc 'SELECT 1' >/dev/null 2>&1 \
  && ok "сервер логинится под mdm_app" || fail "вход под mdm_app не работает (пароль не поставлен)"

# -tA без каста: psql печатает boolean как t/f. Через ::text было бы true/false —
# сравнение молча не совпало бы ни с чем, и «привилегированная роль» показывалась бы на
# исправной раскладке (поймано первым же прогоном).
priv="$(psql_net "$DATABASE_DSN" -tAc \
  "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")"
priv="$(printf '%s' "$priv" | tr -d '[:space:]')"
[ "$priv" = "f|f" ] && ok "роль сервера: rolsuper=f, rolbypassrls=f" \
                    || fail "роль сервера привилегированная (rolsuper|rolbypassrls)=($priv)"

# ---------------------------------------------------------------------------
# C. Изоляция действует — и видно, чем именно она отличалась от сломанной
# ---------------------------------------------------------------------------
echo "== C. RLS: чужой тенант не виден серверу и виден владельцу =="

T1=11111111-1111-4111-8111-111111111111
T2=22222222-2222-4222-8222-222222222222
psql_net "$MIGRATION_DSN" -v ON_ERROR_STOP=1 -q -c "
  INSERT INTO tenants (id, name) VALUES ('$T1','T1'), ('$T2','T2') ON CONFLICT DO NOTHING;
  INSERT INTO device_groups (tenant_id, name) VALUES ('$T1','g1'), ('$T2','g2');" >/dev/null

seen_app="$(psql_net "$DATABASE_DSN" -tAc \
  "SET routineops.tenant_id = '$T1'; SELECT count(*) FROM device_groups" | tail -1 | tr -d '[:space:]')"
[ "$seen_app" = "1" ] && ok "под mdm_app виден только свой тенант ($seen_app из 2)" \
                      || fail "под mdm_app видно строк: $seen_app (ожидалась 1) — RLS не изолирует"

seen_owner="$(psql_net "$MIGRATION_DSN" -tAc \
  "SET routineops.tenant_id = '$T1'; SELECT count(*) FROM device_groups" | tail -1 | tr -d '[:space:]')"
[ "$seen_owner" = "2" ] && ok "под владельцем видны оба тенанта ($seen_owner) — это и был дефект" \
                        || echo "  · под владельцем видно $seen_owner (ожидалось 2) — проверь FORCE RLS"

# ---------------------------------------------------------------------------
# D. КРАСНЫЙ: возвращаем сломанную раскладку — гейт обязан сработать
# ---------------------------------------------------------------------------
echo "== D. красный исход: сервер под владельцем БД =="

grep -v '^DATABASE_DSN=' "$WORK/.env.prod" >"$WORK/.env.broken"
echo "DATABASE_DSN=$MIGRATION_DSN" >>"$WORK/.env.broken"
broken_dsn="$MIGRATION_DSN"

bad_priv="$(psql_net "$broken_dsn" -tAc \
  "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")"
bad_priv="$(printf '%s' "$bad_priv" | tr -d '[:space:]')"
[ "$bad_priv" = "f|f" ] && fail "сломанная раскладка прошла проверку привилегий — гейт слепой" \
                        || ok "проверка привилегий краснеет: (rolsuper|rolbypassrls)=($bad_priv)"

bad_seen="$(psql_net "$broken_dsn" -tAc \
  "SET routineops.tenant_id = '$T1'; SELECT count(*) FROM device_groups" | tail -1 | tr -d '[:space:]')"
[ "$bad_seen" = "1" ] && fail "владелец не должен уважать RLS — тест изоляции ничего не доказывает" \
                      || ok "под владельцем изоляции нет ($bad_seen строк) — последствие подтверждено"

# migrate.sh обязан ПРЕДУПРЕДИТЬ о привилегированной роли сервера.
run_migrate "$WORK/.env.broken" >"$WORK/migrate-broken.log" 2>&1 || true
grep -q "SUPERUSER или BYPASSRLS" "$WORK/migrate-broken.log" \
  && ok "migrate.sh предупреждает о привилегированной роли" \
  || fail "migrate.sh промолчал о сервере под привилегированной ролью"

# ---------------------------------------------------------------------------
# E. КРАСНЫЙ: app-роль без MIGRATION_DSN — DDL не должен катиться под ней
# ---------------------------------------------------------------------------
echo "== E. красный исход: MIGRATION_DSN потерян =="

grep -v '^MIGRATION_DSN=' "$WORK/.env.prod" >"$WORK/.env.nomig"
if run_migrate "$WORK/.env.nomig" >"$WORK/migrate-nomig.log" 2>&1; then
  fail "migrate.sh покатил DDL под mdm_app вместо отказа"
fi
grep -q "MIGRATION_DSN не задан" "$WORK/migrate-nomig.log" \
  && ok "migrate.sh отказался катить DDL под ролью приложения" \
  || { tail -10 "$WORK/migrate-nomig.log" >&2; fail "отказ есть, но не тот — проверь сообщение"; }

# env-db-roles.sh обязан починить эту же .env.prod без участия человека.
cp "$WORK/.env.nomig" "$WORK/.env.fix"
bash "$REPO/scripts/env-db-roles.sh" "$WORK/.env.fix" >/dev/null
grep -q '^MIGRATION_DSN=postgres://mdm:' "$WORK/.env.fix" \
  && ok "env-db-roles.sh восстановил MIGRATION_DSN из POSTGRES_PASSWORD" \
  || fail "env-db-roles.sh не восстановил MIGRATION_DSN"

# И обязан развести роли на инсталляции, приехавшей со старой раскладкой.
cp "$WORK/.env.broken" "$WORK/.env.legacy"
sed -i.bak '/^MIGRATION_DSN=/d' "$WORK/.env.legacy"; rm -f "$WORK/.env.legacy.bak"
bash "$REPO/scripts/env-db-roles.sh" "$WORK/.env.legacy" >/dev/null
legacy_app="$(sed -n 's/^DATABASE_DSN=//p' "$WORK/.env.legacy" | head -1)"
case "$legacy_app" in
  postgres://mdm_app:*) ok "env-db-roles.sh развёл роли на старой инсталляции" ;;
  *) fail "старая раскладка осталась под владельцем: ${legacy_app%%@*}@..." ;;
esac

echo ""
echo "DB-ROLE: PASS — сервер ходит под ролью без SUPERUSER/BYPASSRLS, оба красных исхода воспроизведены ✅"
