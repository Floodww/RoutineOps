# Self-hosted развёртывание и обновление

Актуально на 2026-07-24 (v2.5.0).

MDM ставится и обновляется **одной командой**. Каждый деплойер self-host'ит из
публичного репозитория и обновляется на своём темпе — мы в его инфраструктуру
ничего не пушим.

Что уже есть и что планируется — [ROADMAP.md](ROADMAP.md).

Две ортогональные оси обновления:

| Ось | Что | Как обновляется |
|-----|-----|-----------------|
| **A. Сервер + web** | gRPC/HTTP API, веб-панель | `git pull` + `docker rebuild` — мгновенно у деплойера |
| **B. Агенты на машинах парка** | бинарь агента | self-update тянет новый **подписанный** бинарь с сервера ЭТОГО деплойера |

---

## Первая установка

```bash
ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='<сильный_пароль>' ./install.sh
```

> **Без `sudo`.** Запусти от обычного пользователя, добавленного в группу `docker`
> (`sudo usermod -aG docker "$USER"`, затем перелогинься). Под root каталог `.git`,
> `.env.prod` и `release_ed25519.pem` станут root-owned, и следующий `git pull` /
> `./update.sh` от обычного пользователя сломается на правах.

> `ADMIN_PASSWORD` **обязателен** — без него install.sh выходит с ошибкой. Пароль
> обязан пройти политику сложности (≥8 символов, минимум 3 из 4 классов:
> строчные/прописные/цифры/спецсимволы). Слабый пароль сервер отвергнет — админ НЕ
> создастся, в логе будет `seed admin failed`.

install.sh:
1. генерирует TLS-сертификаты и `.env.prod` (секреты, seed-админ).
   Серверный серт выпускается для `localhost`/`routineops-server`/`127.0.0.1` плюс
   публичный IP хоста (install.sh сам подставляет его в `SERVER_SANS`). Для
   доменного имени задай `SERVER_HOST=mdm.example.com` — он уедет в SAN;
   подробности — [install.md](install.md);
2. генерирует **per-deployer подписной ключ** `release_ed25519.pem` (ed25519).
   Приватник НИКОГДА не покидает эту машину; публичный ключ (`RELEASE_PUBKEY`)
   сервер отдаёт агенту в ответе на enroll. Каждый деплойер = свой корень доверия;
   агенты доверяют ТОЛЬКО его серверу;
3. поднимает стек (`postgres`, `redis`, `migrate`, `server`, `web`).
   Сервис `migrate` накатывает миграции ДО старта `server` (fail-closed);
4. собирает и **подписывает** агентов (`windows/amd64`, `linux/amd64`; `darwin/arm64` —
   prebuilt из `build/darwin/`), публикует в `agent_releases`;
5. копирует установщики в `releases/`: `RoutineOps-agent.msi` и `RoutineOps-agent.pkg`
   (раздаются как `/downloads/…`).

Версии двух осей (с 2.5.0 раздельные): `VERSION` (в корне репо) — semver продукта
(сервер+веб), теги `vX.Y.Z` / `server-X.Y.Z`; `AGENT_VERSION` — semver агента, теги
`agent-X.Y.Z`. Self-update сравнивает (`IsNewer`) именно **`AGENT_VERSION`** — его
читают `install.sh`/`update.sh` при сборке и публикации агентов. Агентский релиз =
bump `AGENT_VERSION`; серверно-веб релиз = bump `VERSION`. Разнобой версий по
платформам агента — норма: публикуется только изменённый вариант.

---

## Обновление

```bash
./update.sh
```

> **Тоже без `sudo`** — по той же причине: root-owned `.git`/`.env.prod` сломают
> следующий `git pull`.

update.sh: бэкап БД → `git pull` → пересборка (migrate-сервис накатит НОВЫЕ
миграции) → пересборка + публикация агентов новой версии. Парк подтянет их
self-update'ом за интервал поллинга.

> `update.sh` **сам** обновляет канонические установщики в `releases/`
> (`RoutineOps-agent.{msi,pkg}` из `build/`, внутри build-контейнера) — кнопки
> «Скачать MSI/PKG» в UI сразу отдают новый файл, ручной `cp` не нужен. На уже
> установленные агенты это не влияет — они обновляются self-update'ом.

Перед обновлением сверь `.env.prod` с дефолтами из кода: значения, физически
присутствующие в файле, перекрывают их навсегда, и новый дефолт до тебя не доедет
(`grep -nE '^[A-Z_]+=' .env.prod`, детали — [install.md](install.md)).

---

## Существующие инсталляции: один раз засидить schema_migrations

Миграции `001..NNN` **не идемпотентны** (`CREATE TABLE` без `IF NOT EXISTS`), поэтому
на БД, где они накатывались **вручную** (до появления `schema_migrations`), нельзя
просто запустить `update.sh` — `migrate`-сервис попытается накатить их повторно, упадёт
и не даст стартовать серверу. Он это детектит (есть таблицы, нет `schema_migrations`) и
**отказывается** с просьбой сначала прогнать backfill.

Backfill помечает миграции **вплоть до твоего baseline** (`BACKFILL_UPTO` = последняя
реально накатанная миграция) как применённые БЕЗ выполнения. Миграции ВЫШЕ baseline он
НЕ трогает — их накатит `migrate`. Так `git pull`, принёсший новую миграцию, не будет
ошибочно помечен применённым (защита от schema drift):

```bash
set -a; . ./.env.prod; set +a
NET=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' \
  "$(docker compose -f docker-compose.prod.yml ps -q postgres)" | awk '{print $1}')
docker run --rm --network "$NET" \
  -v "$PWD/migrations:/migrations:ro" -v "$PWD/scripts:/scripts:ro" \
  -e DATABASE_DSN -e BACKFILL_UPTO=022 \
  postgres:16-alpine sh /scripts/migrate-backfill.sh
```

(`BACKFILL_UPTO=022` = последняя накатанная у тебя миграция; подставь свою.)
На **новой** установке backfill НЕ нужен — `migrate` накатывает всё с нуля.

---

## Откат

- **Сервер:** `git checkout <старый-tag>` → `docker compose -f docker-compose.prod.yml up -d --build`.
- **БД:** restore из `backups/db-*.dump` (custom-format, down-миграций нет — потому бэкап обязателен ДО апдейта):
  ```bash
  docker exec -i "$(docker compose -f docker-compose.prod.yml ps -q postgres)" \
    pg_restore -U mdm -d mdm --clean --if-exists < backups/<файл>.dump
  ```
- **Агенты:** anti-downgrade floor НЕ откатывает парк на старую версию. Битый релиз
  чинится выпуском версии **вперёд** (`vX.Y.Z+1`), а не откатом парка назад.

---

## Ключи и безопасность

- `release_ed25519.pem` — приватник подписи релизов, `chmod 600`, gitignored.
  Бэкап — только в защищённое хранилище. Потеря приватника **не** оставляет парк
  навсегда без обновлений: генерируешь новую пару → кладёшь новый pubkey в
  `RELEASE_PUBKEY` (`.env.prod`) → перезапуск сервера. Новые энроллменты сразу
  получают новый ключ; уже развёрнутые агенты держат старый сохранённый ключ, пока
  их не переэнроллят (переустановка pkg/msi переэнроллит — бинарь универсальный, тот
  же пакет). До переэнроллмента такие устройства не примут релизы, подписанные новым
  ключом. Подробнее о восстановлении — [operations.md](operations.md).
- `RELEASE_PUBKEY` в `.env.prod` — публичный ключ; сервер отдаёт его агенту в ответе
  на enroll (см. шаг 2 «Первая установка»). Вшивание в бинарь — opt-in для
  legacy/dev-сборок, по умолчанию выключено.
- FileVault-escrow (`ESCROW_RECIPIENT*`) — **enterprise-фича** (build-tag
  `enterprise`). Free-сборка (по умолчанию) её не содержит: escrow-RPC →
  Unimplemented, `lock_mode=filevault` → 409; `ESCROW_*` free-сервером
  игнорируются. Guard от протечки в open-core: `scripts/check-oss-no-enterprise.sh`.
  См. `.env.prod.example`.

Ручная пошаговая установка, SMTP, добавление устройств и типовые проблемы —
в `docs/install.md`.
