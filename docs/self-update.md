# Самообновление агента

Актуально на 2026-07-16 (v2.4.5). Механизм реализован полностью (агент + сервер)
и провалидирован в проде: агент сам скачивает новый подписанный бинарь,
проверяет подпись и перезапускается.

Код: агент — `internal/agent/selfupdate`; сервер — `agentVersion` в
`internal/server/api/handler.go`; публикация — `cmd/publish-release`.

## Как это работает

1. Раз в `ROUTINEOPS_UPDATE_INTERVAL` (по умолчанию 6ч) агент делает
   `GET /api/v1/agent/version?os=<GOOS>&arch=<GOARCH>` → manifest.
2. Если `version` новее (semver) и текущей версии, и anti-rollback floor —
   качает бинарь по `url` (сервер раздаёт `releases/` через `/downloads/`;
   лимит скачивания 200 МБ, таймаут).
3. Проверяет **sha256** бинаря и **ed25519-подпись манифеста** публичным ключом
   релиза (агент получает его при enroll; opt-in legacy-сборки могут вшить ключ в
   бинарь). Без валидной `manifest_signature` — отказ (fail-closed).
4. Атомарно заменяет свой бинарь (unix: rename; windows: rename-aside + write).
5. Перезапускается: macOS — launchd KeepAlive; Windows — `os.Exit(1)` → SCM
   FailureActions поднимает службу на новом бинаре
   (`internal/agent/service/run_windows.go`). Работает начиная с агента v2.2.5;
   у ≤2.2.4 чистый stop не триггерил recovery — служба оставалась Stopped до
   ручного старта/ребута.

dev-сборки (`version=dev` или пустая) не автообновляются.

## Включение

В релизной установке самообновление включается само, ничего настраивать не надо:

- **Публичный ключ** приезжает агенту в ответе на enroll (поле `release_pubkey`):
  сервер держит `RELEASE_PUBKEY` в `.env.prod` и отдаёт его при энроллменте, а агент
  сохраняет ключ в файл рядом с CA. `install.sh`/`update.sh` собирают
  **универсальный** бинарь БЕЗ вшитого ключа (`RELEASE_PUBKEY` в `Makefile` по
  умолчанию пуст) — один бинарь на все деплои. Вшивание при сборке (цели
  `make build-win`/`build-mac`/`build-linux` через
  `-ldflags "-X main.releasePubKey=$(RELEASE_PUBKEY)"`) осталось как opt-in для
  legacy/dev-сборок и по умолчанию выключено.
- **URL манифеста** служба получает при `enroll -install-service`: он выводится
  из enroll-URL (`/api/v1/enroll` → `/api/v1/agent/version`,
  см. `deriveUpdateURL` в `cmd/agent/main.go`).

Какой ключ проверяет подпись, решает `resolveUpdatePubKeyB64` (`cmd/agent/main.go`)
по приоритету: (1) ВШИТЫЙ `releasePubKey`, если сборка не универсальная — он
авторитетен и в проде не обходится через env/флаг (SEC-2); (2) ключ, сохранённый при
enroll из доверенного (пин CA) enroll-ответа — это путь универсального бинаря;
(3) `-update-pubkey`/`ROUTINEOPS_UPDATE_PUBKEY` — dev-override ТОЛЬКО для сборок без вшитого
ключа. Остальные параметры работают в любой сборке:

| Флаг | Env | Дефолт |
|---|---|---|
| `-update-url` | `ROUTINEOPS_UPDATE_URL` | пусто = выключено |
| `-update-interval` | `ROUTINEOPS_UPDATE_INTERVAL` | `6h` |
| `-update-pubkey` | `ROUTINEOPS_UPDATE_PUBKEY` | dev-override; игнорируется при вшитом ключе |
| `-update-floor` | `ROUTINEOPS_UPDATE_FLOOR` | `agent_update_floor.txt`; на macOS/Linux служба пишет в `<DataDir>/update_floor.txt` |

## Контракт manifest

```
GET /api/v1/agent/version?os=darwin&arch=arm64
```
Эндпоинт публичный (без auth). Ответ `200`:
```json
{
  "version":            "v2.4.5",
  "url":                "https://<SERVER_IP>/downloads/agent_darwin_arm64_v2.4.5",
  "sha256":             "<hex sha256 бинаря>",
  "signature":          "<ed25519 над sha256(бинарь) — legacy, для старых агентов>",
  "manifest_signature": "<ed25519 над version\\nos\\narch\\nsha256 — актуальная проверка>"
}
```

- Сервер отдаёт **последний** релиз для os/arch из таблицы `agent_releases`
  (миграции 009 + 019); параметр `current` информационный, гейтинга по
  устройствам нет — все агенты тянут latest в течение интервала.
- `os`/`arch` в ответе не дублируются: агент подставляет свои
  `runtime.GOOS`/`GOARCH` при проверке подписи.
- Агент требует: `sha256(binary) == sha256` И валидную `manifest_signature`.
  Пустая `manifest_signature` → отказ, даже если legacy `signature` валидна.

### Почему подписывается манифест, а не только бинарь

Подпись только `sha256(binary)` защищала бинарь, но не связь версии с бинарём:
скомпрометированный сервер мог отдать СТАРЫЙ валидно подписанный бинарь под
произвольной `version` — агент счёл бы его новым и откатился на уязвимый билд.
Канон `version\nos\narch\nsha256` (newline-разделитель, фиксированный порядок)
закрывает это. Подписывает `cmd/publish-release`, проверяет
`internal/agent/selfupdate/selfupdate.go:signedMessage`/`verify` — PureEdDSA,
без префиксного хеша.

### Anti-rollback floor

Подпись не спасает от replay СТАРОГО, но настоящего манифеста (легитимный v3.0,
отозванный после уязвимости, технически валиден вечно). Поэтому агент держит
high-water mark — файл с максимальной когда-либо применённой версией
(`-update-floor`). Манифест обязан быть новее и текущей версии, и floor; после
успешного апдейта файл обновляется. См. `Updater.loadFloor`/`saveFloor`.

## Публикация релиза

**Self-hosted:** `./update.sh` делает всё сам — бэкап БД → `git pull` →
пересборка (compose-сервис `migrate` накатывает миграции до старта server) →
сборка и публикация агентов windows/amd64, linux/amd64, darwin/arm64 с подписью
per-deployer ключом `release_ed25519.pem` (его создаёт `install.sh`).

**Вручную** (ключ по умолчанию `RELEASE_KEY=~/release_ed25519.pem`):

```sh
make build-win VERSION=$(cat VERSION)
make publish-release BINARY=bin/agent_windows_amd64.exe OS=windows ARCH=amd64 VERSION=v$(cat VERSION)
# эквивалент: go run ./cmd/publish-release -binary … -version … -os … -arch … -key …
```

`publish-release` считает sha256, подписывает бинарь и канон манифеста,
копирует бинарь в `releases/` и пишет запись в `agent_releases` (UPSERT по
os/arch/version — повторная публикация той же версии не падает).

Генерация ключа (один раз; для self-hosted это делает `install.sh`):

```sh
openssl genpkey -algorithm ed25519 -out release_ed25519.pem   # приватник — у деплойера/в CI secrets
# raw 32-байтный публичный ключ base64 — это RELEASE_PUBKEY: сервер кладёт его в
# .env.prod и раздаёт агентам при enroll (и он же — значение для opt-in вшивания):
openssl pkey -in release_ed25519.pem -pubout -outform DER | tail -c 32 | base64
```

## Как проверить

- Манифест: `curl 'https://<SERVER_IP>/api/v1/agent/version?os=windows&arch=amd64'`.
- Версия агента на устройстве: колонка «Версия агента» в UI
  (`devices.agent_version`, миграция 025) или лог службы.
- Ждать до 6ч либо временно уменьшить `ROUTINEOPS_UPDATE_INTERVAL` у службы.

## Безопасность (зафиксировано в коде)

- Приватный ключ релиза в агенте/на сервере отсутствует — только публичный.
- Манифест без валидной `manifest_signature` НЕ применяется (fail-closed).
- Anti-rollback floor: манифест ниже уже применённой версии отклоняется, даже
  если подпись валидна.
- Публичный ключ проверки приезжает при enroll по доверенному каналу (пин CA); в
  универсальной сборке он НЕ вшит. Если ключ всё же вшит (opt-in legacy), он
  авторитетен и не переопределяется env/флагом (SEC-2).
- Лимит размера скачивания (200 МБ), таймаут на загрузку.
- Бинарь недоверен по дизайну — канал раздачи может быть любым, подлинность
  гарантируют sha256 + ed25519.
