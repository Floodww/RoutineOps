# Агент: CLI и сценарии развёртывания

Актуально на 2026-07-24 (агент 2.5.0).

Справочник по командам бинарника `agent`. Краткую версию печатает сам бинарник:
`agent help` (или `agent -h` / `agent --help`).

Связь agent↔server — строго mTLS (`:50051`). Канал энроллмента — server-auth TLS
(через nginx на `:443`; напрямую в server — `:8081`, по умолчанию не опубликован
наружу) + одноразовый токен (на момент энроллмента mTLS-идентичности ещё нет).

## Команды

| Команда | Назначение |
|---|---|
| `enroll` | Получить mTLS-сертификат по одноразовому токену; опц. скачать CA и поставить службу |
| `run` | Запустить агент (значение по умолчанию, если команда не указана) |
| `install` | Зарегистрировать системную службу (launchd/SCM); нужны root/админ |
| `uninstall` | Снять службу |
| `cleanup-legacy` | Удалить следы прежних ручных установок (Windows: `C:\mdm-extract`) |
| `request-admin` | Запросить временные права администратора |
| `diag` | Диагностика: конфиг, провайдер сертификата, опц. проба связи (`-probe`) |
| `tray` | Иконка статуса в трее (Windows и macOS, per-user процесс) |
| `tamper-status` | Состояние защиты от удаления. Windows: флаги в реестре + режим загрузки. macOS: флаг `schg` на бинаре и plist'ах. Linux: защиты нет |
| `tamper-disarm` | Разоружить защиту. Windows: только из безопасного режима. macOS: `chflags noschg` от root — **обязателен перед `uninstall`**. Linux: вернёт ошибку «не реализована» |
| `tamper-cleanup` | Windows: снять SafeBoot-регистрацию и флаги (вызывается из `uninstall.bat`). macOS/Linux: no-op |
| `filevault-provision` | Дозавершить FileVault-provisioning (macOS, интерактивно; только enterprise-сборка, в free вернёт ошибку) |
| `version` | Версия, платформа, статус self-update и escrow |
| `help` | Справка с примерами |

Флаги идут **после** команды. При `install` / `enroll -install-service` параметры
(адрес сервера, источник идентичности, пути к mTLS-материалу) сохраняются в конфиг
службы — **пути указывайте абсолютными**, иначе служба со своим рабочим каталогом их
не найдёт. Любой флаг можно задать через env-переменную (см. `agent run -h`).

## Ключевые флаги

| Флаг | Env | Назначение |
|---|---|---|
| `-server host:port` | `ROUTINEOPS_SERVER_ADDR` | Адрес gRPC-сервера |
| `-server-name` | `ROUTINEOPS_SERVER_NAME` | Ожидаемое имя в серверном сертификате |
| `-cert` / `-key` / `-ca` | `ROUTINEOPS_AGENT_CERT` / `ROUTINEOPS_AGENT_KEY` / `ROUTINEOPS_CA_CERT` | Файловый mTLS-материал |
| `-cert-source file\|keystore` | `ROUTINEOPS_CERT_SOURCE` | Источник идентичности (`keystore` = защищённое хранилище ОС) |
| `-keystore-label` | `ROUTINEOPS_KEYSTORE_LABEL` | Метка идентичности в keystore (обычно `device_id` = CN) |
| `-enroll-url` | `ROUTINEOPS_ENROLL_URL` | Эндпоинт энроллмента (`https://host/api/v1/enroll`) |
| `-token` | `ROUTINEOPS_ENROLL_TOKEN` | Одноразовый enrollment-токен |
| `-ca-url` | `ROUTINEOPS_CA_URL` | Откуда скачать CA-бандл, если `-ca` нет на диске |
| `-ca-sha256 HEX` | `ROUTINEOPS_CA_SHA256` | Пин sha256 CA-бандла. **Обязателен вместе с `-ca-url`** — скачивание CA без пина отклоняется (защита от MITM) |
| `-install-service` | `ROUTINEOPS_ENROLL_INSTALL` | После `enroll` сразу зарегистрировать службу |
| `-probe` | — | `diag`: дополнительно проверить mTLS-соединение |
| `-outbox-max` | `ROUTINEOPS_OUTBOX_MAX` | Потолок числа записей в очереди отчётов (0 = без лимита) |
| `-outbox-max-age` | `ROUTINEOPS_OUTBOX_MAX_AGE` | Потолок возраста записи (0 = без лимита по возрасту) |
| `-update-url` | `ROUTINEOPS_UPDATE_URL` | URL манифеста самообновления (`.../api/v1/agent/version`); при `enroll -install-service` прописывается в службу автоматически |
| `-update-interval` | `ROUTINEOPS_UPDATE_INTERVAL` | Период проверки обновлений (по умолчанию 6ч) |

Публичный ключ проверки подписи обновлений агент получает при enroll (поле
`release_pubkey`, приходит по доверенному каналу с пином CA) — сборки по умолчанию
универсальные, без вшитого ключа. Вшивание при сборке
(`-ldflags -X main.releasePubKey=...`) — opt-in для legacy/dev-сборок; если ключ
вшит, он авторитетен и не переопределяется, а `-update-pubkey` — dev-override ТОЛЬКО
для сборок без вшитого ключа. Подробнее — `docs/self-update.md`.

## Сценарии

### Энроллмент «в одну команду» (файловые серты)

Получить серт по токену, скачать CA, зарегистрировать службу. Запускать от
администратора/root (служба работает под LocalSystem/root-демоном).
`-ca-sha256` обязателен при `-ca-url` (скачивание CA без пина отклоняется);
альтернатива — разложить CA локальным файлом через `-ca` и убрать `-ca-url`:

```bash
agent enroll \
  -enroll-url https://mdm.example/api/v1/enroll \
  -token <one-time-token> \
  -ca-url https://mdm.example/ca.crt \
  -ca-sha256 <hex-sha256-ca.crt> \
  -server mdm.example:50051 \
  -install-service
```

Повторный запуск `enroll` идемпотентен: при валидной (непросроченной)
идентичности энроллмент пропускается (одноразовый токен не гасится повторно),
агент сразу переходит к регистрации службы.

### Энроллмент с идентичностью в хранилище ОС (Keychain / Windows NCrypt)

`cert-source=keystore` импортирует выданную идентичность в машинное хранилище и
убирает приватный ключ с диска. Вместе с `-install-service` **обязательно** от
администратора/root — иначе идентичность ляжет в пользовательский стор, недоступный
службе под LocalSystem/root:

```bash
agent enroll \
  -enroll-url https://mdm.example/api/v1/enroll \
  -token <one-time-token> \
  -ca-url https://mdm.example/ca.crt \
  -server mdm.example:50051 \
  -cert-source keystore \
  -install-service
```

### Ручной запуск (отладка)

Файловые серты, агент пишет логи в stderr:

```bash
agent run -server mdm.example:50051 \
  -cert certs/agent.crt -key certs/agent.key -ca certs/ca.crt
```

Идентичность из keystore (ключа на диске нет):

```bash
agent run -server mdm.example:50051 -cert-source keystore
```

### Диагностика на устройстве

Проверить конфиг, провайдер сертификата и (с `-probe`) живое mTLS-соединение:

```bash
agent diag -server mdm.example:50051 -probe
```

### Временные права администратора

```bash
agent request-admin -server mdm.example:50051 -reason "установка ПО"
```

## См. также

- `docs/enrollment.md` — протокол энроллмента и выпуск токенов.
- `docs/install.md` — публикация релизов и установка службы.
- `docs/field-troubleshooting.md` — разбор полевых проблем подключения.
