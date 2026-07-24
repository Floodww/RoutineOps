# Установка и настройка MDM

Актуально на 2026-07-24 (v2.5.0).

> **Быстрый путь:** `./install.sh` делает всё, что описано ниже, одной командой
> (сертификаты, `.env.prod`, ключ подписи релизов, стек, сборка и публикация
> агентов). Обновление — `./update.sh`. См. [self-hosted-deploy.md](self-hosted-deploy.md).
> Этот документ — те же шаги вручную, для понимания и нестандартных случаев,
> плюс исчерпывающий справочник по переменным, портам и типичным проблемам.

---

## Требования

### Характеристики сервера

| Парк устройств | CPU | RAM | Диск |
|---|---|---|---|
| до 50 устройств | 1 vCPU | 2 ГБ | 20 ГБ SSD |
| до 500 устройств | 2 vCPU | 4 ГБ | 40 ГБ SSD |
| 500+ устройств | 4+ vCPU | 8+ ГБ | 80+ ГБ SSD |

> Диск нужен под базу данных PostgreSQL и бинарные релизы агентов. Рекомендуется SSD — PostgreSQL чувствителен к задержке I/O.

### Программные требования

- Linux-сервер (Ubuntu 22.04+, Debian 12+)
- Docker + **Docker Compose v2** (обязательно, см. ниже)
- Открытые порты: `80`/`443` (веб + enrollment + загрузки), `50051` (gRPC для агентов)
- Домен или статический IP

> **Требуется Docker Compose v2.** На Ubuntu 22.04 по умолчанию установлен `docker-compose` v1.29.2, который несовместим с Docker Engine 25+ и падает с ошибкой `KeyError: 'ContainerConfig'` при пересоздании контейнеров. Все команды ниже используют синтаксис v2 (`docker compose` без дефиса).
>
> Установка Compose v2:
> ```bash
> sudo mkdir -p /usr/local/lib/docker/cli-plugins
> sudo curl -SL https://github.com/docker/compose/releases/download/v2.27.1/docker-compose-linux-x86_64 \
>   -o /usr/local/lib/docker/cli-plugins/docker-compose
> sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
> docker compose version   # должно вывести Docker Compose version v2.x.x
> ```

### Пользователь, от которого всё запускается

Ставьте и обновляйте MDM от **обычного пользователя**, входящего в группу `docker`:

```bash
sudo usermod -aG docker "$USER"
# перелогиньтесь (новая группа применяется только к новой сессии)
id -nG   # в списке должен появиться docker
```

> **Важно:** никогда не запускайте `sudo ./install.sh` или `sudo ./update.sh`.
> Под root каталог `.git`, `.env.prod` и `release_ed25519.pem` станут root-owned, и
> следующий `git pull` от обычного пользователя сломается на правах. Репозиторий,
> ключи и `.env.prod` должны принадлежать тому пользователю, который запускает
> скрипты. Сами скрипты вызывают `docker` без `sudo` — именно поэтому нужна группа.

---

## Установка сервера

### Вариант A — через `install.env` (рекомендуется)

Скопируйте шаблон, заполните и запустите — так все параметры уходят в установку
сразу и наверняка (ничего не забудется в инлайновых переменных):

```bash
cp install.env.example install.env
nano install.env      # заполните PUBLIC_ADDR и ADMIN_EMAIL / ADMIN_PASSWORD
./install.sh
```

`install.env` лежит в `.gitignore` (в нём пароль администратора) — коммитить его
нельзя. Инлайновые переменные при запуске (`VAR=… ./install.sh`) переопределяют файл.

`install.sh` сгенерирует сертификаты (подставив в SAN нужные адреса), создаст
`.env.prod` со случайными секретами, сгенерирует per-deployer ключ подписи релизов,
поднимет стек, соберёт и опубликует агентов, а также разложит установщики
(`releases/RoutineOps-agent.msi`, `releases/RoutineOps-agent.pkg`).

> **Обновление установщиков MSI/PKG в `/downloads/`.** Кнопки «Скачать MSI/PKG» в UI
> отдают `releases/RoutineOps-agent.{msi,pkg}`. Эти файлы обновляют **и `install.sh`, и
> `update.sh`**: оба копируют их из `build/msi/RoutineOps-agent.msi` и `build/pkg/RoutineOps-agent.pkg`
> внутри build-контейнера (`releases/` становится root-owned после публикации, поэтому
> host-side `cp` от деплойера падал бы `Permission denied`, а `umask 077` дал бы 600 —
> в контейнере root + `umask 022` → 644, читаемо сервером). Поэтому чтобы выложить новый
> установщик, достаточно положить свежесобранный файл в `build/msi/RoutineOps-agent.msi` /
> `build/pkg/RoutineOps-agent.pkg` (MSI — на Windows через `build/msi/build-msi.ps1`, PKG — на
> macOS) и подтянуть его в репо на сервере (`git pull` делает сам `update.sh`): следующий
> `./update.sh` или `./install.sh` скопирует его в `releases/`. Ручной
> `sudo cp build/msi/RoutineOps-agent.msi releases/RoutineOps-agent.msi && sudo chmod 644 releases/RoutineOps-agent.*`
> нужен только на сервере со старыми скриптами (до июля 2026, когда `update.sh` установщики
> не обновлял). На уже установленные агенты выкладка нового установщика не влияет — они
> обновляются через self-update.

Ключевые поля `install.env`:

- **`PUBLIC_ADDR`** — внешний адрес (IP или домен), по которому к серверу ходят
  агенты и браузеры. За NAT/VPN `hostname -I` даёт ВНУТРЕННИЙ IP — задайте внешний
  адрес ЯВНО, иначе enroll по внешнему адресу упадёт на TLS: адрес обязан быть в SAN
  сертификата. Внутренний IP хоста добавляется в SAN автоматически.
- **`ADMIN_PASSWORD`** обязателен — без него `install.sh` отказывается работать.
  Пароль обязан пройти политику сложности (≥8 символов, минимум 3 из 4 классов:
  строчные / прописные / цифры / спецсимволы). Слабый пароль сервер отвергнет:
  админ **не создастся**, а в логе будет `seed admin failed` — войти будет некем.
- Опционально: `SERVER_HOST` (доп. DNS-имя в SAN), SMTP-поля (почта инвайтов/сброса),
  `TELEGRAM_BOT_TOKEN` (алерты), `COOKIE_SECURE`, retention — см. комментарии в шаблоне.

> Без `install.env` можно и инлайном (всё то же самое переменными окружения):
> `PUBLIC_ADDR=mdm.example.com ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=… ./install.sh`

Дальше — раздел [«Проверка»](#проверка). Остальное в этом разделе — ручной путь.

### Вариант B — вручную, по шагам

#### 1. Скачайте репозиторий

```bash
git clone <URL-этого-репозитория>
cd RoutineOps
```

> Каталог называется `RoutineOps` (по имени репозитория), а не как-либо иначе.

#### 2. Сгенерируйте TLS-сертификаты

Серверный сертификат обязан покрывать адрес, по которому к серверу обращаются
агенты. Базовый набор SAN (`DNS:localhost`, `DNS:routineops-server`, `IP:127.0.0.1`)
скрипт проставляет сам; внешний адрес добавляется через переменную `SERVER_SANS`:

```bash
SERVER_SANS="IP:203.0.113.10,DNS:mdm.example.com" bash scripts/gen-certs.sh
```

Создаст `certs/ca.crt`, `ca.key`, `server.crt`, `server.key`.

> **Важно:** редактировать `scripts/gen-certs.sh` не нужно — SAN задаётся только
> через `SERVER_SANS` (`install.sh` подставляет туда публичный IP хоста
> автоматически). Скрипт **идемпотентен**: если `certs/server.key` уже есть, он
> пропускает генерацию. Чтобы перевыпустить сертификат с новым SAN, сначала
> уберите старую пару (`mv certs/server.crt certs/server.crt.bak` и то же с
> `server.key`) — CA при этом не пострадает.

#### 3. Создайте файл переменных окружения

Все переменные живут в одном файле `.env.prod` (его читают и сервер, и postgres,
и migrate-сервис). Скопируйте шаблон и заполните:

```bash
cp .env.prod.example .env.prod
chmod 600 .env.prod
```

Минимум, который нужно заполнить:

```env
POSTGRES_PASSWORD=<придумайте_пароль>
DATABASE_DSN=postgres://mdm:<тот_же_пароль>@postgres:5432/mdm?sslmode=disable
REDIS_ADDR=redis:6379
SERVER_CERT=certs/server.crt
SERVER_KEY=certs/server.key
CA_CERT=certs/ca.crt
CA_KEY=certs/ca.key
JWT_SECRET=<openssl rand -hex 32>
SEED_ADMIN_EMAIL=admin@example.com
SEED_ADMIN_PASSWORD=<пароль_администратора>
PUBLIC_WEB_URL=https://mdm.example.com
COOKIE_SECURE=true
```

> **Важно:** не используйте в паролях спецсимвол `$` — он интерпретируется как
> начало переменной в env-файлах и приведёт к ошибке аутентификации.
>
> **Хост в `DATABASE_DSN`** — `postgres` (имя сервиса в compose), а не `localhost`.
>
> **`PUBLIC_WEB_URL`** — с `https://`: nginx редиректит 80 → 443. Это значение
> используется в генерируемых installer-скриптах и ссылках на загрузку агентов.
>
> **`RELEASE_PUBKEY`** не заполняйте вручную — `install.sh` генерирует per-deployer
> ключ подписи релизов и дописывает его сам (см. [self-hosted-deploy.md](self-hosted-deploy.md)).

#### 4. Соберите и запустите контейнеры

```bash
export VERSION=$(cat VERSION)   # версия релиза — build-arg для образа сервера
docker compose -f docker-compose.prod.yml up -d --build
```

> **Важно:** `export VERSION` обязателен. Compose интерполирует build-arg `VERSION`
> только из окружения запуска (`env_file` на сборку не влияет), и без него образ
> соберётся с версией `dev`. Агент версии `dev` пропускает самообновление, а
> сравнение версий на сервере ломается. `./install.sh` и `./update.sh` делают это сами.

Миграции БД накатывает **автоматически** compose-сервис `migrate` (таблица
`schema_migrations`, fail-closed: сервер не стартует, пока миграции не применены).
Ручной psql для миграций не нужен.

> На **существующей** инсталляции, где миграции когда-то накатывались вручную (до
> появления `schema_migrations`), перед первым `./update.sh` нужен одноразовый
> backfill — иначе `migrate` откажется стартовать. Процедура:
> [self-hosted-deploy.md](self-hosted-deploy.md#существующие-инсталляции-один-раз-засидить-schema_migrations).

---

## Переменные окружения

Всё читается из `.env.prod`. Значения в файле **всегда перекрывают** дефолты из
кода (см. [«Ловушка перекрытых дефолтов»](#ловушка-перекрытых-дефолтов)).

### Обязательные

| Переменная | Дефолт | Назначение |
|---|---|---|
| `POSTGRES_PASSWORD` | — | Пароль суперпользователя postgres-контейнера. Без него postgres не стартует. Без `$` в значении |
| `DATABASE_DSN` | `postgres://mdm:mdm_dev_password@localhost:5432/mdm?sslmode=prefer` | DSN базы. В проде задавать явно, хост — `postgres` |
| `REDIS_ADDR` | `localhost:6379` | Адрес Redis. В compose — `redis:6379` |
| `JWT_SECRET` | `dev-secret-change-in-production` | Корень доверия админ-сессий. `openssl rand -hex 32`. Ротация — [jwt-secret-rotation.md](jwt-secret-rotation.md) |
| `PUBLIC_WEB_URL` | `https://localhost:8081` | Внешний URL сервера. Подставляется в installer-скрипты, ссылки на загрузку и инвайты |

### Сертификаты

| Переменная | Дефолт | Назначение |
|---|---|---|
| `SERVER_CERT` | `certs/server.crt` | Серверный сертификат (TLS для REST и gRPC) |
| `SERVER_KEY` | `certs/server.key` | Приватный ключ сервера |
| `CA_CERT` | `certs/ca.crt` | Корневой CA: проверка клиентских сертификатов агентов |
| `CA_KEY` | `certs/ca.key` | Ключ CA: подпись сертификатов при enrollment. Нет ключа — enrollment выключен |

### Первый администратор

| Переменная | Дефолт | Назначение |
|---|---|---|
| `SEED_ADMIN_EMAIL` | пусто | Email первого админа. Пусто = seed не выполняется |
| `SEED_ADMIN_PASSWORD` | пусто | Пароль первого админа. Обязан пройти политику сложности (≥8 символов, 3 из 4 классов), иначе `seed admin failed` |

### Сеть и раздача файлов

| Переменная | Дефолт | Назначение |
|---|---|---|
| `HTTP_ADDR` | `:8081` | Адрес REST/HTTPS-сервера **внутри контейнера**. Наружу его проксирует nginx |
| `GRPC_ADDR` | `:50051` | Адрес gRPC-сервера для агентов |
| `RELEASES_DIR` | `./releases` | Каталог с опубликованными бинарями агентов; раздаётся как `/downloads/*` |
| `COOKIE_SECURE` | `false` | `true` → на cookie админ-сессии ставится флаг `Secure` (уходит только по HTTPS). **Ставьте `true` на любом деплое за HTTPS**; любое другое значение = выключено |

> **`COOKIE_SECURE` не прописывается автоматически.** `install.sh` его в `.env.prod`
> не пишет, то есть по умолчанию флаг `Secure` на cookie сессии **не ставится**.
> Добавьте `COOKIE_SECURE=true` вручную и перезапустите сервер.

### Хранение данных и алерты

| Переменная | Дефолт | Назначение |
|---|---|---|
| `DATA_RETENTION_DAYS` | `7` | Срок хранения операционных данных (алерты, результаты скриптов). `0` = бессрочно |
| `AUDIT_RETENTION_DAYS` | `365` | Отдельный, длинный срок хранения `audit_log`. `0` = бессрочно |
| `AGENT_UNREACHABLE_MINUTES` | `10080` (7 суток) | Сколько минут без heartbeat до алерта `agent_unreachable` |
| `AGENT_UNREACHABLE_COOLDOWN_MINUTES` | `360` (6 часов) | Окно подавления повторных `agent_unreachable` по одному устройству |

### Почта и уведомления

| Переменная | Дефолт | Назначение |
|---|---|---|
| `SMTP_HOST` | пусто | Хост SMTP. **Пусто = почта отключена** (в логе `mailer disabled`) |
| `SMTP_PORT` | `587` | `587` = STARTTLS, `465` = implicit TLS |
| `SMTP_USER` | пусто | Логин SMTP |
| `SMTP_PASS` | пусто | Пароль SMTP — как правило, **app password**, а не пароль от ящика |
| `SMTP_FROM` | `noreply@mdm.local` | Адрес отправителя. Дефолтный домен отвергнет любой реальный релей — задавайте явно |
| `SMTP_TLS` | `false` | `true` → implicit TLS (порт `465`). Любое значение кроме `true` = STARTTLS |
| `TELEGRAM_BOT_TOKEN` | пусто | Токен своего бота от `@BotFather`. Пусто = Telegram-уведомления отключены |

### Самообновление агентов

| Переменная | Дефолт | Назначение |
|---|---|---|
| `RELEASE_PUBKEY` | пусто | Публичный ed25519-ключ подписи релизов. **Заполняется `install.sh` автоматически**, вручную не трогать |

Enterprise-переменные (`ESCROW_RECIPIENT`, `ESCROW_RECIPIENT_FPR`) free-сборкой
игнорируются — см. `.env.prod.example` и [ROADMAP.md](ROADMAP.md).

### Ловушка перекрытых дефолтов

Переменная, **физически присутствующая** в `.env.prod`, перекрывает дефолт из кода
навсегда. Если в новом релизе дефолт изменился, до вашей инсталляции он не доедет —
там продолжит действовать старое значение из файла. Перед обновлением сверьте:

```bash
grep -nE '^[A-Z_]+=' .env.prod
```

и сравните с дефолтами в `internal/server/config/config.go`. Чаще всего расходятся
`DATA_RETENTION_DAYS`, `AUDIT_RETENTION_DAYS`, `AGENT_UNREACHABLE_MINUTES`
(текущий дефолт `10080` = 7 суток; старые инсталляции нередко держат минуты и
получают шквал ложных алертов) и `AGENT_UNREACHABLE_COOLDOWN_MINUTES`.

---

## Порты

| Порт | Наружу | Протокол | Назначение |
|---|---|---|---|
| `80` | да | HTTP | Редирект на 443; **исключение** — `/downloads/` раздаётся прямо по HTTP (бинари публичны, установщик сверяет sha256-пин) |
| `443` | да | HTTPS | Веб-интерфейс, REST API, enrollment, `/ca.crt`, `/downloads/` (nginx) |
| `50051` | да | gRPC/TLS | Постоянное соединение агентов (mTLS) |
| `8081` | нет — bind `127.0.0.1` | HTTPS | REST API напрямую, минуя nginx. `/healthz` живёт **только** здесь — nginx его не проксирует |
| `5432` | нет — bind `127.0.0.1` | PostgreSQL | База данных |
| Redis | нет — только внутри compose-сети | — | Очередь доставки задач (asynq) |

Агенты подключаются к **443** (enrollment, скачивание CA и бинарей — адрес берётся
из `PUBLIC_WEB_URL`) и **50051** (основной канал). Схема компонентов —
[ARCHITECTURE.md](../ARCHITECTURE.md).

---

## Публикация релиза агента

Перед добавлением первого устройства бинарь агента должен быть собран, **подписан**
и зарегистрирован в БД. Без этого installer-скрипт генерируется без строки загрузки
агента.

`./install.sh` (и каждый `./update.sh`) делает это автоматически: собирает агентов
(`windows/amd64`, `linux/amd64`, а также prebuilt `darwin/arm64` из `build/darwin/`),
подписывает их per-deployer ключом `release_ed25519.pem` и публикует через
`cmd/publish-release` (UPSERT в `agent_releases`, идемпотентно).

> **`linux/arm64` штатные скрипты НЕ публикуют.** В UI архитектуру `arm64` выбрать
> можно, но installer-скрипт придёт без строки загрузки, пока вы не опубликуете
> бинарь вручную (команда ниже, `-os linux -arch arm64`).

Вручную (например, для одной платформы) — то же самое в golang-контейнере на
compose-сети:

```bash
set -a; . ./.env.prod; set +a
PG=$(docker compose -f docker-compose.prod.yml ps -q postgres)
NET=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$PG" | awk '{print $1}')
docker run --rm --network "$NET" -v "$(pwd)":/app -w /app \
  -e DATABASE_DSN="$DATABASE_DSN" \
  golang:1.26-alpine sh -c '
    V=$(cat AGENT_VERSION)   # версия АГЕНТА (отдельно от продукта/сервера)
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${V}" \
      -o /tmp/agent_linux_arm64 ./cmd/agent
    go run ./cmd/publish-release -binary /tmp/agent_linux_arm64 \
      -version "v${V}" -os linux -arch arm64 -key release_ed25519.pem
  '
```

> Ручной `INSERT` в `agent_releases` с пустой подписью не работает: self-update
> требует валидную ed25519-подпись манифеста (канон `version+os+arch+sha256`;
> пустая или невалидная подпись = fail-closed отказ) плюс сверку sha256 бинаря,
> а даунгрейд блокируется high-water mark версии — публикуйте только через
> `cmd/publish-release`. Детали — [self-update.md](self-update.md).

> **Windows-агент нельзя собирать «как есть».** Без `.syso` с манифестом
> Common Controls и без `-H windowsgui` вы получите агента, у которого падает трей
> и лок-оверлей. Точные флаги — в `update.sh`; лучше просто вызвать `./update.sh`.
> Аналогично macOS-агент требует cgo и собирается только на маке (`make release-darwin`),
> поэтому в репо лежит prebuilt `build/darwin/agent_darwin_arm64`.

---

## Добавление устройства

Устройство появляется в интерфейсе **только после того, как агент установлен и
выполнил enrollment** — не в момент создания токена.

### 1. Получите токен установки

В веб-интерфейсе откройте **«Устройства»** → **«Добавить устройство»** и выберите ОС
(hostname подставится автоматически при enrollment).

- **Windows:** UI выдаст готовую команду `msiexec` (со всеми пятью свойствами) и
  кнопку **«Скачать MSI»** (`/downloads/RoutineOps-agent.msi`).
- **Linux / macOS:** выберите архитектуру и нажмите **«Скачать установщик»** —
  это shell-скрипт `install-mdm.sh` с уже подставленными токеном, `-ca-url`,
  `-ca-sha256`-пином и адресом gRPC.

> Токен действует **24 часа** и одноразовый. Если истёк или сгорел — нажмите
> «Перерегистрировать» на странице устройства. Подробнее — [enrollment.md](enrollment.md).

### 2. Установите агент

#### Windows — универсальный MSI

```powershell
msiexec /i RoutineOps-agent.msi /qn `
  ENROLL_URL="https://mdm.example.com/api/v1/enroll" `
  ENROLL_TOKEN="<токен>" `
  CA_URL="https://mdm.example.com/ca.crt" `
  CA_SHA256="<hex sha256 от ca.crt>" `
  SERVER_ADDR="mdm.example.com:50051"
```

> **Все пять свойств обязательны.** MSI универсален — он **не содержит** `ca.crt`.
> Агент качает CA по `CA_URL` и сверяет его с `CA_SHA256` (скачивание CA без пина
> отклоняется: TOFU = MITM). Пропустите любое из пяти — установка прервётся на
> Launch-condition. Готовую команду с подставленными токеном и пином показывает UI;
> вручную пин берётся так: `sha256sum certs/ca.crt`.

MSI кладёт агента в `C:\Program Files\RoutineOps`, выполняет enrollment, ставит, запускает
и хардерит службу `RoutineOps-agent`, поднимает трей — без ребута. Детали, повторная
установка и сборка MSI: [build/msi/README.md](../build/msi/README.md).

#### macOS — .pkg (основной канал)

Пакет лежит на сервере: `https://mdm.example.com/downloads/RoutineOps-agent.pkg`
(кладётся туда `install.sh` из `build/pkg/RoutineOps-agent.pkg`). Кнопки в UI для него нет —
качайте по прямой ссылке.

```sh
# на деплое с самоподписанным сертификатом передайте CA явно (--cacert ca.crt),
# а не отключайте проверку через -k
curl -fsSL --cacert /path/to/ca.crt \
  "https://mdm.example.com/downloads/RoutineOps-agent.pkg" -o /tmp/RoutineOps-agent.pkg
sudo installer -pkg /tmp/RoutineOps-agent.pkg -target /
```

> **Ставьте пакет из терминала, а не двойным кликом.** `.pkg` не подписан
> Developer ID и не нотаризован — Gatekeeper заблокирует установку из Finder.
> `sudo installer` этот путь обходит.

Пакет кладёт только бинарь `/usr/local/bin/RoutineOps-agent`; enrollment он сам не делает
(если только root заранее не положил `/tmp/mdm-enroll.env`). Допишите вручную —
postinstall печатает ту же команду:

```sh
sudo /usr/local/bin/RoutineOps-agent enroll -install-service \
  -enroll-url https://mdm.example.com/api/v1/enroll -server mdm.example.com:50051 \
  -token <токен> \
  -ca /usr/local/etc/mdm/ca.crt \
  -ca-url https://mdm.example.com/ca.crt -ca-sha256 <hex sha256 от ca.crt>
```

> **После обновления пакета поверх работающего агента перезапустите службы вручную.**
> `.pkg` заменяет бинарь на диске, но LaunchDaemon продолжает крутить старый процесс:
> ```sh
> sudo launchctl kickstart -k system/RoutineOps-agent
> sudo launchctl kickstart -k "gui/$(id -u)/RoutineOps-agent.tray"   # трей, при наличии
> ```

Раскладка на macOS: демон `/Library/LaunchDaemons/RoutineOps-agent.plist`, трей
`/Library/LaunchAgents/RoutineOps-agent.tray.plist`, данные и серты `/var/lib/RoutineOps-agent/`,
логи `/Library/Logs/RoutineOps/`.

#### Linux и macOS — сгенерированный установщик

Скачайте `install-mdm.sh` кнопкой в UI (или `GET /api/v1/installer?os=linux&arch=amd64&token=<токен>`) и запустите:

```bash
chmod +x install-mdm.sh
sudo bash install-mdm.sh
```

Скрипт скачает бинарь, сверит его sha256, положит в `/usr/local/bin/RoutineOps-agent`
и выполнит `enroll -install-service`.

**Что ставится на Linux:**

| Что | Где |
|---|---|
| Бинарь | `/usr/local/bin/RoutineOps-agent` |
| systemd-юнит | `/etc/systemd/system/RoutineOps-agent.service` (`Restart=always`) |
| Состояние (outbox, `*.seen`) | `/var/lib/RoutineOps-agent/` |
| Сертификаты | `/var/lib/RoutineOps-agent/certs/` |
| Лог | `/var/log/RoutineOps-agent/agent.log` |

Инвентаризация ПО на Linux работает через первый найденный пакетный менеджер:
`dpkg-query` → `rpm` → `pacman` → `apk`. Ни одного не нашлось — не ошибка: железо и
ОС всё равно отправятся, список ПО будет пуст. Серийный номер читается из
`/sys/class/dmi/id/product_serial`, а если там пусто или вендорский плейсхолдер
(`Default string` и т.п.) — из `dmidecode -s system-serial-number` (нужен root и
установленный пакет `dmidecode`).

Собранные архитектуры — `amd64` и `arm64` (`make build-linux`, `make build-linux-arm64`),
но штатные `install.sh`/`update.sh` публикуют только `amd64`; см.
[«Публикация релиза агента»](#публикация-релиза-агента).

> **Чего на Linux нет** (сервер это учитывает, устройство остаётся управляемым):
> - **полноэкранного оверлея блокировки** — команда `lock` принимается, состояние
>   персистится и переживает перезапуск, но окна с паролем не рисуется;
> - **хранилища ключей ОС** (`-cert-source keystore`) — на Linux только файловые
>   сертификаты, это штатный путь;
> - **трея** — подкоманда `tray` завершится с кодом 2;
> - **tamper-protection** — на Linux защиты от удаления нет; она есть на Windows (SafeBoot + реестр) и macOS (`schg`), см. [tamper-protection.md](tamper-protection.md). `tamper-disarm` на Linux вернёт ошибку «не реализована».

---

## Проверка

Логи сервера:

```bash
docker compose -f docker-compose.prod.yml logs --tail=30 server
```

Ожидаемый вывод при успешном старте:

```
INFO  config loaded
INFO  database connected
INFO  CA signer loaded, enrollment enabled
INFO  asynq worker started  redis=redis:6379
INFO  gRPC server listening addr=:50051
INFO  HTTPS server listening addr=:8081
```

Веб-интерфейс: откройте `https://<IP_или_домен>` и войдите с учётными данными из
`SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD`.

Статус службы агента на устройстве:

```bash
systemctl status RoutineOps-agent          # Linux
sudo launchctl list | grep mdm      # macOS
Get-Service RoutineOps-agent               # Windows (PowerShell)
```

Логи агента:

```bash
journalctl -u RoutineOps-agent -f                  # Linux (плюс /var/log/RoutineOps-agent/agent.log)
tail -f /Library/Logs/RoutineOps/agent.err.log     # macOS
# Windows: %ProgramData%\RoutineOps\logs\agent.log
```

После успешного enrollment устройство появится в разделе **«Устройства»**.
Если агент не выходит на связь — [field-troubleshooting.md](field-troubleshooting.md)
(`agent diag -probe` за минуту показывает причину).

---

## Конфигурация SMTP (email-уведомления)

SMTP нужен для приглашений пользователей и сброса пароля. Приглашение отправляется
из UI (роли: `it_admin` — полный доступ, `viewer` — только чтение); письмо содержит
ссылку `/accept-invite?token=...`. Добавьте в `.env.prod`:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=noreply@example.com
SMTP_PASS=<app password>
SMTP_FROM=noreply@example.com
# SMTP_TLS=true   # раскомментировать для порта 465 (implicit TLS)
```

Правила, на которых спотыкаются чаще всего:

- Порт **587** = STARTTLS (`SMTP_TLS=false`), порт **465** = implicit TLS (`SMTP_TLS=true`).
- Многие провайдеры требуют, чтобы **`SMTP_FROM` совпадал с `SMTP_USER`** (логином),
  иначе отправка отклоняется.
- Используйте **app password** (пароль приложения), а не пароль от почтового ящика.
- Пустой `SMTP_HOST` = почта выключена, в логе `mailer disabled`.
- Успешная отправка **не пишет ничего** в лог — отсутствие строки об ошибке и есть
  признак успеха.

Диагностика:

```bash
docker compose -f docker-compose.prod.yml logs server | grep "send invite"
```

> **Важно:** ошибка SMTP не блокирует создание приглашения — оно сохраняется в БД, а
> ссылка возвращается в ответе API (`invite_url`). Если письмо не дошло, ссылку можно
> скопировать оттуда и передать пользователю вручную.

---

## Обновление развёрнутого MDM

Одной командой (**от того же непривилегированного пользователя, без `sudo`**):

```bash
./update.sh
```

`update.sh` делает всё по порядку: бэкап БД (`backups/db-*.dump`, custom format) →
`git pull --ff-only` → пересборка контейнеров (сервис `migrate` накатит новые
миграции до старта сервера) → пересборка, подпись и публикация агентов новой
версии. Парк подтянет агентов self-update'ом (проверка раз в 6 часов,
`ROUTINEOPS_UPDATE_INTERVAL`). Детали и откат — [self-hosted-deploy.md](self-hosted-deploy.md).

Чек-лист вокруг обновления:

1. Сверьте `.env.prod` с новыми дефолтами — см. [«Ловушка перекрытых дефолтов»](#ловушка-перекрытых-дефолтов).
2. Запустите `./update.sh`.
3. **Обновите установщики вручную, если в релизе приехал новый MSI/.pkg.**
   `update.sh` публикует только голые бинари для self-update и **не трогает**
   `releases/` — туда файлы копирует лишь `install.sh`:
   ```bash
   cp build/msi/RoutineOps-agent.msi releases/RoutineOps-agent.msi
   cp build/pkg/RoutineOps-agent.pkg releases/RoutineOps-agent.pkg
   ```
   Без этого кнопка «Скачать MSI» в UI продолжит отдавать **старый** установщик.
   На уже установленные агенты это не влияет — они обновляются сами.
4. Убедитесь, что всё поднялось:
   ```bash
   docker compose -f docker-compose.prod.yml logs --tail=20 server
   ```

Версию агента каждого устройства видно в UI и в БД (`devices.agent_version`).

> Агенты, собранные без `-ldflags "-X main.version=..."` (версия `dev`),
> самообновление пропускают. Для тестового окружения проще переустановить агент
> вручную через новый installer-скрипт из UI.

---

## Управление сервером

```bash
# Перезапуск
docker compose -f docker-compose.prod.yml restart

# Логи
docker compose -f docker-compose.prod.yml logs -f server

# Остановка
docker compose -f docker-compose.prod.yml down

# Резервное копирование БД (custom format — восстанавливается pg_restore --clean)
mkdir -p backups
docker compose -f docker-compose.prod.yml exec -T postgres pg_dump -U mdm -Fc mdm > backups/db-$(date +%Y%m%d).dump
```

Полный список критичных активов, процедуры восстановления и мониторинг —
[operations.md](operations.md).

---

## Сертификаты

Структура каталога:

```
certs/
  ca.crt       — корневой CA (нужен агентам для проверки сервера)
  ca.key       — приватный ключ CA (храните в безопасном месте)
  server.crt   — серверный сертификат
  server.key   — приватный ключ сервера
  agents/
    <device_id>/
      agent.crt  — клиентский сертификат агента
      agent.key  — приватный ключ агента
      ca.crt     — копия CA для агента
```

Сроки жизни и отсутствие автопродления:

| Сертификат | Срок | Что делать до истечения |
|---|---|---|
| Root CA | 10 лет | Перевыпуск = переустановка/перерегистрация всех агентов. `ca.key` бэкапить обязательно |
| Серверный | 1 год | Перевыпустить (`gen-certs.sh` после удаления старой пары, не забыв `SERVER_SANS`). Парк замену не заметит: агенты доверяют CA, а не серту |
| Агентский (выдаётся при enrollment) | 1 год | Автопродления нет. По истечении агент теряет mTLS-канал → «Перерегистрировать» в UI и повторный enrollment |

Проверить срок:

```bash
openssl x509 -enddate -noout -in certs/ca.crt
openssl x509 -enddate -noout -in certs/server.crt
```

Процедуры ротации — [operations.md](operations.md).

---

## Типичные проблемы

### Сервер не поднимается

| Симптом | Причина | Что делать |
|---|---|---|
| `KeyError: 'ContainerConfig'` при `docker-compose up` | `docker-compose` v1.29.2 несовместим с Docker Engine 25+ | Установить Compose v2 (раздел «Требования») и использовать `docker compose` без дефиса |
| `docker: unknown command: docker compose` | Плагин Compose v2 не установлен | Установить его (раздел «Требования») |
| Postgres: `superuser password is not specified` | В `.env.prod` не задан `POSTGRES_PASSWORD` | Задать; файл должен лежать в корне проекта рядом с `docker-compose.prod.yml` |
| `password authentication failed for user "mdm"` | `POSTGRES_PASSWORD` и пароль в `DATABASE_DSN` разошлись, либо в пароле есть `$` | Исправить и пересоздать volume: `docker compose -f docker-compose.prod.yml down -v && … up -d` |
| `redis eval error: dial tcp [::1]:6379` | В `.env.prod` не задан `REDIS_ADDR` | Добавить `REDIS_ADDR=redis:6379` |
| `migrate` отказывается стартовать: есть таблицы, нет `schema_migrations` | Старая инсталляция с ручными миграциями | Одноразовый backfill — [self-hosted-deploy.md](self-hosted-deploy.md#существующие-инсталляции-один-раз-засидить-schema_migrations) |
| Собранный образ рапортует версию `dev` | Забыт `export VERSION=$(cat VERSION)` перед `up -d --build` | Пересобрать с переменной; self-update сравнивает именно её |

### Вход и права

| Симптом | Причина | Что делать |
|---|---|---|
| В логе `seed admin failed`, войти нечем | `SEED_ADMIN_PASSWORD` не прошёл политику (≥8 символов, 3 из 4 классов) | Задать сильный пароль. Учтите: seed выполняется на старте, для существующей БД пользователь уже мог не создаться |
| `git pull` падает на правах после обновления | Запускали `sudo ./update.sh` — `.git`, `.env.prod`, ключи стали root-owned | `sudo chown -R "$USER:$USER" .` в каталоге установки; добавить пользователя в группу `docker` и больше не использовать `sudo` |
| Cookie сессии уходит без флага `Secure` | `COOKIE_SECURE` не задан (`install.sh` его не пишет) | Добавить `COOKIE_SECURE=true` в `.env.prod` и перезапустить сервер |

### Почта

| Симптом | Причина | Что делать |
|---|---|---|
| В логе `mailer disabled` | Пустой `SMTP_HOST` | Заполнить SMTP-переменные |
| `no such host` / SERVFAIL на внешние домены из контейнера `server` | Петля встроенного Docker-DNS: `dns: [127.0.0.11]` заворачивает резолвер на самого себя. `postgres`/`redis` при этом резолвятся, а SMTP молча умирает | В актуальном `docker-compose.prod.yml` у `server` заданы внешние форвардеры (`dns: 8.8.8.8, 1.1.1.1`) — сделать `git pull` и пересоздать контейнер. Диагностика ниже |
| SMTP: отказ при отправке, письма не уходят | `SMTP_FROM` ≠ `SMTP_USER` (многие провайдеры это запрещают), либо используется пароль от ящика вместо app password, либо `SMTP_TLS` не соответствует порту | Выровнять `From` с логином; завести app password; `465` → `SMTP_TLS=true`, `587` → `false` |

Диагностика DNS-петли:

```bash
docker compose -f docker-compose.prod.yml exec server cat /etc/resolv.conf
# в строке ExtServers: не должно быть 127.0.0.11 — там должны стоять внешние резолверы

docker compose -f docker-compose.prod.yml exec server nslookup smtp.example.com
docker compose -f docker-compose.prod.yml exec server nslookup smtp.example.com 8.8.8.8
# резолвится только со вторым (явным сервером) → петля резолвера
```

### Установка агента

| Симптом | Причина | Что делать |
|---|---|---|
| Installer-скрипт содержит `# Поместите бинарь RoutineOps-agent в /usr/local/bin вручную` (или `# Поместите RoutineOps-agent.exe в $InstallDir вручную`) | Релиз агента для этой пары os/arch не зарегистрирован в БД | Выполнить [«Публикация релиза агента»](#публикация-релиза-агента) или просто `./update.sh`. Для `linux/arm64` — только вручную |
| `msiexec` мгновенно прерывается с текстом про `ENROLL_URL … CA_SHA256 …` | Не переданы все пять свойств (Launch-condition) | Скопировать команду из UI: `CA_SHA256` пропускать нельзя, MSI не содержит CA |
| Кнопка «Скачать MSI» отдаёт старый установщик | `update.sh` не обновляет `releases/` | `cp build/msi/RoutineOps-agent.msi releases/RoutineOps-agent.msi` |
| macOS: двойной клик по `.pkg` блокируется Gatekeeper | Пакет не подписан Developer ID и не нотаризован | `sudo installer -pkg <файл>.pkg -target /` |
| macOS: после установки нового `.pkg` агент рапортует старую версию | `.pkg` не перезапускает LaunchDaemon — старый процесс продолжает работать | `sudo launchctl kickstart -k system/RoutineOps-agent` |
| PowerShell: «файл не имеет цифровой подписи» | Запуск `.ps1`-установщика с политикой по умолчанию | `powershell -ExecutionPolicy Bypass -File <скрипт>.ps1` (для Windows штатный путь — MSI) |

### Агент не выходит на связь

| Симптом | Причина | Что делать |
|---|---|---|
| В логе `client cert ещё не действителен` | `not_before` в будущем: часы устройства убежали назад | Синхронизировать время (NTP) на устройстве. Сертификаты выпускаются на 1 год, автопродления нет |
| `certificate signed by unknown authority` | Неверный `ca.crt` или серт от другого CA | Сверить CA; при расхождении — «Перерегистрировать» и повторный enrollment |
| Linux: `systemctl status RoutineOps-agent` → `Unit … not found` | Enroll выполнялся без `-install-service`, либо не от root | `sudo /usr/local/bin/RoutineOps-agent enroll … -install-service` |
| Linux: юнит есть, но `activating`/`failed` в цикле | `Restart=always` перезапускает падающий процесс. Причина — в логах | `journalctl -u RoutineOps-agent -n 50 --no-pager` и `/var/log/RoutineOps-agent/agent.log` |
| Linux: устройство приехало без серийного номера | В `/sys/class/dmi/id/product_serial` пусто/плейсхолдер, а `dmidecode` не установлен | Поставить `dmidecode`; служба и так работает от root. В ВМ серийника может не быть в принципе |
| Linux: список ПО пуст | Не найден ни один из `dpkg-query`/`rpm`/`pacman`/`apk` | Ожидаемое поведение, не ошибка: остальная инвентаризация работает |
| macOS: launchd-служба не стартует (exit 1) | Нет лог-каталога, либо агент не может создать `agent_outbox/` в рабочем каталоге | `sudo mkdir -p /Library/Logs/RoutineOps`; переустановить текущим установщиком — он раскладывает `/var/lib/RoutineOps-agent/` сам |
| macOS: агент перестал работать после ребута | Признак старой ручной установки из `/tmp` (macOS чистит его при перезагрузке) | Переустановить: бинарь — `/usr/local/bin/RoutineOps-agent`, данные и серты — `/var/lib/RoutineOps-agent/` |
| Windows: служба `RoutineOps-agent` не запускается | Разное; нужен ручной прогон с явными путями | Запустить агента руками (команда ниже) и прочитать ошибку |

Ручной прогон агента на Windows (mTLS-материал MSI кладёт в подкаталог `certs`
рядом с бинарём):

```powershell
& "C:\Program Files\RoutineOps\RoutineOps-agent.exe" run `
  -server "mdm.example.com:50051" `
  -cert "C:\Program Files\RoutineOps\certs\agent.crt" `
  -key  "C:\Program Files\RoutineOps\certs\agent.key" `
  -ca   "C:\Program Files\RoutineOps\certs\ca.crt"
```

Подробная полевая диагностика (`agent diag`, чтение вывода, re-enroll) —
[field-troubleshooting.md](field-troubleshooting.md). Справочник по флагам агента —
[agent-cli.md](agent-cli.md).
