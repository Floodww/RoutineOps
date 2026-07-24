<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/routineops-lockup-dark-256.png">
    <img alt="RoutineOps" src="brand/logo/routineops-lockup-light-256.png" width="360">
  </picture>
</p>

# RoutineOps

> English summary: [README.en.md](./README.en.md)

RoutineOps — self-hosted MDM/RMM для парка Windows-, macOS- и Linux-устройств: агенты держат
постоянный gRPC/mTLS-канал с вашим сервером и работают через интернет без VPN.
Версия продукта (сервер+веб) — файл [`VERSION`](./VERSION); версия агента — файл
[`AGENT_VERSION`](./AGENT_VERSION) (агент версионируется и выпускается отдельно).

<img width="2862" height="1628" alt="image" src="https://github.com/user-attachments/assets/a434096b-1196-43ec-9aed-f9ff17644402" />




## Безопасность

Любой пользователь, заинтересовавшийся подобным продуктом, задаст вопрос по безопасности, потому что это основа и первое, о чём необходимо беспокоиться. В отличие от подобных конкурирующих продуктов, которые предоставляют «pay to secure», RoutineOps таким не является. Первое правило, которого мы придерживались при разработке: «безопасность не продаётся».

Подробно с самим функционированием и моделью безопасности вы можете ознакомиться в следующих файлах: [`ARCHITECTURE.md`](./ARCHITECTURE.md) и [`SECURITY.md`](./SECURITY.md).

От себя кратко могу назвать наш стек по безопасности: **mTLS (TLS 1.3) с пиннингом приватного CA** на всём канале агентов и идентичностью по сертификату (`device_id` = CN, тело сообщений серверу не доверяется); **RBAC**; **admin-сессии на JWT** и **lockout'ом по IP и по аккаунту**; **одноразовые enroll-токены**; **Ed25519-подпись самообновления агентов** с проверкой sha256 и anti-rollback; **журнал аудита** всех действий администраторов; **secure-by-default** — обязательный сильный `JWT_SECRET`, security-заголовки (HSTS/CSP), rate-limit и cap на размер запроса. В моём понимании это максимум для self-hosted продукта. Но для полного понимания настоятельно советую обратиться к файлам, указанным выше.

## Возможности

- **Агенты для Windows, macOS и Linux** — Windows ставится универсальным MSI, macOS — `.pkg`, Linux — systemd-юнитом через сгенерированный installer-скрипт (инвентарь ПО берётся у dpkg/rpm/pacman/apk).
- **Запрос админ прав** — пользователь может на своем устройстве прямо из трея отправить заявку на админ права.
- **Инвентаризация** — hostname, ОС, CPU/RAM/диск, IP, серийный номер, версия агента, список установленного ПО, события процессов.
- **Скрипты** — разовый запуск на устройство или группу; политики по расписанию (cron), при подключении агента и по событию; библиотека скриптов и просмотр результатов.
- **Группы устройств** — членство, цвет группы, фильтр списка устройств по группе, привязка скрипт- и софт-политик, запуск скрипта на всю группу.
- **Политики ПО** — правила allowed/forbidden по устройству, группе или платформе.
- **Комплаенс политик** — по каждой софт- и скрипт-политике видно, на сколько устройств она распространяется и сколько из них Pass / Fail.
- **Блокировка устройства** — полноэкранный overlay с паролем (Windows и macOS), разблокировка работает и офлайн.
- **События и алерты** — `agent_unreachable` (устройство пропало с радаров), запрещённое ПО, несанкционированная установка/изменение настроек; группировка по типу со счётчиком неподтверждённых; уведомления в Telegram.
- **Журнал аудита** — все действия администраторов, retention настраивается (`AUDIT_RETENTION_DAYS`, по умолчанию 365 дней).
- **RBAC** — роли `it_admin` (полный доступ) и `viewer` (только чтение); приглашения пользователей по email.
- **Self-update агентов** — подписанные ed25519-релизы, проверка sha256 и подписи манифеста, защита от отката версии.
- **mTLS** — агент аутентифицируется клиентским сертификатом, сервер выпускает его при enrollment.

## Быстрый старт

1. **Сервер.** Linux (Ubuntu 22.04+ / Debian 12+), Docker + Compose v2, открытые порты 80/443 (веб, enrollment, загрузки) и 50051 (gRPC агентов). До 50 устройств хватит 1 vCPU / 2 GB RAM / 20 GB SSD. Достаточно статического IP, домен не обязателен. Подробнее: [`docs/install.md`](./docs/install.md).

2. **Установка.** Скопируйте шаблон конфигурации, заполните его и запустите — так все параметры уходят в установку сразу и наверняка:
   ```bash
   cp install.env.example install.env
   nano install.env      # PUBLIC_ADDR (внешний IP/домен) + ADMIN_EMAIL / ADMIN_PASSWORD
   ./install.sh
   ```
   Скрипт сгенерирует TLS-сертификаты, `.env.prod` с секретами, ключ подписи релизов, поднимет compose-стек (миграции накатываются автоматически) и соберёт+опубликует агентов для Windows/Linux/macOS. **`PUBLIC_ADDR`** — адрес, по которому к серверу ходят агенты и браузеры извне (внешний IP или домен): за NAT/VPN укажите его явно, иначе enroll по внешнему адресу упадёт на TLS (адрес обязан быть в SAN сертификата; внутренний IP хоста добавляется в SAN автоматически). Запускайте **без `sudo`**, от пользователя в группе `docker` — иначе root-owned `.git` и `.env.prod` сломают следующий `./update.sh` ([`docs/install.md`](./docs/install.md)). Подробнее: [`docs/self-hosted-deploy.md`](./docs/self-hosted-deploy.md).

3. **Первый вход:** `https://<IP-или-домен>` с кредами `ADMIN_EMAIL`/`ADMIN_PASSWORD`. Пароль обязан пройти политику сложности (минимум 8 символов, 3 из 4 классов) — со слабым паролем админ не будет создан (в логе сервера — `seed admin failed`).

4. **Агенты уже опубликованы** шагом 2 и доступны с сервера (`/downloads/...`). Обновление в дальнейшем: запустить `./update.sh` — он подтянет новый релиз (`git pull`), пересоберёт сервер и переопубликует агентов, а парк подтянет новую версию сам (по умолчанию раз в 6 часов). Подробнее: [`docs/self-update.md`](./docs/self-update.md).

   > **Кнопки «Скачать MSI/PKG» в UI** отдают `releases/RoutineOps-agent.{msi,pkg}` (по `/downloads/`). Эти установщики обновляют **и `install.sh`, и `update.sh`** — оба копируют их из `build/msi/RoutineOps-agent.msi` и `build/pkg/RoutineOps-agent.pkg` (внутри build-контейнера, чтобы права были читаемы сервером). Значит чтобы выложить новый установщик, достаточно положить свежесобранный файл в `build/msi/RoutineOps-agent.msi` / `build/pkg/RoutineOps-agent.pkg` (MSI собирается на Windows — `build/msi/build-msi.ps1`, PKG на macOS) и закоммитить/подтянуть его в репо на сервере: следующий `./update.sh` (или `./install.sh`) сам скопирует его в `releases/`. Отдельный ручной `sudo cp … releases/` нужен только на сервере со старыми скриптами (до июля 2026, когда `update.sh` установщики не обновлял).

5. **Подключение устройства:** в веб-интерфейсе «Устройства» → «Добавить устройство» — получите одноразовый токен (TTL 24 часа) и готовую команду установки. Windows — универсальный MSI: `msiexec /i RoutineOps-agent.msi /qn ENROLL_URL=... ENROLL_TOKEN=... CA_URL=... CA_SHA256=... SERVER_ADDR=...` (все пять свойств обязательны: CA не вшит в MSI, агент качает его по `CA_URL` и пинит по `CA_SHA256`). macOS — `.pkg` с сервера (`sudo installer -pkg RoutineOps-agent.pkg -target /`, пакет не подписан — двойной клик заблокирует Gatekeeper). Linux/macOS — сгенерированный инсталлер `sudo bash install-mdm.sh`. Подробнее: [`docs/install.md`](./docs/install.md) и [`docs/enrollment.md`](./docs/enrollment.md).

## Документация

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — компоненты системы, каналы связи, границы доверия.
- [`docs/install.md`](./docs/install.md) — полная установка: требования, сертификаты, порты, публикация агентов.
- [`docs/self-hosted-deploy.md`](./docs/self-hosted-deploy.md) — `install.sh` / `update.sh`, бэкапы, миграции, откат.
- [`docs/enrollment.md`](./docs/enrollment.md) — подключение устройств: одноразовые токены, выпуск сертификатов.
- [`docs/agent-cli.md`](./docs/agent-cli.md) — команды, флаги и env-переменные бинарника агента.
- [`docs/config-as-code.md`](./docs/config-as-code.md) — группы, скрипты и политики в YAML: `routineops export` / `apply`, конфигурация парка в git.
- [`docs/self-update.md`](./docs/self-update.md) — самообновление агентов: подписанные релизы, публикация версии, anti-rollback.
- [`docs/operations.md`](./docs/operations.md) — эксплуатация: бэкапы и восстановление, типовые операции.
- [`docs/field-troubleshooting.md`](./docs/field-troubleshooting.md) — диагностика агента на устройстве (`agent diag`), типовые причины «агент не выходит на связь».
- [`docs/tamper-protection.md`](./docs/tamper-protection.md) — защита агента от удаления пользователем (Windows: SafeBoot + реестр; macOS: флаг `schg`; на Linux — нет), процедура штатного снятия.
- [`docs/jwt-secret-rotation.md`](./docs/jwt-secret-rotation.md) — ротация `JWT_SECRET` (корень доверия admin-сессий).
- [`SECURITY.md`](./SECURITY.md) — модель доверия и обязанности оператора при self-hosted развёртывании.

Что обязательно бэкапить: дамп PostgreSQL, каталог `certs/` (особенно `ca.key`),
`release_ed25519.pem` (потеря = парк больше не получит обновлений), `.env.prod`.
Детали — в [`docs/self-hosted-deploy.md`](./docs/self-hosted-deploy.md).

## Стек

| Компонент | Технология |
|---|---|
| Агент | Go |
| Сервер | Go (монолит) |
| Связь агент ↔ сервер | gRPC + Protocol Buffers + mTLS |
| База данных | PostgreSQL 16 |
| Очередь доставки задач агентам | Redis + Asynq |
| Веб-интерфейс | React + TypeScript (Vite), раздаётся nginx-контейнером (`web` в compose) |

## Локальная разработка

```bash
# Поднять Postgres + Redis
docker compose up -d

# Запустить тесты
TEST_POSTGRES_DSN="postgres://mdm:mdm@localhost:55432/mdm?sslmode=disable" go test ./...

# Запустить тесты с детектором гонок
TEST_POSTGRES_DSN="postgres://mdm:mdm@localhost:55432/mdm?sslmode=disable" go test -race ./...
```

> Postgres слушает на хост-порту **55432** (внутри контейнера — 5432), пароль **mdm**.

## Enterprise

Enterprise-редакция добавляет к возможностям выше:

| Возможность | Статус |
|---|---|
| FileVault-эскроу ключей восстановления (macOS) | ✅ |
| Принудительная FileVault-блокировка устройства | ✅ |
| Удаление ПО с устройства из интерфейса | в разработке |
| Мультитенантность (отдельные тенанты со своими политиками) | в разработке |
| SSO/OIDC, MFA, SCIM, экспорт в SIEM | в разработке |
| Удалённое подключение к рабочему столу | в планах |

В этой сборке enterprise-функции отсутствуют физически (например,
`lock_mode=filevault` вернёт 409). Полный список и планы — в [`docs/ROADMAP.md`](./docs/ROADMAP.md).

**По вопросам Enterprise-лицензии, багам и предложениям** — пишите на
[charmander020104@gmail.com](mailto:charmander020104@gmail.com) или в Telegram
[@flood_j](https://t.me/flood_j), либо открывайте
[Issue](https://github.com/Floodww/RoutineOps/issues) в этом репозитории.

<p align="center">
  <img src="brand/app-icon/windows/routineops-128.png" alt="" width="48">
  &nbsp;&nbsp;
  <img src="brand/app-icon/macos/icon_128x128.png" alt="" width="48">
  &nbsp;&nbsp;
  <img src="brand/logo/routineops-logo-128.png" alt="RoutineOps" width="48">
</p>
