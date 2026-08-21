# MSI-установщик MDM-агента (Windows)

Актуально для v2.4.1 и выше. Канонический источник MSI: `mdm-agent.wxs` +
`build-msi.ps1` в этом каталоге; собранный MSI кладётся на сервер в `releases/`
и раздаётся как `/downloads/RoutineOps-agent.msi`.

Один универсальный MSI на все устройства и все деплои: ни `ca.crt`, ни ключ подписи
релизов внутрь не вшиты. Персональный одноразовый enrollment-токен, адрес сервера,
URL CA и его sha256-пин передаются при установке как properties — модель enrollment
(токен 24ч) не меняется.

## Что делает MSI

1. Кладёт `RoutineOps-agent.exe` в `C:\Program Files\RoutineOps\`. **CA внутрь MSI не вшит:** агент
   качает его по `CA_URL` и сверяет с hex-пином `CA_SHA256`. Скачивание CA без пина
   отклоняется до сетевого запроса (SEC-1: TOFU-скачивание CA в момент установки =
   MITM → rogue-сервер → RCE под SYSTEM). Пин приезжает из доверенного веб-UI.
2. Прописывает автозапуск трея: `HKLM\...\Run\RoutineOpsTray = "…\RoutineOps-agent.exe" tray`
   (иконка статуса при следующем логоне любого пользователя).
3. Запускает `RoutineOps-agent.exe enroll -enroll-url … -token … -ca-url … -ca-sha256 …
   -server … -install-service` (deferred, под SYSTEM). Агент:
   - получает серт по токену (**идемпотентно**: если валидный серт уже есть,
     повторный enroll НЕ делается — токен уже погашен, сервер вернул бы 401);
   - **ставит, СТАРТУЕТ и хардерит службу** `RoutineOps-agent` (автозапуск + авто-рестарт; DACL,
     non-admin не остановит). Установка идемпотентна: прежняя служба с тем же именем
     (в т.ч. из ручной распаковки `C:\mdm-extract`) снимается и ставится заново;
   - сразу поднимает **трей в активной сессии** (`CreateProcessAsUser`), не дожидаясь
     релогина;
   - чистит легаси (`C:\mdm-extract`).
4. При удалении (`msiexec /x`) снимает службу (`RoutineOps-agent.exe uninstall`, со стопом перед
   удалением) и чистит легаси, затем удаляет файлы и Run-ключ.
5. Кладёт `uninstall.bat` — скрипт ручного снятия для случаев, когда штатный путь недоступен
   (взведена tamper-protection, служба не снимается). ⚠️ Запускать его нужно в ОБЫЧНОМ
   режиме Windows: в безопасном отключена служба Windows Installer, и шаг снятия
   регистрации вернёт 1652. Безопасный режим — только для `tamper-disarm`, после чего
   перезагрузка (см. [tamper-protection.md](../../docs/tamper-protection.md)).

> **Регистрацию продукта снимает только `msiexec /x`** — и потому её обязан дёргать любой
> путь снятия. Ручной снос файлов и ключей её не трогает: продукт остаётся числиться
> установленным при пустом диске. `uninstall.bat` делает это сам (`RoutineOps-agent.exe
> msi-unregister`), самоснос по команде сервера — своим bat-делетером. Соответствие
> «батник внутри пакета == батник в репозитории» держит гейт
> `scripts/check-installer-versions.sh`: авторинг может быть верным, а трекнутый MSI —
> собранным из прежнего.

**Итог: после одного `msiexec /qn` подняты и служба, и трей — без ребута/релогина.**

«Автозапуск с системой» и «нельзя закрыть» обеспечивает **служба**, не трей (трей —
per-user индикатор, у служб нет UI: session-0 isolation).

### Поведение при сбое enrollment и повторной установке

Экшен `EnrollExec` помечен `Return="ignore"`: сбой enrollment (битый/погашенный токен,
сервер недоступен) **НЕ откатывает** уже разложенные файлы (раньше с `Return="check"`
Program Files оставался пустым — полевой баг v22). Итог enrollment смотреть по логу службы
(`%ProgramData%\RoutineOps\…`) или по онлайн-статусу устройства в UI — код возврата `msiexec`
его не отражает.

Повторить enroll после сбоя (enroll и установка службы идемпотентны):

```powershell
# Та же версия MSI: нужен REINSTALL. Обычный /i уходит в режим обслуживания и enroll не
# выполняет — на этом он ПРЕРЫВАЕТСЯ с внятным текстом, а не отдаёт молча 0.
msiexec /i RoutineOps-agent.msi /qn REINSTALL=ALL REINSTALLMODE=vomus `
  ENROLL_URL="https://<host>/api/v1/enroll" ENROLL_TOKEN="<новый токен>" `
  CA_URL="https://<host>/ca.crt" CA_SHA256="<hex sha256 от ca.crt>" `
  SERVER_ADDR="<host>:50051"
```

Либо просто поставить **новую версию** MSI (апгрейд: новый ProductCode → enroll
отработает как на свежей установке).

Третий случай, который раньше нигде не был описан: **файлов на диске нет, а запись в
«Установка и удаление программ» есть** (агента снимали процедурой, которая не дёргала `msiexec /x`). `REINSTALL`
здесь тоже сработает — `o` вернёт отсутствующие файлы, — но чище сначала снять сироту:

```powershell
msiexec /x "{ProductCode}" /qn     # ProductCode — имя ключа в HKLM\...\Uninstall
```

Апгрейд между MSI-версиями работает штатно (`MajorUpgrade`, `Schedule=afterInstallValidate`,
фиксированный `UpgradeCode`); серты переживают апгрейд (не MSI-компонент), поэтому новая
версия не дёргает токен повторно.

## Сборка

Бинарь кросс-собирается на Mac/Linux/в CI, упаковка — на Windows (WiX v4/v5).
Собирайте exe через `make build-win` — он зашивает self-update semver
(`-X main.version` из файла `VERSION` в корне), манифест Common Controls и
PE-VERSIONINFO (для апгрейда поверх старого exe):

```bash
make build-win                        # VERSION берётся из файла VERSION (сейчас 2.4.1)
make msi-exe                          # то же + копирует exe в build/msi/RoutineOps-agent.exe
# enterprise-агент (FileVault/escrow, build-tag; только в enterprise-срезе исходников):
make build-win AGENT_TAGS=enterprise ESCROW_RECIPIENT=age1... ESCROW_RECIPIENT_FPR=<fpr>
```

> **Не задавайте `RELEASE_PUBKEY` при сборке универсального MSI.** `make build-win`
> прокидывает его в `-X main.releasePubKey`, а вшитый ключ **авторитетнее**
> полученного от сервера — такой бинарь станет deployment-specific и на чужом
> деплое перестанет обновляться (там релизы подписаны другим per-deployer ключом).
> По умолчанию переменная пуста, и агент берёт ключ из ответа на enroll.

Никаких дополнительных файлов рядом с `RoutineOps-agent.exe` класть не нужно: в
`mdm-agent.wxs` единственный файловый компонент — `AgentExe`. Компонента `CaCert`
больше нет, `ca.crt` в MSI не упаковывается.

```powershell
# на Windows (поставит WiX .NET-tool и расширение Util при отсутствии).
# ВСЕГДА передавайте -ExePath на СВЕЖЕСОБРАННЫЙ бинарь!
pwsh build/msi/build-msi.ps1 -ExePath .\RoutineOps-agent.exe -Version 2.4.1.0 `
  -PfxPath codesign.pfx -PfxPassword ****   # подпись опциональна
```

> **Версионирование (две независимые шкалы):**
> - `-X main.version` (agent self-update semver) — файл `VERSION` в корне репо.
> - `-Version` MSI ProductVersion — `x.y.z.b`. ⚠️ Windows Installer игнорирует
>   четвёртое поле: перезаливка с ростом только `b` НЕ триггерит `MajorUpgrade`
>   (старый продукт останется, новый встанет рядом). При перезаливке поднимайте
>   третье поле (`z`) либо добавьте `AllowSameVersionUpgrades="yes"` в
>   `<MajorUpgrade>` в mdm-agent.wxs.
>
> Держите соответствие MSI-версии и SHA256 упакованного exe (скрипт печатает хеш).

> ⚠️ **Без `-ExePath` скрипт берёт лежащий рядом `build/msi/RoutineOps-agent.exe`** — он
> gitignored и НЕ обновляется сам, поэтому легко молча упаковать СТАРЫЙ бинарь (в
> полевой отладке так и собирался MSI без свежих флагов). Скрипт печатает sha256/
> время паковываемого exe и предупреждает при использовании дефолта — сверяйтесь.

### Проверка, что внутри MSI правильный бинарь

```powershell
msiexec /a RoutineOps-agent.msi /qn TARGETDIR=C:\msitest
"C:\msitest\PFiles64\RoutineOps\RoutineOps-agent.exe" enroll -h | findstr ca-url   # должна быть строка с -ca-url
```

## Установка на устройстве

```powershell
msiexec /i RoutineOps-agent.msi /qn `
  ENROLL_URL="https://<host>/api/v1/enroll" `
  ENROLL_TOKEN="<персональный одноразовый токен>" `
  CA_URL="https://<host>/ca.crt" `
  CA_SHA256="<hex sha256 от ca.crt>" `
  SERVER_ADDR="<host>:50051"
```

Все **пять** свойств обязательны — Launch-condition в `mdm-agent.wxs` прерывает
установку, если не задано хоть одно. ⚠️ Оговорка, которая раньше здесь отсутствовала и
стоила суток разбора: **эта проверка работает только на ЧИСТОЙ установке.** Если продукт
уже зарегистрирован (`Installed=true`), условие проходит по левой части, и набор свойств
не проверяется вовсе. На этот случай в авторинге есть ВТОРОЕ Launch-условие: свойства
переданы, а энроллмент в этом прогоне не выполнится — установка прерывается с подсказкой
про `REINSTALL=ALL REINSTALLMODE=vomus`. Без `SERVER_ADDR` служба ушла бы в дефолт
`localhost:55443`; без `CA_SHA256` агент отказывается качать CA по `CA_URL`
(TOFU без пина = MITM). Готовую команду с подставленными токеном и пином
показывает веб-UI; пин вручную — `sha256sum certs/ca.crt` на сервере.

## Доставка с сервера

Реализовано: канонический MSI лежит на сервере в `releases/RoutineOps-agent.msi` и
раздаётся по `/downloads/RoutineOps-agent.msi`. UI (Устройства → добавить устройство,
Windows) даёт ссылку на скачивание и генерирует готовую msiexec-команду с
per-device токеном и `ca_sha256`.

MSI собирается на Windows и коммитится в репо как `build/msi/RoutineOps-agent.msi`. В
`releases/` его копируют **и `install.sh`, и `update.sh`** (с июля 2026, коммит
`2e5a181`) — оба делают это внутри build-контейнера, где root + `umask 022` дают
файл 644, читаемый сервером (host-side `cp` от деплойера падал `Permission denied`:
`releases/` root-owned после `publish-release`, а `umask 077` дал бы 600). Поэтому
после релиза с новым установщиком достаточно положить свежий файл в
`build/msi/RoutineOps-agent.msi` и подтянуть в репо на сервере — следующий `./update.sh`
(он делает `git pull`) или `./install.sh` сам обновит `releases/RoutineOps-agent.msi`.

Ручной `sudo cp build/msi/RoutineOps-agent.msi releases/RoutineOps-agent.msi` нужен только на
сервере со старыми скриптами (до `2e5a181`), где `update.sh` установщик не трогал.
На уже установленные агенты выкладка нового установщика не влияет — они обновляются
сами. Свойства MSI:

| Property      | Значение                          |
|---------------|-----------------------------------|
| `ENROLL_URL`  | `<serverURL>/api/v1/enroll`       |
| `ENROLL_TOKEN`| персональный токен устройства     |
| `CA_URL`      | `<serverURL>/ca.crt` — откуда агент качает CA |
| `CA_SHA256`   | hex sha256 CA-бандла; без него скачивание CA отклоняется |
| `SERVER_ADDR` | `<host>:50051` (gRPC, для `-server`) |

Токен остаётся персональным/одноразовым — меняется только формат доставки (MSI вместо
прямого вызова enroll).
