# Полевая диагностика агента

Памятка для развёртывания на реальных устройствах: как за минуту понять, почему
агент не выходит на связь, и что чинить. Главный инструмент — `agent diag`.

## Pre-flight (после установки, до «боевого» запуска)

```sh
# Файловые серты:
agent diag -server <host:50051> -server-name routineops-server \
           -cert /path/agent.crt -key /path/agent.key -ca /path/ca.crt -probe

# Серт в хранилище ОС (Keychain/Cert Store):
agent diag -server <host:50051> -server-name routineops-server \
           -cert-source keystore -keystore-label <device_id> -ca /path/ca.crt -probe
```

- **Exit 0** — серт читается, не истёк, mTLS-dial прошёл → можно запускать службу.
- **Exit 1** — серт нечитаем/истёк или `-probe` не подключился. Не запускать, см. таблицу ниже.

`-probe` делает реальный mTLS-хендшейк с сервером — это и есть проверка «дойдём ли».

## Как читать вывод `agent diag`

```
client cert:
  subject:  CN=<device_id>      ← CN всегда = device_id (его проставляет сервер при энроллменте)
  issuer:   CN=RoutineOps Root CA
  expires:  через N дн (...)     ← ВНИМАНИЕ при ≤14 дн, ИСТЁК при истечении
CA (...):
  expires:  через N дн          ← если CA истёк — перевыпуск всей цепочки
state:
  outbox:       ... — K записей  ← растёт и не сливается → сервер недоступен
  task-seen:    ... — есть/нет    ← идемпотентность задач (переживает рестарт)
  script-seen:  ... — есть/нет    ← дедуп выполненных скриптов
  policy-cache: ... — есть/нет    ← локальная политика ПО (работает оффлайн)
```

## Лог службы при старте

Агент при запуске сам пишет здоровье серта (одна из строк):

| Строка в логе | Что значит | Действие |
|---|---|---|
| `client cert в порядке` | серт валиден | — |
| `client cert скоро истекает` | ≤ 14 дней | запланировать re-enroll |
| `client cert ИСТЁК` | просрочен | re-enroll сейчас (см. ниже) |
| `client cert ещё не действителен` | `not_before` в будущем → **сдвиг часов** | синхронизировать время на машине (NTP) |
| `client cert: не удалось загрузить` | нет файла / нет ключа в хранилище | проверить пути/`-cert-source`/label |

## Симптом → диагноз → фикс

| Симптом | Команда диагностики | Причина / фикс |
|---|---|---|
| Не коннектится, в логе бэкофф | `agent diag -probe` | exit 1 + текст ошибки пробы: см. ниже |
| `-probe`: `connection refused` / таймаут | — | сервер недоступен/файрвол/неверный `-server`. Проверить адрес и сетевой доступ |
| `-probe`: TLS / `certificate signed by unknown authority` | `agent diag` (issuer/CA) | неверный `-ca` или серт от другого CA. Сверить `ca.crt` |
| `-probe`: `bad certificate` / handshake fail | `agent diag` (expires) | client cert истёк или выпущен другим CA → re-enroll |
| `client cert ещё не действителен` | `agent diag` | `not_before` в будущем: часы устройства ушли назад. Синхронизировать время (NTP) — серты выпускаются на 1 год, автопродления нет, и пере-enroll со сбитыми часами выдаст такой же «будущий» серт |
| outbox растёт, не сливается | `agent diag` (state) | сервер недоступен — алерты не теряются, дошлются после восстановления. Чинить связь |
| задача выполнилась дважды | проверить `task-state` файл | `-task-state` указывает на непишемый путь → дедуп только в памяти, теряется при рестарте. Дать пишемый путь |
| macOS: `uninstall` падает с `operation not permitted` (plist/бинарь не удаляются) | `sudo RoutineOps-agent tamper-status` | взведена tamper-protection (`schg`): `sudo RoutineOps-agent tamper-disarm`, затем повторить `uninstall` |
| Windows: `msiexec /i` отдал **0**, но службы нет и `%ProgramFiles%\RoutineOps` пуст | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "RoutineOps Agent" /reg:64` | Сиротская регистрация установщика: агента снимали руками, не сняв запись продукта. Он числится установленным, `msiexec` уходит в режим обслуживания и пропускает и проверку свойств, и энроллмент. Лечение: `msiexec /x {ProductCode} /qn` (ProductCode = имя найденного ключа), затем повторить установку командой из UI. Штатно этого не бывает: `uninstall.bat` снимает запись сам (`msi-unregister`) |
| Windows: `msiexec /i` прерывается, в журнале «Приложение» запись MsiInstaller про «уже зарегистрирован» | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "RoutineOps Agent" /reg:64` | Ожидаемое поведение, а не сбой: установщик отказывается ставиться поверх уже зарегистрированного продукта, потому что энроллмент в этом прогоне не выполнится. Повторить ту же команду с `REINSTALL=ALL REINSTALLMODE=vomus`; если агента на диске нет — сперва `msiexec /x {ProductCode} /qn`. Под `/qn` текст отказа виден только в журнале и в `/l*v`-логе |

## Linux: служба под systemd

Раскладка: бинарь `/usr/local/bin/RoutineOps-agent`, юнит `/etc/systemd/system/RoutineOps-agent.service`,
состояние и серты `/var/lib/RoutineOps-agent/` (+ `certs/`), лог `/var/log/RoutineOps-agent/agent.log`.

```sh
systemctl status RoutineOps-agent            # active (running)?
journalctl -u RoutineOps-agent -n 50 --no-pager   # почему упал
journalctl -u RoutineOps-agent -f            # смотреть вживую
tail -f /var/log/RoutineOps-agent/agent.log  # собственный лог агента
```

| Симптом | Причина / фикс |
|---|---|
| `Unit RoutineOps-agent.service could not be found` | enroll выполнялся без `-install-service` или не от root. Повторить: `sudo RoutineOps-agent enroll … -install-service` |
| Юнит в цикле `activating` → `failed` | `Restart=always` поднимает падающий процесс. Настоящая причина — в `journalctl -u RoutineOps-agent`: чаще всего нечитаемые серты или неверный `-server` |
| `запись unit /etc/systemd/system/RoutineOps-agent.service (нужен root?)` | enroll запущен от обычного пользователя. Повторить под `sudo` |
| Устройство приехало без серийного номера | `/sys/class/dmi/id/product_serial` пуст или содержит вендорский плейсхолдер (`Default string`, `To be filled by O.E.M.`), а фолбэк `dmidecode` не установлен. Поставить пакет `dmidecode` (служба и так работает от root). В части ВМ серийника нет в принципе — это нормально |
| В инвентаре пустой список ПО | Не найден ни один из `dpkg-query` / `rpm` / `pacman` / `apk`. Не ошибка: железо и ОС всё равно отправляются |
| `cert-source=keystore не поддержан в этой сборке` | Хранилище ключей ОС на Linux не реализовано. Штатный путь — файловые серты (`-cert-source file`, дефолт) |
| Команда `lock` прошла, но экран не заблокировался | На Linux нет полноэкранного оверлея: состояние блокировки применяется и персистится (`lock.json`), окна с паролем не рисуется. Ожидаемое поведение |
| `подкоманда tray поддерживается только на Windows и macOS` (exit 2) | Трея на Linux нет. Служба от этого не страдает |

## Re-enroll при истёкшем/битом серте

Старый серт больше не примут на mTLS. Перевыпуск — по новому одноразовому токену:
в UI на странице устройства нажать **«Перерегистрировать»** (токен живёт 24 часа),
затем на машине:

```sh
agent enroll -enroll-url https://<host>/api/v1/enroll -token <one-time-token> \
             -ca /path/ca.crt -cert /path/agent.crt -key /path/agent.key
# (напрямую в сервер, минуя nginx: https://<host>:8081/api/v1/enroll — только
#  если порт 8081 опубликован наружу; по умолчанию он привязан к 127.0.0.1)
# при keystore-режиме добавить: -cert-source keystore
# повторно зарегистрировать службу: -install-service
```

> ⚠️ Если старый серт ещё **НЕ истёк** (например, выпущен другим CA или
> аннулирован кнопкой «Перерегистрировать»), `agent enroll` идемпотентно
> пропустит перевыпуск («идентичность уже выдана — пропускаю энроллмент»)
> и токен не будет использован. В этом случае перед `agent enroll`
> удалите/переместите старые `agent.crt` и `agent.key` (в keystore-режиме —
> удалите идентичность из хранилища ОС).

После успеха `agent diag` снова должен давать exit 0.

## Быстрый чек-лист на устройство

1. `agent diag -probe` → exit 0? Если нет — таблица выше.
2. CN в выводе = ожидаемый `device_id`?
3. `expires` > 14 дней?
4. Запустить службу, в логе — `client cert в порядке` и `стрим Connect открыт`.

> Сервер можно перезапускать/редеплоить — агенты переподключаются сами
> (переподключение с бэкоффом встроено в агент), ручное вмешательство на
> устройствах не требуется.
