# Защита агента от удаления (tamper-protection)

Актуально на 2026-07-24 (v2.5.0).

Не даёт обычному пользователю снести агента — в том числе через безопасный режим.
Снять агента может только администратор по строгой процедуре. Основной механизм —
Windows (ниже). На macOS — упрощённый вариант (immutable-флаг `schg`, см. раздел
«macOS»). На Linux пакет `internal/agent/tamper` — no-op.

## Как устроено (Windows)

- **Флаги в реестре** (`HKLM\SOFTWARE\RoutineOps\Agent`, DWORD; правка HKLM требует админа):
  - `TamperProtection` — `1` защита взведена;
  - `SafeBootGuard` — `1` защита взведена.
- **Запуск в безопасном режиме.** Служба регистрируется в
  `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\RoutineOps-agent` и `…\Network\…`
  (значение `Service`). Поэтому она стартует и в безопасном режиме, держит свой
  `exe` залоченным — файл нельзя удалить ни в обычном, ни в безопасном режиме.
- **Сторож (enforce).** Определяет режим загрузки через `GetSystemMetrics(SM_CLEANBOOT)`:
  - **обычный режим + флаги=1** → каждые 30 с восстанавливает SafeBoot-ключи и
    возвращает флаги в `1`, если их обнулили «на ходу». Значит, в обычном режиме
    сбросить защиту нельзя — агент тут же перевзводит её;
  - **обычный режим + флаги=0 на старте** → пассивный режим: ничего не перевзводит,
    удаление разрешено;
  - **безопасный режим** → сторож не работает: служба запущена (exe залочен), но
    флаги не трогает. Только здесь админ может durably выставить `0`.

Развязка гонки «агент сам себя перевзводит»: durably обнулить флаги можно лишь
там, где сторож пассивен (безопасный режим). После reboot в обычный режим агент
читает `0` на старте и больше не перевзводит → батник снимает агента.

## Процедура снятия (только администратор)

1. Загрузиться в **безопасном режиме** (`msconfig` → Загрузка → Безопасный режим;
   либо Shift+Перезагрузка → Поиск и устранение неисправностей → Параметры
   загрузки → 4).
2. Разоружить защиту:
   ```
   "C:\Program Files\RoutineOps\RoutineOps-agent.exe" tamper-disarm
   ```
   (эквивалент: обнулить `TamperProtection` и `SafeBootGuard` в
   `HKLM\SOFTWARE\RoutineOps\Agent`). Команда работает **только** в безопасном режиме — в
   обычном вернёт ошибку, так как сторож всё равно перевзведёт флаги.
3. Перезагрузиться в **обычный** режим.
4. Скопировать `uninstall.bat` (`build/msi/uninstall.bat`) в каталог установки
   агента (`%ProgramFiles%\MDM`) и запустить **от имени администратора** — агента
   батник ищет рядом с собой. Батник проверит, что защита снята, остановит и
   удалит службу, снимет SafeBoot-ключи и флаги (`RoutineOps-agent tamper-cleanup`),
   удалит файлы (`%ProgramFiles%\RoutineOps`), данные (`%ProgramData%\RoutineOps`),
   Run-ключ трея (`HKLM\...\Run\RoutineOpsTray`) и легаси `C:\mdm-extract`.

## Команды диагностики

Windows:
```
RoutineOps-agent tamper-status     # TamperProtection / SafeBootGuard / safe_mode + подсказка
RoutineOps-agent tamper-disarm     # обнулить флаги (только в безопасном режиме)
RoutineOps-agent tamper-cleanup    # снять SafeBoot-ключи и флаги (его вызывает uninstall.bat)
```

macOS:
```
sudo RoutineOps-agent tamper-status   # schg=1/0 на /usr/local/bin/RoutineOps-agent
sudo RoutineOps-agent tamper-disarm   # chflags noschg на бинарь и оба plist'а
                               # tamper-cleanup на macOS — no-op
```

Linux: защиты нет, `tamper-status` всегда печатает нули, `tamper-disarm` вернёт ошибку
«tamper-protection на этой ОС не реализована».

## macOS

Защита проще (`tamper_darwin.go`): `tamper.Arm` навешивает системный
immutable-флаг `schg` (`chflags`) на `/usr/local/bin/RoutineOps-agent` и
Launch-plist'ы (`/Library/LaunchDaemons/RoutineOps-agent.plist`,
`/Library/LaunchAgents/RoutineOps-agent.tray.plist`). Пока флаг стоит, файлы не удалить
даже под root. Сторожа нет — флаг держит ядро. Снятие: `RoutineOps-agent tamper-disarm`
от root (делает `chflags noschg`); `tamper-status` показывает состояние флага.

⚠️ **Порядок снятия на macOS:** сначала `sudo RoutineOps-agent tamper-disarm`, только потом
`sudo RoutineOps-agent uninstall`. `service.Uninstall` делает `os.Remove` plist'а — под
флагом `schg` получите `operation not permitted` даже под root.

ℹ️ `tamper-status` на macOS проверяет **только** `/usr/local/bin/RoutineOps-agent`. Если
флаг остался на plist'ах, а с бинаря снят, статус покажет «снята». При странностях
сверяйтесь напрямую: `ls -lO /usr/local/bin/RoutineOps-agent /Library/LaunchDaemons/RoutineOps-agent.plist /Library/LaunchAgents/RoutineOps-agent.tray.plist`

## Границы

- Защита рассчитана на обычного пользователя и на «загрузился в Safe Mode и удалил».
  От локального администратора, целенаправленно знающего процедуру, полной защиты
  нет — он снимет агента штатным путём (так и задумано: это управляемое устройство).
- Защита взводится при установке службы (`agent install` и `agent enroll
  -install-service` → `tamper.Arm`). Если установка прошла без прав админа/root,
  ключи/флаги не создадутся и агент поставится без защиты от удаления. На обеих
  платформах это видно в логе: `tamper.Arm` возвращает ошибку (на macOS —
  `os.ErrPermission`, т.к. `chflags schg` требует root), а установка продолжается
  с предупреждением «не удалось взвести tamper-protection». Раньше на macOS отказ
  был молчаливым — агент оставался незащищённым, а лог рапортовал успехом.
