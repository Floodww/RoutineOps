@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
REM ============================================================================
REM  uninstall.bat — снятие RoutineOps-агента с защитой от удаления (tamper-protection).
REM
REM  Полная процедура (обычный пользователь снять агента НЕ может — нужен админ):
REM    1. Загрузиться в БЕЗОПАСНОМ режиме Windows
REM       (msconfig -> Загрузка -> Безопасный режим, либо Shift+Перезагрузка ->
REM        Поиск и устранение неисправностей -> Параметры загрузки -> 4).
REM    2. Разоружить защиту:
REM         "C:\Program Files\RoutineOps\RoutineOps-agent.exe" tamper-disarm
REM       (либо вручную: HKLM\SOFTWARE\RoutineOps\Agent ->
REM        TamperProtection=0 и SafeBootGuard=0).
REM    3. Перезагрузиться в ОБЫЧНЫЙ режим.
REM    4. Запустить ЭТОТ батник от имени администратора.
REM ============================================================================

REM --- права администратора ---
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [ОШИБКА] Запустите этот файл от имени администратора.
  pause
  exit /b 1
)

REM --- работать из копии во %TEMP% ---
REM
REM 🔴 Поймано на живом прогоне, и без этого вся процедура обрывается на середине.
REM uninstall.bat — КОМПОНЕНТ самого MSI, поэтому `msiexec /x` его удаляет. А cmd.exe
REM читает батник с диска по мере исполнения: как только файл исчезает, интерпретатор
REM печатает «The batch file cannot be found» и прекращает работу. На машине это выглядело
REM так: регистрация снята, а отчёт, чистка реестра и снос каталога не выполнились вовсе,
REM код возврата 1. Копия во %TEMP% установщику не принадлежит, и он её не трогает.
REM
REM Переход БЕЗ call: запуск другого батника без call передаёт управление насовсем, и
REM исходный файл больше не читается — именно это здесь и нужно. Признак — аргумент
REM --staged, а не сравнение путей: %TEMP% может прийти коротким именем 8.3.
if "%~1"=="--staged" goto :staged
copy /y "%~f0" "%TEMP%\routineops-uninstall.bat" >nul 2>&1
if not exist "%TEMP%\routineops-uninstall.bat" goto :staged
"%TEMP%\routineops-uninstall.bat" --staged "%~dp0"

:staged
REM Каталог, откуда батник запустили изначально: у копии %~dp0 указывает во временный.
set "SRCDIR=%~dp0"
if "%~1"=="--staged" set "SRCDIR=%~2"
set "EXE=%SRCDIR%RoutineOps-agent.exe"
if not exist "%EXE%" set "EXE=%ProgramFiles%\RoutineOps\RoutineOps-agent.exe"

REM --- проверка, что защита разоружена (по умолчанию считаем снятой, если значения нет) ---
set "PROT=0x0"
set "GUARD=0x0"
for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\RoutineOps\Agent" /v TamperProtection 2^>nul ^| find "TamperProtection"') do set "PROT=%%a"
for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\RoutineOps\Agent" /v SafeBootGuard 2^>nul ^| find "SafeBootGuard"') do set "GUARD=%%a"

if /i not "%PROT%"=="0x0" goto :armed
if /i not "%GUARD%"=="0x0" goto :armed
goto :remove

:armed
echo [СТОП] Tamper-protection ВЗВЕДЕНА (TamperProtection=%PROT% SafeBootGuard=%GUARD%).
echo.
echo Сначала разоружите её в БЕЗОПАСНОМ режиме Windows:
echo     "%EXE%" tamper-disarm
echo затем перезагрузитесь в обычный режим и запустите этот батник снова.
pause
exit /b 2

:remove
echo Останавливаю службу RoutineOps-агента...
sc stop RoutineOps-agent >nul 2>&1
REM дать службе закрыться и освободить exe. ping, а не timeout: timeout отказывается
REM работать при перенаправленном stdin («Input redirection is not supported») и молча
REM пропускает ожидание — поймано на живом прогоне. В bat-делетере самосноса тот же приём.
ping 127.0.0.1 -n 4 >nul

REM --- уйти из сносимого каталога ---
REM
REM Батник лежит в самом каталоге установки, и рабочий каталог cmd.exe по умолчанию тот
REM же. Каталог, который является cwd живого процесса, Windows удалить не даёт: rmdir
REM снесёт содержимое, но не сам каталог, и честный отчёт внизу напечатает «[ЧАСТИЧНО]»
REM при фактически полном снятии. Тем же упирался бы RemoveFolders внутри msiexec /x.
cd /d "%SystemRoot%"

echo Снимаю SafeBoot-регистрацию и флаги защиты...
if exist "%EXE%" start "" /wait "%EXE%" tamper-cleanup

echo Удаляю службу...
sc delete RoutineOps-agent >nul 2>&1

REM --- снять трей ДО снятия установщика и до сноса каталога ---
REM
REM Служба остановлена и удалена, но сам процесс трея продолжает жить в сессии вошедшего
REM пользователя и ДЕРЖИТ exe. Об это спотыкается и rmdir («Отказано в доступе к файлу
REM RoutineOps-agent.exe», каталог остаётся, и выглядит это как «батник не отработал»), и
REM msiexec /x: занятый файл он не удаляет, а переименовывает в .rbf и откладывает до
REM перезагрузки. Поэтому taskkill идёт ПЕРЕД обоими шагами — тот же порядок закреплён в
REM самосносе (buildDeleterScript: msiexec после taskkill).
REM
REM Трей и оверлей — не службы, SCM их не воскрешает, поэтому безусловный taskkill здесь
REM безопасен: службу мы сняли выше (sc delete), и воскрешать её через FailureActions
REM некому. `.old` — на случай зависшего процесса прерванного самообновления.
echo Снимаю процессы агента (трей, оверлей)...
taskkill /F /IM RoutineOps-agent.exe >nul 2>&1
taskkill /F /IM RoutineOps-agent.exe.old >nul 2>&1
REM Дать Windows отпустить хэндлы: сразу после taskkill файл ещё занят.
ping 127.0.0.1 -n 3 >nul

REM --- снять регистрацию установщика ---
REM
REM 🔴 Сердце процедуры, и раньше этого шага здесь не было. Всё, что делает батник выше и
REM ниже, — служба, файлы, ключи — НЕ трогает регистрацию продукта в базе Windows
REM Installer. Она остаётся сиротой: в «Установка и удаление программ» агент числится
REM установленным, хотя на диске от него ничего нет. Следующая установка ТОГО ЖЕ пакета
REM видит Installed=true, уходит в режим обслуживания и не выполняет ни проверку
REM обязательных свойств, ни энроллмент — msiexec отдаёт 0, а на машине не появляется ни
REM службы, ни сертификатов. Поймано в поле: молчаливый успех при нулевом результате.
REM
REM Ищет продукт и зовёт msiexec сам агент: батник не знает ни UpgradeCode, ни
REM ProductCode. Поиск по имени в реестре разъехался бы при ренейме, а `wmic product` на
REM живой машине запускает переконфигурацию каждого установленного MSI.
REM
REM Работает НЕ установленный exe, а его копия под другим именем образа — см. :unregister.
set "MSIRC=9"
if not exist "%EXE%" (
  echo [ВНИМАНИЕ] RoutineOps-agent.exe не найден — снять регистрацию установщика нечем.
) else (
  echo Снимаю регистрацию установщика...
  call :unregister
)

if "%MSIRC%"=="0" echo   Регистрация установщика снята или её не было.
if "%MSIRC%"=="3" echo   Регистрация установщика снята; часть файлов удалится после перезагрузки.
if "%MSIRC%"=="2" (
  echo   [ВНИМАНИЕ] Установленный агент не принял команду msi-unregister: он либо старше
  echo   этого скрипта, либо не смог прочитать свою конфигурацию. Запись в «Установка и
  echo   удаление программ» останется — снимите её вручную:
  echo       msiexec /x {ProductCode} /qn
)
if "%MSIRC%"=="1" (
  echo   [ВНИМАНИЕ] Снять регистрацию установщика не удалось — см. вывод выше.
  echo   Запись в «Установка и удаление программ» останется.
)

REM подчистить ключи на случай, если exe уже удалён, tamper-cleanup не отработал или
REM установщик не смог снять свой Run-ключ. Порядок «сначала msiexec, потом руками» —
REM тот же, что в самосносе: штатное снятие первым, ручное добивание вторым.
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\RoutineOps-agent" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\RoutineOps-agent" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\RoutineOps" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v RoutineOpsTray /f >nul 2>&1

echo Удаляю файлы...
rmdir /s /q "%ProgramFiles%\RoutineOps" >nul 2>&1
rmdir /s /q "%ProgramData%\RoutineOps" >nul 2>&1
REM Следы прежних ручных установок (распаковка MSI вручную ставила службу из этого каталога).
rmdir /s /q "C:\mdm-extract" >nul 2>&1

REM --- сказать правду об исходе ---
REM
REM Раньше батник печатал «Готово» безусловно, в том числе когда rmdir не смог снести
REM каталог: `>nul 2>&1` глушит и вывод, и ошибку. Сообщение об успехе, не зависящее от
REM успеха, — худший вид отчёта: пользователь уходит уверенным, а агент остаётся на диске.
REM
REM Проверяем не «есть ли каталог», а «осталось ли в нём хоть что-то, кроме этого скрипта».
REM Каталог законно переживает удачное снятие: в нём лежит сам батник, и cmd.exe держит его
REM открытым до последней строки — ругаться на это значило бы врать в обратную сторону.
REM А вот содержимое проверить ОБЯЗАТЕЛЬНО, и не ради бинаря: бинарь — компонент MSI, его
REM удаляет сам установщик. Приватный ключ устройства (certs\agent.key) компонентом НЕ
REM является, он создаётся на энроллменте, и единственный, кто его сносит, — тот самый
REM rmdir выше с заглушённым кодом возврата. Проверка только по бинарю пропускала бы
REM «Готово» на машине с оставшимся ключом.
set "LEFT="
if exist "%ProgramFiles%\RoutineOps\certs" set "LEFT=каталог certs (в нём приватный ключ устройства)"
for /f "delims=" %%d in ('dir /b /ad "%ProgramFiles%\RoutineOps" 2^>nul') do set "LEFT=подкаталог %%d"
for /f "delims=" %%f in ('dir /b /a-d "%ProgramFiles%\RoutineOps" 2^>nul ^| findstr /v /i /c:"uninstall.bat"') do set "LEFT=файл %%f"

if defined LEFT (
  echo.
  echo [ЧАСТИЧНО] Служба снята и защита отключена, но в каталоге установки осталось:
  echo     %LEFT%
  echo     %ProgramFiles%\RoutineOps
  echo Обычно это значит, что файл ещё держит какой-то процесс. Перезагрузитесь и
  echo запустите этот батник ещё раз — на чистой загрузке остаток снимется.
  pause
  exit /b 3
)

if "%MSIRC%"=="9" (
  echo.
  echo [ПРОВЕРЬТЕ] Файлы агента сняты, но проверить регистрацию установщика было нечем:
  echo исполняемого файла агента на машине уже не было. Если агента ставили из MSI,
  echo запись могла остаться. Проверьте и при необходимости снимите:
  echo     reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "RoutineOps Agent" /reg:64
  echo     msiexec /x {ProductCode} /qn
  pause
  exit /b 4
)

if not "%MSIRC%"=="0" if not "%MSIRC%"=="3" (
  echo.
  echo [ЧАСТИЧНО] Файлы агента сняты, но регистрация установщика осталась — см. выше.
  echo Пока она есть, повторная установка того же пакета будет прервана установщиком.
  echo Снимите запись вручную: msiexec /x {ProductCode} /qn
  pause
  exit /b 3
)

echo.
echo Готово. RoutineOps-агент удалён.
if exist "%ProgramFiles%\RoutineOps" echo Пустой каталог %ProgramFiles%\RoutineOps остался — удалите его вручную.
pause
exit /b 0

REM ============================================================================
REM  :unregister — снять регистрацию установщика КОПИЕЙ агента, а не им самим.
REM
REM  🔴 Копия обязательна, и вот почему. msiexec /x выполняет UnenrollExec, тот зовёт
REM  `RoutineOps-agent.exe uninstall`, а он снимает пользовательские процессы через
REM  `taskkill /F /IM RoutineOps-agent.exe` с фильтром только по СВОЕМУ pid. Процесс,
REM  который ждёт msiexec, — другой pid с тем же именем образа, и он попадает под этот
REM  taskkill. Убитый процесс отдаёт код 1, а служба Windows Installer при этом доводит
REM  удаление до конца: регистрация СНЯТА, а батник рапортует «не удалось». У копии другое
REM  имя образа, и связь разрывается. Заодно копия не держит ни одного удаляемого файла,
REM  так что установщику нечего откладывать до перезагрузки.
REM
REM  Подпрограмма, а не блок в основном потоке: внутри скобочного блока %errorlevel%
REM  раскрывается на разборе блока, а не после запуска, и код возврата читался бы неверный.
REM
REM  Второй кандидат на копию — каталог самого агента: в корпоративной среде запуск из
REM  %TEMP% штатно запрещают политикой (AppLocker/SRP), и единственный %TEMP% оставил бы
REM  нас без запасного пути.
REM
REM 🔴 `start "" /wait`, а НЕ прямой запуск. Агент собран GUI-subsystem (-H windowsgui,
REM см. cmd/agent/console_windows.go), а cmd.exe дожидается только консольных программ:
REM GUI-процесс он запускает и идёт дальше той же секундой. Прямой вызов дал бы
REM %errorlevel% от запуска, а не от работы — батник отрапортовал бы «регистрация снята»
REM раньше, чем msiexec успел начать, и пошёл бы делать reg delete и rmdir ПОВЕРХ живой
REM транзакции удаления. `start /wait` ждёт независимо от подсистемы и пробрасывает код.
REM Первый пустой аргумент обязателен: иначе start примет путь в кавычках за заголовок окна.
REM ============================================================================
:unregister
set "STAGE=%TEMP%\ro-msi-unreg-%RANDOM%.exe"
copy /y "%EXE%" "%STAGE%" >nul 2>&1
if exist "%STAGE%" goto :unreg_run
set "STAGE=%~dp0ro-msi-unreg.exe"
copy /y "%EXE%" "%STAGE%" >nul 2>&1
if exist "%STAGE%" goto :unreg_run
echo   [ВНИМАНИЕ] Рабочую копию агента создать не удалось ни во временном каталоге, ни
echo   рядом с ним. Запускаю установленный файл напрямую: если он будет снят собственным
echo   установщиком, код возврата окажется недостоверным — сверьтесь с записью в
echo   «Установка и удаление программ» после завершения.
start "" /wait "%EXE%" msi-unregister
set "MSIRC=%errorlevel%"
goto :eof

:unreg_run
start "" /wait "%STAGE%" msi-unregister
set "MSIRC=%errorlevel%"
del /f /q "%STAGE%" >nul 2>&1
goto :eof
