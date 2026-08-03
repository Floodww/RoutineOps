<#
.SYNOPSIS
  Собирает (и при наличии серта подписывает) MSI-установщик MDM-агента из WiX-исходника.

.DESCRIPTION
  Запускать НА WINDOWS. Бинарь mdm-agent.exe кросс-собирается на Mac/в CI
  (make build-win, CGO_ENABLED=0) и кладётся в этот каталог либо передаётся -ExePath.
  Нужен WiX v4/v5 (.NET tool) — скрипт доставит его и расширение Util при отсутствии.

  Один универсальный MSI; токен передаётся при установке как property:
    msiexec /i RoutineOps-agent.msi /qn ENROLL_URL=... ENROLL_TOKEN=... CA_URL=...

.PARAMETER ExePath   Путь к собранному mdm-agent.exe (по умолчанию .\mdm-agent.exe).
.PARAMETER Version   Версия пакета x.y.z.b (по умолчанию 1.0.0.0).
.PARAMETER Out       Имя выходного MSI (по умолчанию RoutineOps-agent.msi).
.PARAMETER PfxPath   PFX для подписи MSI (опц.). .PARAMETER PfxPassword Пароль PFX (опц.).
.PARAMETER TimestampUrl  RFC3161-сервер меток времени (опц.).
#>
param(
  [string]$ExePath = "$PSScriptRoot\mdm-agent.exe",
  [string]$Version = "1.0.0.0",
  [string]$Out = "$PSScriptRoot/RoutineOps-agent.msi",
  [string]$PfxPath,
  [string]$PfxPassword,
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
  throw "Не найден бинарь агента: $ExePath. Соберите его: make build-win (CGO_ENABLED=0)."
}
# Копируем бинарь в каталог сборки, КРОМЕ случая, когда -ExePath уже указывает на
# целевой файл: Copy-Item падает с «не может перезаписать сам себя» (дефолтный путь
# = $PSScriptRoot\mdm-agent.exe).
$exeDest = Join-Path $PSScriptRoot "mdm-agent.exe"
if ((Resolve-Path $ExePath).Path -ne (Resolve-Path $exeDest -ErrorAction SilentlyContinue).Path) {
  Copy-Item $ExePath $exeDest -Force
}

# Без явного -ExePath берётся ранее лежавший build/msi/mdm-agent.exe — он gitignored
# и НЕ обновляется сам, поэтому легко упаковать СТАРЫЙ бинарь (так и случилось в
# полевой отладке: MSI собирался со стейл-exe без свежих флагов). Всегда печатаем
# хеш/время паковываемого бинаря, а при использовании дефолта — громко предупреждаем.
$exeInfo = Get-Item $exeDest
$exeHash = (Get-FileHash $exeDest -Algorithm SHA256).Hash
if (-not $PSBoundParameters.ContainsKey('ExePath')) {
  Write-Warning ("-ExePath не задан: пакуется $exeDest (изменён $($exeInfo.LastWriteTime)). " +
    "Это может быть СТАРЫЙ бинарь! Соберите свежий (make build-win) и передайте -ExePath явно.")
}
Write-Host "Пакуется бинарь агента:"
Write-Host ("  путь:    " + $exeDest)
Write-Host ("  размер:  " + $exeInfo.Length)
Write-Host ("  изменён: " + $exeInfo.LastWriteTime)
Write-Host ("  sha256:  " + $exeHash)

# WiX toolset (.NET global tool) + расширение Util (для WixQuietExec).
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  Write-Host "Устанавливаю WiX (.NET tool)..."
  dotnet tool install --global wix --version 4.0.5
  $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}
wix extension add -g WixToolset.Util.wixext/4.0.5 2>$null | Out-Null

Write-Host "Сборка MSI ($Version)..."
# Отметка времени ДО сборки: по ней отличается свежесобранный MSI от лежавшего
# здесь с прошлого раза. Без неё провалившаяся сборка «подтверждается» старым
# файлом — а он ещё и уедет в релиз как новый.
$before = (Get-Item $Out -ErrorAction SilentlyContinue).LastWriteTimeUtc

wix build "$PSScriptRoot/mdm-agent.wxs" `
  -d Version=$Version `
  -ext WixToolset.Util.wixext `
  -arch x64 `
  -o $Out

# Провал wix обязан валить скрипт. Раньше его код возврата не проверялся вовсе:
# при ошибке WIX0103 (относительные пути в .wxs не разрешились — так бывает,
# когда скрипт запущен не из своего каталога) на экран уходило «MSI собран», код
# возврата был нулевой, и упаковать в релиз можно было прошлый MSI, приняв его за
# свежий. Проверяем и код, и что файл действительно перезаписан этим запуском.
if ($LASTEXITCODE -ne 0) { throw "wix build завершился с кодом $LASTEXITCODE — MSI не собран." }
$built = Get-Item $Out -ErrorAction SilentlyContinue
if (-not $built) { throw "wix build отчитался успехом, но файла $Out нет." }
if ($before -and $built.LastWriteTimeUtc -le $before) {
  throw "Файл $Out не обновлён этой сборкой (остался от $($built.LastWriteTime)) — упаковали бы старый MSI."
}
Write-Host ("MSI собран: " + $Out)
Write-Host ("  версия:  " + $Version)
Write-Host ("  sha256:  " + (Get-FileHash $Out -Algorithm SHA256).Hash)

# Подпись (опционально). Подход согласован с gen-win-codesign.ps1.
if ($PfxPath) {
  $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe `
    -ErrorAction SilentlyContinue | Select-Object -Last 1
  if (-not $signtool) { throw "signtool.exe не найден (Windows SDK)." }
  & $signtool.FullName sign /fd SHA256 /f $PfxPath /p $PfxPassword `
    /tr $TimestampUrl /td SHA256 $Out
  Write-Host "MSI подписан."
}
