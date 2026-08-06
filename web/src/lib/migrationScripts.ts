export function getIntuneMigrationScript(base: string, serverAddr: string, token: string, caSHA256: string): string {
  return `# PowerShell script for Intune Migration to RoutineOps
$ErrorActionPreference = 'Stop'

$msiUrl = "${base}/releases/RoutineOps-agent.msi"
$installerPath = Join-Path $env:TEMP "RoutineOps-agent.msi"

Write-Host "Downloading RoutineOps agent from $msiUrl..."
Invoke-WebRequest -Uri $msiUrl -OutFile $installerPath -UseBasicParsing

Write-Host "Installing RoutineOps agent..."
$arguments = @(
    "/i",
    "\`"$installerPath\`"",
    "/qn",
    "/norestart",
    "REBOOT=ReallySuppress",
    "ENROLL_URL=\`"${base}/api/v1/enroll\`"",
    "ENROLL_TOKEN=\`"${token}\`"",
    "CA_URL=\`"${base}/ca.crt\`"",
    "CA_SHA256=\`"${caSHA256}\`"",
    "SERVER_ADDR=\`"${serverAddr}\`""
)

$logPath = Join-Path $env:TEMP "RoutineOps-install.log"
$arguments += @("/l*v", "\`"$logPath\`"")

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
# 1603 is what a failed launch condition looks like under /qn. The installer refuses when the
# product is already registered but this run would install nothing and skip enrollment (for
# example after the agent was removed by hand). Repair mode is the documented way through: it
# re-lays missing files and re-runs enrollment. Only 1603 is retried on purpose - retrying a
# busy installer (1618) or a missing product (1605) would just hide the real reason.
if ($process.ExitCode -eq 1603) {
    Write-Host "Install returned 1603; the product may already be registered. Retrying in repair mode..."
    # A separate log: msiexec truncates the file it is given, so reusing $logPath would erase
    # the record of the first failure - the one the error message tells the operator to read.
    $repairLog = Join-Path $env:TEMP "RoutineOps-repair.log"
    $repair = $arguments + @("REINSTALL=ALL", "REINSTALLMODE=vomus")
    $repair = $repair -replace [regex]::Escape($logPath), $repairLog
    $process2 = Start-Process -FilePath "msiexec.exe" -ArgumentList $repair -Wait -PassThru
    if ($process2.ExitCode -ne 0 -and $process2.ExitCode -ne 3010 -and $process2.ExitCode -ne 1641) {
        throw "RoutineOps installation failed with exit code 1603, repair returned $($process2.ExitCode). See $logPath and $repairLog"
    }
} elseif ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010 -and $process.ExitCode -ne 1641) {
    throw "RoutineOps installation failed with exit code $($process.ExitCode). See $logPath"
}

Write-Host "RoutineOps agent installed successfully."

# Cleanup
Remove-Item -Path $installerPath -Force
Write-Host "Migration complete. The old MDM profile can be removed later."
`
}

export function getJamfMigrationScript(base: string, serverAddr: string, token: string, caSHA256: string): string {
  return `#!/bin/bash
# Bash script for Jamf/Workspace ONE Migration to RoutineOps
set -e

PKG_URL="${base}/releases/RoutineOps-agent.pkg"
PKG_PATH="/tmp/RoutineOps-agent.pkg"

echo "Downloading RoutineOps agent from $PKG_URL..."
curl -L -s -o "$PKG_PATH" "$PKG_URL"

echo "Installing RoutineOps agent..."
sudo installer -pkg "$PKG_PATH" -target /

echo "Enrolling RoutineOps agent..."
sudo /usr/local/bin/RoutineOps-agent enroll -install-service \\
  -enroll-url "${base}/api/v1/enroll" -token "${token}" \\
  -ca-url "${base}/ca.crt" -ca-sha256 "${caSHA256}" \\
  -server "${serverAddr}" -server-name routineops-server

echo "RoutineOps agent installed and enrolled successfully."

# Cleanup
rm -f "$PKG_PATH"
echo "Migration complete. The old MDM profile can be removed later."
`
}
