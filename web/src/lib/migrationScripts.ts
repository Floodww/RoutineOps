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
    "ENROLL_URL=\`"${base}/api/v1/enroll\`"",
    "ENROLL_TOKEN=\`"${token}\`"",
    "CA_URL=\`"${base}/ca.crt\`"",
    "CA_SHA256=\`"${caSHA256}\`"",
    "SERVER_ADDR=\`"${serverAddr}\`""
)

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
    throw "RoutineOps installation failed with exit code $($process.ExitCode)"
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
