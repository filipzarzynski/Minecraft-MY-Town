param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('Prealloc', 'Dynamic')]
  [string]$Mode,

  [string]$ServerRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$TaskName = 'MY-Town-Minecraft-Server',
  [switch]$RestartServerNow
)

$ErrorActionPreference = 'Stop'
$ramConfigFile = Join-Path $ServerRoot 'scripts\ram-mode.json'
$mcCmd = Join-Path $ServerRoot 'scripts\mc-cmd.ps1'

$cfg = Get-Content -Path $ramConfigFile -Raw | ConvertFrom-Json
$prevMode = $cfg.Mode
$cfg.Mode = $Mode
$cfg | ConvertTo-Json -Depth 4 | Set-Content -Path $ramConfigFile -Encoding UTF8

Write-Host "RAM mode updated: $prevMode -> $Mode (effective on next server start/reboot)."
Write-Host ("Flags for '$Mode': " + $(if ($Mode -eq 'Prealloc') { $cfg.PreallocFlags } else { $cfg.DynamicFlags }))

if ($RestartServerNow) {
  Write-Host "Gracefully stopping running server via RCON..."
  try {
    & $mcCmd -Command 'save-all flush' | Out-Null
    & $mcCmd -Command 'stop' | Out-Null
  } catch {
    Write-Warning "RCON stop check: $_"
  }

  $deadline = (Get-Date).AddSeconds(45)
  while ((Get-Date) -lt $deadline) {
    $procs = Get-CimInstance Win32_Process -Filter "Name='java.exe'" | Where-Object { $_.CommandLine -match 'purpur-' }
    if (-not $procs) { break }
    Start-Sleep -Seconds 1
  }

  $remaining = Get-CimInstance Win32_Process -Filter "Name='java.exe'" | Where-Object { $_.CommandLine -match 'purpur-' }
  if ($remaining) {
    throw "Server java.exe process is still running after 45s. Aborting task restart."
  }

  Write-Host "Starting Scheduled Task '$TaskName' in $Mode mode..."
  try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  } catch {
    Write-Host "Elevation required to start Scheduled Task; requesting UAC..."
    $p = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', "Start-ScheduledTask -TaskName '$TaskName'") -Verb RunAs -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Failed to start '$TaskName' (exit $($p.ExitCode))." }
  }
  Write-Host "Scheduled Task '$TaskName' started."
}
