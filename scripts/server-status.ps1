param(
  [string]$ServerRoot = '',
  [string]$TaskPrefix = 'MY-Town',
  [int]$RecentIncidents = 8,
  [switch]$Json
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ServerRoot)) { $ServerRoot = Split-Path -Parent $PSScriptRoot }
. (Join-Path $PSScriptRoot 'server-common.ps1')

$paths = Get-McPaths -ServerRoot $ServerRoot -TaskPrefix $TaskPrefix
$state = Get-WatchdogState -Paths $paths
$flag  = Get-IntentionalStopInfo -Paths $paths
$proc  = Get-ServerJavaProcess -Paths $paths

$serverTaskInfo = Invoke-SchtasksQueryOrRun -Paths $paths -Mode Query -TaskName $paths.ServerTaskName
$serverTaskStatus = 'Unknown'
$serverTaskLastResult = ''
if ($serverTaskInfo.Ok) {
  if ($serverTaskInfo.Output -match '(?m)^Status:\s*(.+)$')      { $serverTaskStatus = $Matches[1].Trim() }
  if ($serverTaskInfo.Output -match '(?m)^Last Result:\s*(.+)$') { $serverTaskLastResult = $Matches[1].Trim() }
}

$wdTaskInfo = Invoke-SchtasksQueryOrRun -Paths $paths -Mode Query -TaskName $paths.WatchdogTaskName
$wdTaskStatus = if ($wdTaskInfo.Ok -and ($wdTaskInfo.Output -match '(?m)^Status:\s*(.+)$')) { $Matches[1].Trim() } else { 'Not registered' }

$localSlp = Test-MinecraftSlp -TargetHost '127.0.0.1' -Port 25565 -TimeoutMs 4000
$rconPlayers = $null
$playitCmdAddr = $null
$playitCmdStatus = $null
if ($localSlp.Online -or $proc) {
  $rList = Invoke-RconSafe -Paths $paths -Command 'list' -TimeoutMs 4000
  if ($rList.Ok) { $rconPlayers = ($rList.Output -replace '§.', '').Trim() }
  $rPlayitSt = Invoke-RconSafe -Paths $paths -Command 'playit agent status' -TimeoutMs 4000
  if ($rPlayitSt.Ok) { $playitCmdStatus = ($rPlayitSt.Output -split "`r?`n" | Select-Object -First 1) -replace '§.', '' }
  $rPlayitAddr = Invoke-RconSafe -Paths $paths -Command 'playit tunnel get-address' -TimeoutMs 4000
  if ($rPlayitAddr.Ok) {
    $cleanAddr = ($rPlayitAddr.Output -replace '§.', '').Trim()
    if ($cleanAddr -match 'playit\.gg:\s*([^\s]+)') { $playitCmdAddr = $Matches[1].Trim() }
  }
}

$tunnelHost = if ($playitCmdAddr) { $playitCmdAddr } else { Get-PlayitTunnelHost -Paths $paths -State $state }
$publicSlp = if ($tunnelHost) { Test-MinecraftSlp -TargetHost $tunnelHost -Port 25565 -ResolveSrv -TimeoutMs 6000 } else { $null }

$uptimeStr = 'N/A'
if ($proc -and $proc.StartTime) {
  $up = (Get-Date) - $proc.StartTime
  $uptimeStr = "{0}d {1:00}h {2:00}m" -f $up.Days, $up.Hours, $up.Minutes
}

$incidents = @()
if (Test-Path -LiteralPath $paths.IncidentLog) {
  $incidents = @(Get-Content -LiteralPath $paths.IncidentLog -Tail $RecentIncidents -ErrorAction SilentlyContinue)
}

$summary = [ordered]@{
  checked_at             = (Get-Date).ToString('o')
  intentional_stop_flag  = $flag
  server_task_status     = $serverTaskStatus
  server_task_last_res   = $serverTaskLastResult
  watchdog_task_status   = $wdTaskStatus
  java_pid               = if ($proc) { $proc.Pid } else { $null }
  java_uptime            = $uptimeStr
  java_working_set_gb    = if ($proc) { $proc.WorkingSetGB } else { $null }
  local_slp              = $localSlp
  rcon_list              = $rconPlayers
  playit_plugin_status   = $playitCmdStatus
  playit_tunnel_host     = $tunnelHost
  public_slp             = $publicSlp
  recent_incidents       = $incidents
}

if ($Json) {
  $summary | ConvertTo-Json -Depth 5
  return
}

Write-Host ""
Write-Host "=== MY-Town Server Status ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ===" -ForegroundColor Cyan
if ($flag) {
  Write-Host "  Intentional Stop Flag : ACTIVE ($($flag.timestamp)) - $($flag.reason)" -ForegroundColor Yellow
} else {
  Write-Host "  Intentional Stop Flag : None (Watchdog active)" -ForegroundColor Green
}
Write-Host "  Scheduled Task (MC)   : $serverTaskStatus (LastResult=$serverTaskLastResult)"
Write-Host "  Scheduled Task (WD)   : $wdTaskStatus"

if ($proc) {
  Write-Host "  Java Process          : RUNNING (PID=$($proc.Pid), Uptime=$uptimeStr, WorkingSet=$($proc.WorkingSetGB) GB)" -ForegroundColor Green
} else {
  Write-Host "  Java Process          : NOT RUNNING" -ForegroundColor Red
}

if ($localSlp.Online) {
  Write-Host "  Localhost (127.0.0.1) : ONLINE ($($localSlp.Version), $($localSlp.PlayersOnline)/$($localSlp.PlayersMax) players, $($localSlp.LatencyMs) ms)" -ForegroundColor Green
} else {
  Write-Host "  Localhost (127.0.0.1) : UNREACHABLE ($($localSlp.Error))" -ForegroundColor Red
}

if ($rconPlayers) {
  Write-Host "  RCON (127.0.0.1:25575): $rconPlayers"
} else {
  Write-Host "  RCON (127.0.0.1:25575): Unavailable" -ForegroundColor DarkGray
}

if ($tunnelHost) {
  Write-Host "  Playit Plugin State   : $(if ($playitCmdStatus) { $playitCmdStatus } else { 'unknown' }) ($tunnelHost)"
  if ($publicSlp -and $publicSlp.Online) {
    $ep = if ($publicSlp.SrvTarget) { $publicSlp.SrvTarget } else { "$($publicSlp.ConnectHost):$($publicSlp.ConnectPort)" }
    Write-Host "  Public Tunnel Ping    : ONLINE via $ep ($($publicSlp.LatencyMs) ms, $($publicSlp.PlayersOnline)/$($publicSlp.PlayersMax) players)" -ForegroundColor Green
  } else {
    Write-Host "  Public Tunnel Ping    : FAILED via $tunnelHost ($($publicSlp.Error))" -ForegroundColor Red
  }
} else {
  Write-Host "  Public Tunnel Ping    : Unknown tunnel host" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Recent Downtime / Control Log ($($paths.IncidentLog)) ===" -ForegroundColor Cyan
if ($incidents.Count -eq 0) {
  Write-Host "  (No incidents recorded yet.)"
} else {
  foreach ($line in $incidents) { Write-Host "  $line" }
}
Write-Host ""
