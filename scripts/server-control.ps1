param(
  [Parameter(Mandatory)][ValidateSet('Start', 'Stop', 'Restart', 'RestartPlayit')][string]$Action,
  [string]$Reason = '',
  [string]$ServerRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$TaskPrefix = 'MY-Town',
  [int]$TimeoutSeconds = 45
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'server-common.ps1')

$paths = Get-McPaths -ServerRoot $ServerRoot -TaskPrefix $TaskPrefix
$utf8NoBom = New-Object System.Text.UTF8Encoding $false

function Invoke-GracefulStop {
  param([string]$StopReason)
  $proc = Get-ServerJavaProcess -Paths $paths
  New-Item -ItemType Directory -Force -Path $paths.AdminDir | Out-Null
  $flagObj = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    user      = "$env:USERDOMAIN\$env:USERNAME"
    reason    = $StopReason
  }
  [System.IO.File]::WriteAllText($paths.IntentionalStopFlag, ($flagObj | ConvertTo-Json -Compress), $utf8NoBom)
  Write-Host "Set intentional-stop.flag ($StopReason)."

  if (-not $proc) {
    Write-McIncident -Paths $paths -Event 'INTENTIONAL_STOP' -Cause 'MANUAL_CONTROL' -Details "$StopReason (java.exe was already stopped)"
    Write-Host "Server java.exe is already stopped."
    return
  }

  Write-McIncident -Paths $paths -Event 'INTENTIONAL_STOP' -Cause 'MANUAL_CONTROL' -PidValue $proc.Pid -Details $StopReason
  Write-Host "Saving and stopping Purpur (PID=$($proc.Pid))..."
  $null = Invoke-RconSafe -Paths $paths -Command 'save-all flush' -TimeoutMs 20000
  $stopRcon = Invoke-RconSafe -Paths $paths -Command 'stop' -TimeoutMs 10000

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    if (-not (Get-ServerJavaProcess -Paths $paths)) {
      Write-Host "Server stopped cleanly."
      return
    }
    Start-Sleep -Seconds 1
  }
  throw "Server PID=$($proc.Pid) did not exit within ${TimeoutSeconds}s (RCON stop Ok=$($stopRcon.Ok): $($stopRcon.Output))."
}

function Invoke-ServerStart {
  param([string]$StartReason)
  $alreadyUp = Get-ServerJavaProcess -Paths $paths
  if (Test-Path -LiteralPath $paths.IntentionalStopFlag) {
    Remove-Item -LiteralPath $paths.IntentionalStopFlag -Force
    Write-Host "Cleared intentional-stop.flag."
  }

  $state = Get-WatchdogState -Paths $paths
  $state.inIncident = $false
  $state.incidentStartIso = $null
  $state.incidentCause = $null
  $state.playitConsecutiveFail = 0
  $state.localSlpFail = 0
  Save-WatchdogState -Paths $paths -State $state

  if ($alreadyUp) {
    Write-Host "Server java.exe is already running (PID=$($alreadyUp.Pid))."
    return
  }

  Write-McIncident -Paths $paths -Event 'MANUAL_START' -Cause 'MANUAL_CONTROL' -Details $StartReason
  Write-Host "Starting Scheduled Task '$($paths.ServerTaskName)'..."
  $runRes = Invoke-SchtasksQueryOrRun -Paths $paths -Mode Run -TaskName $paths.ServerTaskName
  if (-not $runRes.Ok) {
    throw "Failed to trigger Scheduled Task '$($paths.ServerTaskName)': $($runRes.Output)"
  }

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  $up = $false
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    $slp = Test-MinecraftSlp -TargetHost '127.0.0.1' -Port 25565 -TimeoutMs 2500
    if ($slp.Online) {
      $p = Get-ServerJavaProcess -Paths $paths
      Write-Host "Server is ONLINE (PID=$($p.Pid), $($slp.Version), $($slp.LatencyMs) ms)."
      $up = $true
      break
    }
  }
  if (-not $up) {
    Write-Warning "Task started, but localhost:25565 SLP is not up yet after ${TimeoutSeconds}s. Check $($paths.LatestLog)."
  }
}

switch ($Action) {
  'Stop' {
    $r = if ($Reason) { $Reason } else { 'Manual shutdown via server-control.ps1 -Action Stop' }
    Invoke-GracefulStop -StopReason $r
  }
  'Start' {
    $r = if ($Reason) { $Reason } else { 'Manual start via server-control.ps1 -Action Start' }
    Invoke-ServerStart -StartReason $r
  }
  'Restart' {
    $r = if ($Reason) { $Reason } else { 'Manual restart via server-control.ps1 -Action Restart' }
    Invoke-GracefulStop -StopReason $r
    Invoke-ServerStart -StartReason $r
  }
  'RestartPlayit' {
    $r = if ($Reason) { $Reason } else { 'Manual Playit agent restart via server-control.ps1' }
    Write-McIncident -Paths $paths -Event 'PLAYIT_MANUAL_RESTART' -Cause 'MANUAL_CONTROL' -Details $r
    $res = Invoke-RconSafe -Paths $paths -Command 'playit agent restart' -TimeoutMs 8000
    if (-not $res.Ok) { throw "RCON playit agent restart failed: $($res.Output)" }
    Write-Host "RCON: $($res.Output)"
    Start-Sleep -Seconds 8
    $state = Get-WatchdogState -Paths $paths
    $hostName = Get-PlayitTunnelHost -Paths $paths -State $state
    if ($hostName) {
      $slp = Test-MinecraftSlp -TargetHost $hostName -Port 25565 -ResolveSrv -TimeoutMs 6000
      Write-Host "Public SLP ($($slp.SrvTarget)): Online=$($slp.Online) Latency=$($slp.LatencyMs)ms Error=$($slp.Error)"
    }
  }
}
