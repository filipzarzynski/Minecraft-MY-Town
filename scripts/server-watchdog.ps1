param(
  [string]$ServerRoot = '',
  [string]$TaskPrefix = 'MY-Town',
  [int]$MaxRestartsPer15Min = 4
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ServerRoot)) { $ServerRoot = Split-Path -Parent $PSScriptRoot }
. (Join-Path $PSScriptRoot 'server-common.ps1')

$paths = Get-McPaths -ServerRoot $ServerRoot -TaskPrefix $TaskPrefix
$mutexName = 'Local\' + ($TaskPrefix -replace '[^a-zA-Z0-9_-]', '_') + '_WatchdogLock'
$mutex = New-Object System.Threading.Mutex($false, $mutexName)
if (-not $mutex.WaitOne(0)) { exit 0 }

try {
  $now = Get-Date
  $state = Get-WatchdogState -Paths $paths

  # Respect explicit intentional shutdowns
  $stopFlag = Get-IntentionalStopInfo -Paths $paths
  if ($stopFlag) { exit 0 }

  # Prune restart timestamps older than 15 minutes
  $cutoff = $now.AddMinutes(-15)
  $recent = @()
  foreach ($iso in $state.recentRestartIsos) {
    try {
      $dt = [datetime]::Parse($iso)
      if ($dt -ge $cutoff) { $recent += $dt.ToString('o') }
    } catch { }
  }
  $state.recentRestartIsos = $recent

  # Discover Playit hostname (and persist across midnight log rotation)
  $tunnelHost = Get-PlayitTunnelHost -Paths $paths -State $state
  if ($tunnelHost) { $state.lastTunnelHost = $tunnelHost }

  $proc = Get-ServerJavaProcess -Paths $paths
  $localSlp = if ($proc) { Test-MinecraftSlp -TargetHost '127.0.0.1' -Port 25565 -TimeoutMs 5000 } else { [PSCustomObject]@{ Online = $false; Error = 'Process not running' } }
  $publicSlp = if ($proc -and $localSlp.Online -and $tunnelHost) {
    Test-MinecraftSlp -TargetHost $tunnelHost -Port 25565 -ResolveSrv -TimeoutMs 6000
  } else {
    $null
  }

  # Case A: Server is completely healthy (process running, local SLP OK, public Playit OK or not configured)
  $publicHealthy = (-not $tunnelHost) -or ($publicSlp -and $publicSlp.Online)
  if ($proc -and $localSlp.Online -and $publicHealthy) {
    if ($state.inIncident) {
      $downtimeSec = $null
      if ($state.incidentStartIso) {
        try { $downtimeSec = [int][Math]::Max(0, ($now - [datetime]::Parse($state.incidentStartIso)).TotalSeconds) } catch { }
      }
      Write-McIncident -Paths $paths -Event 'RECOVERED' -Cause ([string]$state.incidentCause) -PidValue $proc.Pid -DowntimeSeconds $downtimeSec -Details "Server and Playit tunnel healthy"
      $state.inIncident = $false
      $state.incidentStartIso = $null
      $state.incidentCause = $null
    }
    $state.lastKnownPid = $proc.Pid
    if ($proc.StartTime) { $state.lastKnownStartIso = $proc.StartTime.ToString('o') }
    $state.playitConsecutiveFail = 0
    $state.localSlpFail = 0
    $state.lastHealthyIso = $now.ToString('o')
    Save-WatchdogState -Paths $paths -State $state
    exit 0
  }

  # Helper for triggering restart with crash-loop guard
  function Start-TaskWithCrashLoopGuard([string]$TriggerEvent, [string]$DiagCause, [string]$DiagDetails) {
    if ($state.recentRestartIsos.Count -ge $MaxRestartsPer15Min) {
      Write-McIncident -Paths $paths -Event 'CRASH_LOOP_COOLDOWN' -Cause $DiagCause -Details "Skipped restart ($($state.recentRestartIsos.Count) restarts in last 15m). Original: $DiagDetails"
      Save-WatchdogState -Paths $paths -State $state
      return $false
    }
    Write-McIncident -Paths $paths -Event $TriggerEvent -Cause $DiagCause -Details $DiagDetails
    $runRes = Invoke-SchtasksQueryOrRun -Paths $paths -Mode Run -TaskName $paths.ServerTaskName
    $state.recentRestartIsos += $now.ToString('o')
    if (-not $runRes.Ok) {
      Write-McIncident -Paths $paths -Event 'RESTART_FAILED' -Cause 'TASK_SCHEDULER_ERROR' -Details $runRes.Output
      Save-WatchdogState -Paths $paths -State $state
      return $false
    }
    Write-McIncident -Paths $paths -Event 'AUTO_RESTART_TRIGGERED' -Cause $DiagCause -Details "Triggered $($paths.ServerTaskName) via $($runRes.Context)"
    Save-WatchdogState -Paths $paths -State $state
    return $true
  }

  # Case B: java.exe is NOT running (unexpected shutdown / crash / reboot recovery)
  if (-not $proc) {
    $diag = Get-ServerDowntimeDiagnosis -Paths $paths -State $state
    if (-not $state.inIncident) {
      $state.inIncident = $true
      $state.incidentStartIso = $now.ToString('o')
      $state.incidentCause = $diag.Cause
    }
    $state.playitConsecutiveFail = 0
    $state.localSlpFail = 0
    $null = Start-TaskWithCrashLoopGuard -TriggerEvent 'DOWN_DETECTED' -DiagCause $diag.Cause -DiagDetails $diag.Details
    exit 0
  }

  # Case C: java.exe is running, but localhost:25565 SLP failed
  if (-not $localSlp.Online) {
    # Wait up to 90s after process creation so cold startup doesn't trigger a false freeze alarm
    $graceExpired = $true
    if ($proc.StartTime -and (($now - $proc.StartTime).TotalSeconds -lt 90)) { $graceExpired = $false }
    if (-not $graceExpired) {
      Save-WatchdogState -Paths $paths -State $state
      exit 0
    }

    $state.localSlpFail = [int]$state.localSlpFail + 1
    if ($state.localSlpFail -lt 2) {
      Save-WatchdogState -Paths $paths -State $state
      exit 0
    }

    if (-not $state.inIncident) {
      $state.inIncident = $true
      $state.incidentStartIso = $now.ToString('o')
      $state.incidentCause = 'LOCAL_SERVER_UNRESPONSIVE'
    }
    Write-McIncident -Paths $paths -Event 'UNRESPONSIVE_DETECTED' -Cause 'LOCAL_SLP_FAILED' -PidValue $proc.Pid -Details "Local SLP failed twice: $($localSlp.Error)"
    $null = Invoke-RconSafe -Paths $paths -Command 'save-all flush' -TimeoutMs 10000
    $null = Invoke-RconSafe -Paths $paths -Command 'stop' -TimeoutMs 8000
    $waitEnd = (Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $waitEnd) {
      if (-not (Get-ServerJavaProcess -Paths $paths)) { break }
      Start-Sleep -Seconds 1
    }
    $rem = Get-ServerJavaProcess -Paths $paths
    if ($rem) {
      try {
        Stop-Process -Id $rem.Pid -Force -ErrorAction Stop
        Write-McIncident -Paths $paths -Event 'FORCED_KILL' -Cause 'HUNG_JVM_DURING_STOP' -PidValue $rem.Pid -Details "Forced kill after 25s graceful timeout"
      } catch {
        Write-McIncident -Paths $paths -Event 'FORCED_KILL_FAILED' -Cause 'ACCESS_OR_EXIT' -PidValue $rem.Pid -Details $_.Exception.Message
      }
      Start-Sleep -Seconds 2
    }
    $state.localSlpFail = 0
    $null = Start-TaskWithCrashLoopGuard -TriggerEvent 'RECOVERY_RESTART' -DiagCause 'LOCAL_SLP_FAILED' -DiagDetails "Restarting unresponsive Purpur server"
    exit 0
  }

  # Case D: Local Purpur is healthy, but public Playit tunnel SLP failed
  if ($tunnelHost -and $publicSlp -and (-not $publicSlp.Online)) {
    $state.localSlpFail = 0
    $state.playitConsecutiveFail = [int]$state.playitConsecutiveFail + 1
    if ($state.playitConsecutiveFail -eq 1) {
      Save-WatchdogState -Paths $paths -State $state
      exit 0
    }

    if (-not $state.inIncident) {
      $state.inIncident = $true
      $state.incidentStartIso = $now.ToString('o')
      $state.incidentCause = 'PLAYIT_TUNNEL_STUCK'
    }

    if ($state.playitConsecutiveFail -eq 2) {
      Write-McIncident -Paths $paths -Event 'PLAYIT_TUNNEL_STUCK' -Cause 'PUBLIC_SLP_FAILED' -PidValue $proc.Pid -Details "Public SLP to $tunnelHost failed twice ($($publicSlp.Error)); running RCON playit agent restart"
      $rPlayit = Invoke-RconSafe -Paths $paths -Command 'playit agent restart' -TimeoutMs 8000
      $state.lastPlayitRestartIso = $now.ToString('o')
      if ($rPlayit.Ok) {
        Start-Sleep -Seconds 8
        $recheck = Test-MinecraftSlp -TargetHost $tunnelHost -Port 25565 -ResolveSrv -TimeoutMs 6000
        if ($recheck.Online) {
          $downtimeSec = if ($state.incidentStartIso) { [int][Math]::Max(0, ((Get-Date) - [datetime]::Parse($state.incidentStartIso)).TotalSeconds) } else { 8 }
          Write-McIncident -Paths $paths -Event 'RECOVERED' -Cause 'PLAYIT_TUNNEL_STUCK' -PidValue $proc.Pid -DowntimeSeconds $downtimeSec -Details "Recovered via RCON playit agent restart"
          $state.inIncident = $false
          $state.incidentStartIso = $null
          $state.incidentCause = $null
          $state.playitConsecutiveFail = 0
          $state.lastHealthyIso = (Get-Date).ToString('o')
        }
      }
      Save-WatchdogState -Paths $paths -State $state
      exit 0
    }

    # Playit STILL failing after RCON restart attempt -> fall back to full graceful server restart
    Write-McIncident -Paths $paths -Event 'PLAYIT_RECOVERY_FALLBACK_RESTART' -Cause 'PUBLIC_SLP_FAILED' -PidValue $proc.Pid -Details "Playit still unreachable after RCON restart ($($publicSlp.Error)); performing graceful Purpur restart"
    $null = Invoke-RconSafe -Paths $paths -Command 'save-all flush' -TimeoutMs 15000
    $null = Invoke-RconSafe -Paths $paths -Command 'stop' -TimeoutMs 10000
    $waitEnd = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $waitEnd) {
      if (-not (Get-ServerJavaProcess -Paths $paths)) { break }
      Start-Sleep -Seconds 1
    }
    $state.playitConsecutiveFail = 0
    $null = Start-TaskWithCrashLoopGuard -TriggerEvent 'RECOVERY_RESTART' -DiagCause 'PLAYIT_TUNNEL_STUCK' -DiagDetails "Restarting server after Playit tunnel recovery failure"
    exit 0
  }
} finally {
  try { $mutex.ReleaseMutex() | Out-Null } catch { }
  $mutex.Dispose()
}
