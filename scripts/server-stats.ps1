param(
  [string]$ServerRoot = '',
  [int]$Days = 30,
  [switch]$Json
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ServerRoot)) { $ServerRoot = Split-Path -Parent $PSScriptRoot }

function Format-DurationShort([long]$Seconds) {
  if ($Seconds -lt 0) { $Seconds = 0 }
  $ts = [TimeSpan]::FromSeconds($Seconds)
  if ($ts.TotalHours -ge 1) {
    return "{0}h {1:00}m {2:00}s" -f [int][Math]::Floor($ts.TotalHours), $ts.Minutes, $ts.Seconds
  }
  if ($ts.Minutes -ge 1) {
    return "{0}m {1:00}s" -f $ts.Minutes, $ts.Seconds
  }
  return "{0}s" -f $ts.Seconds
}

$propsPath = Join-Path $ServerRoot 'server.properties'
$maxPlayers = 24
if (Test-Path -LiteralPath $propsPath) {
  $mpLine = Get-Content -LiteralPath $propsPath -ErrorAction SilentlyContinue | Where-Object { $_ -match '^max-players=(\d+)' } | Select-Object -First 1
  if ($mpLine -and ($mpLine -match '^max-players=(\d+)')) {
    $maxPlayers = [Math]::Max(1, [int]$Matches[1])
  }
}

$activityPath = Join-Path $ServerRoot 'plugins\MYTownGatekeeper\player-activity.jsonl'
$logsDir      = Join-Path $ServerRoot 'logs'

# 1. Read structured JSONL events from MYTownGatekeeper
$jsonlEvents = New-Object System.Collections.Generic.List[object]
$earliestJsonl = [datetime]::MaxValue
if (Test-Path -LiteralPath $activityPath) {
  foreach ($rawLine in (Get-Content -LiteralPath $activityPath -ErrorAction SilentlyContinue)) {
    if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }
    try {
      $ev = $rawLine | ConvertFrom-Json
      $dt = [datetime]::Parse([string]$ev.timestamp)
      if ($dt -lt $earliestJsonl) { $earliestJsonl = $dt }
      $jsonlEvents.Add([PSCustomObject]@{
        Time        = $dt
        Event       = [string]$ev.event
        Player      = [string]$ev.player
        Online      = if ($null -ne $ev.online) { [int]$ev.online } else { $null }
        MaxPlayers  = if ($null -ne $ev.max_players) { [int]$ev.max_players } else { $maxPlayers }
        DurationSec = if ($null -ne $ev.duration_sec) { [long]$ev.duration_sec } else { $null }
        Source      = 'jsonl'
      })
    } catch { }
  }
}

# 2. Parse historical server logs for sessions predating player-activity.jsonl
$histEvents = New-Object System.Collections.Generic.List[object]
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue

function Add-LogLinesEvents([string[]]$Lines, [datetime]$LogDate, [datetime]$CutoffUpper) {
  $prevTime = $null
  $curDate = $LogDate.Date
  foreach ($line in $Lines) {
    if ($line -match '^\[(\d{2}:\d{2}:\d{2})\].*?:\s*(?:System chat:\s*)?([A-Za-z0-9_]{3,16}) (joined|left) the game\s*$') {
      $tod = [TimeSpan]::ParseExact($Matches[1], 'hh\:mm\:ss', $null)
      if ($prevTime -and ($tod -lt $prevTime)) { $curDate = $curDate.AddDays(1) }
      $prevTime = $tod
      $dt = $curDate.Add($tod)
      if ($dt -lt $CutoffUpper) {
        $evType = if ($Matches[3] -eq 'joined') { 'JOIN' } else { 'QUIT' }
        $histEvents.Add([PSCustomObject]@{
          Time        = $dt
          Event       = $evType
          Player      = $Matches[2]
          Online      = $null
          MaxPlayers  = $maxPlayers
          DurationSec = $null
          Source      = 'server_log'
        })
      }
    } elseif ($line -match '^\[(\d{2}:\d{2}:\d{2})\].*?:\s*(Stopping server|Starting minecraft server version)\s*') {
      $tod = [TimeSpan]::ParseExact($Matches[1], 'hh\:mm\:ss', $null)
      if ($prevTime -and ($tod -lt $prevTime)) { $curDate = $curDate.AddDays(1) }
      $prevTime = $tod
      $dt = $curDate.Add($tod)
      if ($dt -lt $CutoffUpper) {
        $histEvents.Add([PSCustomObject]@{
          Time        = $dt
          Event       = 'SERVER_STOP'
          Player      = ''
          Online      = 0
          MaxPlayers  = $maxPlayers
          DurationSec = $null
          Source      = 'server_log'
        })
      }
    }
  }
}

if (Test-Path -LiteralPath $logsDir) {
  $gzFiles = Get-ChildItem -LiteralPath $logsDir -Filter '*.log.gz' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(\d{4}-\d{2}-\d{2})-(\d+)\.log\.gz$' } |
    Sort-Object {
      $null = $_.Name -match '^(\d{4}-\d{2}-\d{2})-(\d+)\.log\.gz$'
      "{0}-{1:0000}" -f $Matches[1], [int]$Matches[2]
    }
  foreach ($gz in $gzFiles) {
    $null = $gz.Name -match '^(\d{4}-\d{2}-\d{2})-(\d+)\.log\.gz$'
    $d = [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd', $null)
    if ($d -gt $earliestJsonl) { continue }
    $fs = [System.IO.File]::OpenRead($gz.FullName)
    $gs = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
    $sr = New-Object System.IO.StreamReader($gs)
    $lines = ($sr.ReadToEnd()) -split "`r?`n"
    $sr.Close(); $gs.Close(); $fs.Close()
    Add-LogLinesEvents -Lines $lines -LogDate $d -CutoffUpper $earliestJsonl
  }

  $latestLog = Join-Path $logsDir 'latest.log'
  if (Test-Path -LiteralPath $latestLog) {
    $latestInfo = Get-Item -LiteralPath $latestLog
    $latestLines = Get-Content -LiteralPath $latestLog -ErrorAction SilentlyContinue
    # Determine start date: use LastWriteTime date unless rollover occurred
    $startDate = $latestInfo.LastWriteTime.Date
    if ($latestLines -and $latestLines.Count -gt 0 -and ($latestLines[0] -match '^\[(\d{2}:\d{2}:\d{2})\]')) {
      $firstTod = [TimeSpan]::ParseExact($Matches[1], 'hh\:mm\:ss', $null)
      if ($firstTod -gt $latestInfo.LastWriteTime.TimeOfDay.Add([TimeSpan]::FromMinutes(5))) {
        $startDate = $startDate.AddDays(-1)
      }
    }
    Add-LogLinesEvents -Lines $latestLines -LogDate $startDate -CutoffUpper $earliestJsonl
  }
}

# 3. Combine & replay session timeline
$allEvents = @($histEvents.ToArray() + $jsonlEvents.ToArray()) | Sort-Object Time

$cutoffDate = (Get-Date).Date.AddDays(-[Math]::Max(1, $Days) + 1)
$activeSessions = @{} # key -> StartTime
$completedSessions = New-Object System.Collections.Generic.List[object]
$playerStats = @{}    # key -> hashtable
$dailyStats = @{}     # yyyy-MM-dd -> hashtable
$peakOnline = 0
$peakTime = $null
$peakPlayers = @()

function Ensure-PlayerStat([string]$Name) {
  $k = $Name.ToLowerInvariant()
  if (-not $playerStats.ContainsKey($k)) {
    $playerStats[$k] = @{
      Player       = $Name
      Sessions     = 0
      TotalSeconds = [long]0
      LastSeen     = $null
      FirstSeen    = $null
    }
  }
  return $playerStats[$k]
}

function Ensure-DailyStat([datetime]$Dt, [int]$CapMax) {
  $dayKey = $Dt.ToString('yyyy-MM-dd')
  if (-not $dailyStats.ContainsKey($dayKey)) {
    $dailyStats[$dayKey] = @{
      Date         = $dayKey
      UniqueSet    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
      Sessions     = 0
      TotalSeconds = [long]0
      PeakOnline   = 0
      MaxPlayers   = $CapMax
    }
  }
  return $dailyStats[$dayKey]
}

foreach ($ev in $allEvents) {
  if ($ev.Event -eq 'JOIN') {
    $key = $ev.Player.ToLowerInvariant()
    $activeSessions[$key] = [PSCustomObject]@{ Player = $ev.Player; Start = $ev.Time }
    $ps = Ensure-PlayerStat $ev.Player
    $ps.Sessions++
    if (-not $ps.FirstSeen -or $ev.Time -lt $ps.FirstSeen) { $ps.FirstSeen = $ev.Time }
    if (-not $ps.LastSeen -or $ev.Time -gt $ps.LastSeen)   { $ps.LastSeen = $ev.Time }

    $ds = Ensure-DailyStat $ev.Time $ev.MaxPlayers
    [void]$ds.UniqueSet.Add($ev.Player)
    $ds.Sessions++

    $curOnline = if ($null -ne $ev.Online) { [int]$ev.Online } else { $activeSessions.Count }
    if ($curOnline -gt $ds.PeakOnline) { $ds.PeakOnline = $curOnline }
    if ($curOnline -gt $peakOnline) {
      $peakOnline = $curOnline
      $peakTime = $ev.Time
      $peakPlayers = @($activeSessions.Values | ForEach-Object { $_.Player })
    }
  }
  elseif ($ev.Event -eq 'QUIT' -or $ev.Event -eq 'QUIT_SHUTDOWN') {
    $key = $ev.Player.ToLowerInvariant()
    $durSec = [long]0
    $startDt = $ev.Time
    if ($activeSessions.ContainsKey($key)) {
      $startDt = $activeSessions[$key].Start
      $activeSessions.Remove($key)
      $durSec = if ($null -ne $ev.DurationSec) { [long]$ev.DurationSec } else { [long][Math]::Max(0, ($ev.Time - $startDt).TotalSeconds) }
    } elseif ($null -ne $ev.DurationSec) {
      $durSec = [long]$ev.DurationSec
      $startDt = $ev.Time.AddSeconds(-$durSec)
    }
    $ps = Ensure-PlayerStat $ev.Player
    $ps.TotalSeconds += $durSec
    if (-not $ps.LastSeen -or $ev.Time -gt $ps.LastSeen) { $ps.LastSeen = $ev.Time }
    $ds = Ensure-DailyStat $startDt $ev.MaxPlayers
    [void]$ds.UniqueSet.Add($ev.Player)
    $ds.TotalSeconds += $durSec

    $completedSessions.Add([PSCustomObject]@{
      Player   = $ev.Player
      Start    = $startDt
      End      = $ev.Time
      Duration = Format-DurationShort $durSec
      Seconds  = $durSec
      Status   = if ($ev.Event -eq 'QUIT_SHUTDOWN') { 'Closed (Server Stop)' } else { 'Closed' }
    })
  }
  elseif ($ev.Event -eq 'SERVER_STOP') {
    foreach ($k in @($activeSessions.Keys)) {
      $sess = $activeSessions[$k]
      $durSec = [long][Math]::Max(0, ($ev.Time - $sess.Start).TotalSeconds)
      $ps = Ensure-PlayerStat $sess.Player
      $ps.TotalSeconds += $durSec
      if (-not $ps.LastSeen -or $ev.Time -gt $ps.LastSeen) { $ps.LastSeen = $ev.Time }
      $ds = Ensure-DailyStat $sess.Start $ev.MaxPlayers
      $ds.TotalSeconds += $durSec
      $completedSessions.Add([PSCustomObject]@{
        Player   = $sess.Player
        Start    = $sess.Start
        End      = $ev.Time
        Duration = Format-DurationShort $durSec
        Seconds  = $durSec
        Status   = 'Closed (Server Stop)'
      })
    }
    $activeSessions.Clear()
  }
}

# Include currently active online sessions if java.exe is still up
$now = Get-Date
$serverLive = [bool](Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 25565 -State Listen -ErrorAction SilentlyContinue)
$openOnlineList = @()
if ($serverLive) {
  foreach ($sess in $activeSessions.Values) {
    $durSec = [long][Math]::Max(0, ($now - $sess.Start).TotalSeconds)
    $ps = Ensure-PlayerStat $sess.Player
    $ps.TotalSeconds += $durSec
    $ps.LastSeen = $now
    $openOnlineList += [PSCustomObject]@{
      Player   = $sess.Player
      Start    = $sess.Start
      End      = $now
      Duration = (Format-DurationShort $durSec) + ' (online)'
      Seconds  = $durSec
      Status   = 'Online now'
    }
  }
}

$capPct = [math]::Round(($peakOnline * 100.0) / $maxPlayers, 1)
$capVerdict = if ($capPct -ge 80) { 'NEAR OR AT CAPACITY - consider raising max-players/resources' } elseif ($capPct -ge 50) { 'Moderate load' } else { 'Healthy headroom' }

$playerSummary = @($playerStats.Values | Sort-Object -Property TotalSeconds -Descending | ForEach-Object {
  $avg = if ($_.Sessions -gt 0) { [long][Math]::Round($_.TotalSeconds / $_.Sessions) } else { 0 }
  [PSCustomObject]@{
    Player       = $_.Player
    Sessions     = $_.Sessions
    TotalTime    = Format-DurationShort $_.TotalSeconds
    TotalSeconds = $_.TotalSeconds
    AvgSession   = Format-DurationShort $avg
    FirstSeen    = if ($_.FirstSeen) { $_.FirstSeen.ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
    LastSeen     = if ($_.LastSeen)  { $_.LastSeen.ToString('yyyy-MM-dd HH:mm') }  else { 'N/A' }
  }
})

$dailySummary = @($dailyStats.Values | Where-Object { [datetime]::ParseExact($_.Date, 'yyyy-MM-dd', $null) -ge $cutoffDate } | Sort-Object Date -Descending | ForEach-Object {
  [PSCustomObject]@{
    Date           = $_.Date
    UniquePlayers  = $_.UniqueSet.Count
    Sessions       = $_.Sessions
    TotalPlaytime  = Format-DurationShort $_.TotalSeconds
    PeakConcurrent = "$($_.PeakOnline)/$maxPlayers"
  }
})

$recentSessions = @($completedSessions.ToArray() + $openOnlineList | Sort-Object Start -Descending | Select-Object -First 12 | ForEach-Object {
  [PSCustomObject]@{
    Player   = $_.Player
    Joined   = $_.Start.ToString('yyyy-MM-dd HH:mm:ss')
    Duration = $_.Duration
    Status   = $_.Status
  }
})

$resultObj = [ordered]@{
  generated_at         = $now.ToString('o')
  max_players_limit    = $maxPlayers
  currently_online     = $openOnlineList.Count
  peak_concurrent      = $peakOnline
  peak_capacity_pct    = $capPct
  peak_timestamp       = if ($peakTime) { $peakTime.ToString('o') } else { $null }
  peak_players         = $peakPlayers
  capacity_assessment  = $capVerdict
  total_unique_players = $playerSummary.Count
  total_sessions       = ($completedSessions.Count + $openOnlineList.Count)
  players              = $playerSummary
  daily                = $dailySummary
  recent_sessions      = $recentSessions
}

if ($Json) {
  $resultObj | ConvertTo-Json -Depth 6
  return
}

Write-Host ""
Write-Host "=== MY-Town Player & Capacity Statistics ===" -ForegroundColor Cyan
Write-Host "  Max Player Slots   : $maxPlayers"
Write-Host "  Currently Online   : $($openOnlineList.Count)/$maxPlayers"
$peakStr = if ($peakTime) { "$peakOnline/$maxPlayers ($capPct%) on $($peakTime.ToString('yyyy-MM-dd HH:mm:ss')) [$($peakPlayers -join ', ')]" } else { "0/$maxPlayers (0%)" }
Write-Host "  All-Time Peak Load : $peakStr"
Write-Host "  Capacity Status    : $capVerdict" -ForegroundColor $(if ($capPct -ge 80) { 'Yellow' } else { 'Green' })
Write-Host "  Unique Players     : $($playerSummary.Count) | Total Sessions: $($resultObj.total_sessions)"

Write-Host ""
Write-Host "=== Per-Player Totals ===" -ForegroundColor Cyan
if ($playerSummary.Count -eq 0) {
  Write-Host "  (No player sessions recorded yet.)"
} else {
  $playerSummary | Format-Table Player, Sessions, TotalTime, AvgSession, FirstSeen, LastSeen -AutoSize | Out-String | Write-Host
}

Write-Host "=== Daily Breakdown (Last $Days Days) ===" -ForegroundColor Cyan
if ($dailySummary.Count -eq 0) {
  Write-Host "  (No activity in window.)"
} else {
  $dailySummary | Format-Table Date, UniquePlayers, Sessions, TotalPlaytime, PeakConcurrent -AutoSize | Out-String | Write-Host
}

Write-Host "=== Recent Sessions ===" -ForegroundColor Cyan
if ($recentSessions.Count -eq 0) {
  Write-Host "  (No sessions.)"
} else {
  $recentSessions | Format-Table Player, Joined, Duration, Status -AutoSize | Out-String | Write-Host
}
