# Shared helper library for MY-Town server status, control, and watchdog scripts.

function Get-McPaths {
  param([string]$ServerRoot = '', [string]$TaskPrefix = 'MY-Town')
  if ([string]::IsNullOrWhiteSpace($ServerRoot)) { $ServerRoot = Split-Path -Parent $PSScriptRoot }
  $adminDir = Join-Path $ServerRoot 'admin'
  $logsDir  = Join-Path $ServerRoot 'logs'
  $javaExe  = $null
  $localCorretto = Get-ChildItem -Path (Join-Path $ServerRoot 'Corretto') -Filter 'java.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($localCorretto) { $javaExe = $localCorretto.FullName }
  if (-not $javaExe) {
    $progCorretto = Get-ChildItem -Path 'C:\Program Files\Amazon Corretto' -Filter 'java.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($progCorretto) { $javaExe = $progCorretto.FullName }
  }
  return [PSCustomObject]@{
    ServerRoot          = $ServerRoot
    TaskPrefix          = $TaskPrefix
    ServerTaskName      = "${TaskPrefix}-Minecraft-Server"
    WatchdogTaskName    = "${TaskPrefix}-Watchdog"
    AdminDir            = $adminDir
    LogsDir             = $logsDir
    CrashReportsDir     = Join-Path $ServerRoot 'crash-reports'
    WrapperLog          = Join-Path $logsDir 'wrapper.log'
    LatestLog           = Join-Path $logsDir 'latest.log'
    IncidentLog         = Join-Path $logsDir 'uptime-incidents.log'
    IncidentJsonl       = Join-Path $logsDir 'uptime-incidents.jsonl'
    IntentionalStopFlag = Join-Path $adminDir 'intentional-stop.flag'
    WatchdogStateFile   = Join-Path $adminDir 'watchdog-state.json'
    McPasswordFile      = Join-Path $adminDir 'mcserver-password.txt'
    RconCmdScript       = Join-Path $PSScriptRoot 'mc-cmd.ps1'
    JavaExe             = $javaExe
  }
}

function Write-McIncident {
  param(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)][string]$Event,
    [string]$Cause = '',
    [string]$Details = '',
    [Nullable[int]]$PidValue = $null,
    [Nullable[int]]$DowntimeSeconds = $null
  )
  New-Item -ItemType Directory -Force -Path $Paths.LogsDir | Out-Null
  $now = Get-Date
  $tsText = $now.ToString('yyyy-MM-dd HH:mm:ss')
  $tsIso  = $now.ToString('o')

  $parts = @($Event)
  if ($Cause)   { $parts += "Cause=$Cause" }
  if ($null -ne $PidValue) { $parts += "PID=$PidValue" }
  if ($null -ne $DowntimeSeconds) {
    $span = [TimeSpan]::FromSeconds($DowntimeSeconds)
    $parts += ("Downtime={0:hh\:mm\:ss}" -f $span)
  }
  if ($Details) { $parts += $Details }

  $line = "[$tsText] " + ($parts -join ' | ')
  $utf8NoBom = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::AppendAllText($Paths.IncidentLog, "$line`r`n", $utf8NoBom)

  $record = [ordered]@{
    timestamp        = $tsIso
    event            = $Event
    cause            = $Cause
    pid              = $PidValue
    downtime_seconds = $DowntimeSeconds
    details          = $Details
  }
  $jsonLine = ($record | ConvertTo-Json -Compress)
  [System.IO.File]::AppendAllText($Paths.IncidentJsonl, "$jsonLine`r`n", $utf8NoBom)
}

function Get-WatchdogState {
  param([Parameter(Mandatory)]$Paths)
  $default = [ordered]@{
    inIncident            = $false
    incidentStartIso      = $null
    incidentCause         = $null
    lastKnownPid          = $null
    lastKnownStartIso     = $null
    playitConsecutiveFail = 0
    localSlpFail          = 0
    recentRestartIsos     = @()
    lastTunnelHost        = $null
    lastPlayitRestartIso  = $null
    lastHealthyIso        = $null
  }
  if (Test-Path -LiteralPath $Paths.WatchdogStateFile) {
    try {
      $loaded = Get-Content -LiteralPath $Paths.WatchdogStateFile -Raw -ErrorAction Stop | ConvertFrom-Json
      if ($loaded) {
        foreach ($k in @($default.Keys)) {
          if ($loaded.PSObject.Properties.Name -contains $k) {
            $default[$k] = $loaded.$k
          }
        }
      }
    } catch { }
  }
  if ($null -eq $default.recentRestartIsos) { $default.recentRestartIsos = @() }
  else { $default.recentRestartIsos = @($default.recentRestartIsos) }
  return [PSCustomObject]$default
}

function Save-WatchdogState {
  param([Parameter(Mandatory)]$Paths, [Parameter(Mandatory)]$State)
  New-Item -ItemType Directory -Force -Path $Paths.AdminDir | Out-Null
  $utf8NoBom = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::WriteAllText($Paths.WatchdogStateFile, ($State | ConvertTo-Json -Depth 5), $utf8NoBom)
}

function Get-IntentionalStopInfo {
  param([Parameter(Mandatory)]$Paths)
  if (-not (Test-Path -LiteralPath $Paths.IntentionalStopFlag)) { return $null }
  try {
    return (Get-Content -LiteralPath $Paths.IntentionalStopFlag -Raw | ConvertFrom-Json)
  } catch {
    return [PSCustomObject]@{ timestamp = (Get-Item -LiteralPath $Paths.IntentionalStopFlag).LastWriteTime.ToString('o'); reason = 'Flag file present' }
  }
}

function Get-ServerJavaProcess {
  param([Parameter(Mandatory)]$Paths)
  # 1. Identify by loopback listener ports 25565/25575
  $portPids = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 25565,25575 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique)

  $procs = @(Get-CimInstance Win32_Process -Filter "Name='java.exe'" -ErrorAction SilentlyContinue)
  if (-not $procs -or $procs.Count -eq 0) { return $null }

  $matched = $null
  foreach ($p in $procs) {
    if ($portPids -contains [int]$p.ProcessId) { $matched = $p; break }
  }
  if (-not $matched -and $Paths.JavaExe) {
    foreach ($p in $procs) {
      if ($p.ExecutablePath -and ($p.ExecutablePath -ieq $Paths.JavaExe)) { $matched = $p; break }
    }
  }
  if (-not $matched -and (Test-Path -LiteralPath $Paths.WrapperLog)) {
    $lastStart = Get-Content -LiteralPath $Paths.WrapperLog -Tail 30 -ErrorAction SilentlyContinue |
      Where-Object { $_ -match 'Started java\.exe PID=(\d+)' } | Select-Object -Last 1
    if ($lastStart -and ($lastStart -match 'PID=(\d+)')) {
      $expectedPid = [int]$Matches[1]
      $matched = $procs | Where-Object { [int]$_.ProcessId -eq $expectedPid } | Select-Object -First 1
    }
  }
  if (-not $matched) { return $null }

  $startTime = $null
  if ($matched.CreationDate) { $startTime = [datetime]$matched.CreationDate }
  return [PSCustomObject]@{
    Pid         = [int]$matched.ProcessId
    StartTime   = $startTime
    WorkingSetGB = [math]::Round(([double]$matched.WorkingSetSize) / 1GB, 2)
    Ports       = @($portPids)
  }
}

function Invoke-SchtasksQueryOrRun {
  param(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)][ValidateSet('Query', 'Run')][string]$Mode,
    [Parameter(Mandatory)][string]$TaskName,
    [string]$ServiceUser = 'mcserver'
  )
  $argsArray = if ($Mode -eq 'Query') { @('/Query', '/TN', $TaskName, '/V', '/FO', 'LIST') } else { @('/Run', '/TN', $TaskName) }
  $argsLine  = if ($Mode -eq 'Query') { "/Query /TN `"$TaskName`" /V /FO LIST" } else { "/Run /TN `"$TaskName`"" }

  # First try in current security context (works when elevated or for tasks owned by current user)
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $out = & schtasks.exe @argsArray 2>&1 | Out-String
    $code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $prevEap
  }
  if ($code -eq 0) {
    return [PSCustomObject]@{ Ok = $true; Output = $out; Context = $env:USERNAME }
  }

  # If non-elevated FZ tries to access mcserver's task, run schtasks under mcserver credentials
  if (Test-Path -LiteralPath $Paths.McPasswordFile) {
    $pw = (Get-Content -LiteralPath $Paths.McPasswordFile -Raw).Trim()
    if (-not [string]::IsNullOrWhiteSpace($pw) -and ($pw -notlike 'CHANGE-ME*')) {
      $secPw = ConvertTo-SecureString $pw -AsPlainText -Force
      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName = 'schtasks.exe'
      $psi.Arguments = $argsLine
      $psi.UserName = $ServiceUser
      $psi.Domain = $env:COMPUTERNAME
      $psi.Password = $secPw
      $psi.UseShellExecute = $false
      $psi.CreateNoWindow = $true
      $psi.RedirectStandardOutput = $true
      $psi.RedirectStandardError = $true
      $p = [System.Diagnostics.Process]::Start($psi)
      $stdOut = $p.StandardOutput.ReadToEnd()
      $stdErr = $p.StandardError.ReadToEnd()
      $p.WaitForExit()
      if ($p.ExitCode -eq 0) {
        return [PSCustomObject]@{ Ok = $true; Output = "$stdOut`n$stdErr".Trim(); Context = $ServiceUser }
      }
      return [PSCustomObject]@{ Ok = $false; Output = "$stdOut`n$stdErr".Trim(); Context = $ServiceUser }
    }
  }
  return [PSCustomObject]@{ Ok = $false; Output = $out.Trim(); Context = $env:USERNAME }
}

function Write-McVarInt {
  param([System.IO.Stream]$Stream, [int]$Value)
  $v = [uint32]$Value
  while ($true) {
    if (($v -band 0xFFFFFF80) -eq 0) {
      $Stream.WriteByte([byte]$v)
      return
    }
    $Stream.WriteByte([byte](($v -band 0x7F) -bor 0x80))
    $v = $v -shr 7
  }
}

function Read-McVarInt {
  param([System.IO.Stream]$Stream)
  $numRead = 0
  $result = 0
  while ($true) {
    $b = $Stream.ReadByte()
    if ($b -lt 0) { throw "Unexpected EOF reading Minecraft VarInt" }
    $result = $result -bor (($b -band 0x7F) -shl (7 * $numRead))
    $numRead++
    if ($numRead -gt 5) { throw "VarInt too large" }
    if (($b -band 0x80) -eq 0) { return $result }
  }
}

function Read-ExactBytes {
  param([System.IO.Stream]$Stream, [int]$Count)
  $buf = New-Object byte[] $Count
  $offset = 0
  while ($offset -lt $Count) {
    $n = $Stream.Read($buf, $offset, $Count - $offset)
    if ($n -le 0) { throw "Unexpected EOF after $offset/$Count bytes" }
    $offset += $n
  }
  return $buf
}

function Test-MinecraftSlp {
  param(
    [Parameter(Mandatory)][string]$TargetHost,
    [int]$Port = 25565,
    [switch]$ResolveSrv,
    [int]$TimeoutMs = 5000
  )
  $connectHost = $TargetHost
  $connectPort = $Port
  $usedSrv = $false
  $srvRecordHost = $null

  if ($ResolveSrv) {
    try {
      $srv = Resolve-DnsName -Name "_minecraft._tcp.$TargetHost" -Type SRV -ErrorAction Stop |
        Sort-Object Priority, Weight | Select-Object -First 1
      if ($srv -and $srv.NameTarget) {
        $connectHost = $srv.NameTarget.TrimEnd('.')
        $connectPort = [int]$srv.Port
        $usedSrv = $true
        $srvRecordHost = "${connectHost}:${connectPort}"
      }
    } catch { }
  }

  $tcp = New-Object System.Net.Sockets.TcpClient
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $iar = $tcp.BeginConnect($connectHost, $connectPort, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
      throw "TCP connect timed out after ${TimeoutMs}ms to ${connectHost}:${connectPort}"
    }
    $tcp.EndConnect($iar)
    $tcp.ReceiveTimeout = $TimeoutMs
    $tcp.SendTimeout = $TimeoutMs
    $s = $tcp.GetStream()

    $hostBytes = [System.Text.Encoding]::UTF8.GetBytes($connectHost)
    $payload = New-Object System.IO.MemoryStream
    Write-McVarInt $payload 0
    Write-McVarInt $payload 777
    Write-McVarInt $payload $hostBytes.Length
    $payload.Write($hostBytes, 0, $hostBytes.Length)
    $payload.WriteByte([byte](($connectPort -shr 8) -band 0xFF))
    $payload.WriteByte([byte]($connectPort -band 0xFF))
    Write-McVarInt $payload 1
    $hsBytes = $payload.ToArray()

    $frame = New-Object System.IO.MemoryStream
    Write-McVarInt $frame $hsBytes.Length
    $frame.Write($hsBytes, 0, $hsBytes.Length)
    $frame.Write([byte[]]@(0x01, 0x00), 0, 2)
    $outBytes = $frame.ToArray()
    $s.Write($outBytes, 0, $outBytes.Length)
    $s.Flush()

    $pktLen = Read-McVarInt $s
    if ($pktLen -le 0 -or $pktLen -gt 1048576) { throw "Invalid status packet length: $pktLen" }
    $pktId = Read-McVarInt $s
    if ($pktId -ne 0) { throw "Unexpected SLP packet id: $pktId" }
    $jsonLen = Read-McVarInt $s
    if ($jsonLen -le 0 -or $jsonLen -gt 1048576) { throw "Invalid JSON payload length: $jsonLen" }
    $jsonBytes = Read-ExactBytes $s $jsonLen
    $sw.Stop()

    $jsonStr = [System.Text.Encoding]::UTF8.GetString($jsonBytes)
    $obj = $jsonStr | ConvertFrom-Json
    $motdText = if ($obj.description -is [string]) { $obj.description } elseif ($obj.description.text) { $obj.description.text } else { ($obj.description | ConvertTo-Json -Compress) }
    return [PSCustomObject]@{
      Online        = $true
      ConnectHost   = $connectHost
      ConnectPort   = $connectPort
      UsedSrv       = $usedSrv
      SrvTarget     = $srvRecordHost
      LatencyMs     = [int]$sw.ElapsedMilliseconds
      Version       = [string]$obj.version.name
      Protocol      = [int]$obj.version.protocol
      PlayersOnline = [int]$obj.players.online
      PlayersMax    = [int]$obj.players.max
      Motd          = $motdText
      Error         = $null
    }
  } catch {
    return [PSCustomObject]@{
      Online        = $false
      ConnectHost   = $connectHost
      ConnectPort   = $connectPort
      UsedSrv       = $usedSrv
      SrvTarget     = $srvRecordHost
      LatencyMs     = [int]$sw.ElapsedMilliseconds
      Version       = $null
      Protocol      = $null
      PlayersOnline = $null
      PlayersMax    = $null
      Motd          = $null
      Error         = $_.Exception.Message
    }
  } finally {
    $tcp.Close()
  }
}

function Get-PlayitTunnelHost {
  param([Parameter(Mandatory)]$Paths, $State = $null)
  # 1. Check live log first for most recent setup tunnel
  if (Test-Path -LiteralPath $Paths.LatestLog) {
    $line = Get-Content -LiteralPath $Paths.LatestLog -Tail 250 -ErrorAction SilentlyContinue |
      Where-Object { $_ -match 'found minecraft java tunnel:\s*([^\s]+)' } | Select-Object -Last 1
    if ($line -and ($line -match 'found minecraft java tunnel:\s*([^\s]+)')) {
      return $Matches[1].Trim()
    }
  }
  # 2. Check cached state (survives midnight log rotation)
  if ($State -and -not [string]::IsNullOrWhiteSpace($State.lastTunnelHost)) {
    return [string]$State.lastTunnelHost
  }
  # 3. Query Playit /agents/rundata via configured agent-secret
  $playitCfg = Join-Path $Paths.ServerRoot 'plugins\playit-gg\config.yml'
  if (Test-Path -LiteralPath $playitCfg) {
    $cfgLine = Get-Content -LiteralPath $playitCfg -ErrorAction SilentlyContinue | Where-Object { $_ -match '^agent-secret:' } | Select-Object -First 1
    if ($cfgLine) {
      $secret = ($cfgLine -replace '^agent-secret:\s*', '').Trim().Trim('"').Trim("'")
      if (-not [string]::IsNullOrWhiteSpace($secret) -and ($secret -notlike 'CHANGE-ME*')) {
        try {
          $resp = Invoke-RestMethod -Method Post -Uri 'https://api.playit.gg/agents/rundata' `
            -Headers @{ Authorization = "Agent-Key $secret" } -Body '{}' -ContentType 'application/json' -TimeoutSec 6
          $t = $resp.data.tunnels | Where-Object { $_.tunnel_type -eq 'minecraft-java' -or $_.assigned_domain } | Select-Object -First 1
          if ($t -and $t.assigned_domain) { return [string]$t.assigned_domain }
        } catch { }
      }
    }
  }
  return $null
}

function Invoke-RconSafe {
  param([Parameter(Mandatory)]$Paths, [Parameter(Mandatory)][string]$Command, [int]$TimeoutMs = 6000)
  try {
    $out = & $Paths.RconCmdScript -Command $Command -TimeoutMs $TimeoutMs 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
      return [PSCustomObject]@{ Ok = $false; Output = $out.Trim() }
    }
    return [PSCustomObject]@{ Ok = $true; Output = $out.Trim() }
  } catch {
    return [PSCustomObject]@{ Ok = $false; Output = $_.Exception.Message }
  }
}

function Get-ServerDowntimeDiagnosis {
  param([Parameter(Mandatory)]$Paths, $State = $null)
  $lastStartTime = $null
  $lastWrapperPid = $null
  $lastWrapperExit = $null
  $lastWrapperFatal = $null

  if (Test-Path -LiteralPath $Paths.WrapperLog) {
    $wLines = @(Get-Content -LiteralPath $Paths.WrapperLog -Tail 30 -ErrorAction SilentlyContinue)
    for ($i = $wLines.Count - 1; $i -ge 0; $i--) {
      if (-not $lastWrapperExit -and ($wLines[$i] -match '^\[([^\]]+)\].*exited with code (-?\d+)')) {
        try { $lastWrapperExit = "code $($Matches[2]) at $($Matches[1])" } catch { }
      }
      if (-not $lastWrapperFatal -and ($wLines[$i] -match '^\[([^\]]+)\]\s*FATAL:\s*(.+)$')) {
        $lastWrapperFatal = "$($Matches[2]) (at $($Matches[1]))"
      }
      if (-not $lastStartTime -and ($wLines[$i] -match '^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*Started java\.exe PID=(\d+)')) {
        try { $lastStartTime = [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
        $lastWrapperPid = $Matches[2]
        break
      }
    }
  }
  if (-not $lastStartTime -and $State -and $State.lastKnownStartIso) {
    try { $lastStartTime = [datetime]::Parse($State.lastKnownStartIso) } catch { }
  }
  if (-not $lastStartTime) { $lastStartTime = (Get-Date).AddHours(-12) }

  # 1. Check crash-reports newer than last server start
  if (Test-Path -LiteralPath $Paths.CrashReportsDir) {
    $crash = Get-ChildItem -LiteralPath $Paths.CrashReportsDir -Filter 'crash-*.txt' -File -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -ge $lastStartTime } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($crash) {
      $desc = (Get-Content -LiteralPath $crash.FullName -TotalCount 15 -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '^Description:' } | Select-Object -First 1)
      return [PSCustomObject]@{ Cause = 'JVM_CRASH_REPORT'; Details = "$($crash.Name) ($desc)" }
    }
  }

  # 2. Check Windows System Event Log for reboot / Windows Update / unexpected power loss since last start
  try {
    $events = @(Get-WinEvent -FilterHashtable @{
      LogName   = 'System'
      Id        = @(41, 1074, 6008)
      StartTime = $lastStartTime
    } -ErrorAction Stop | Sort-Object TimeCreated -Descending)
    if ($events.Count -gt 0) {
      $ev = $events[0]
      $shortMsg = ($ev.Message -split "`r?`n")[0]
      switch ([int]$ev.Id) {
        1074 { return [PSCustomObject]@{ Cause = 'WINDOWS_REBOOT'; Details = "Event 1074 at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')): $shortMsg" } }
        6008 { return [PSCustomObject]@{ Cause = 'WINDOWS_UNEXPECTED_SHUTDOWN'; Details = "Event 6008 at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')): $shortMsg" } }
        41   { return [PSCustomObject]@{ Cause = 'WINDOWS_POWER_LOSS_OR_BSOD'; Details = "Event 41 at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')): $shortMsg" } }
      }
    }
  } catch { }

  # 3. Check latest.log for OOM / Paper Watchdog / bind failure / unexpected /stop
  if (Test-Path -LiteralPath $Paths.LatestLog) {
    $logTail = @(Get-Content -LiteralPath $Paths.LatestLog -Tail 80 -ErrorAction SilentlyContinue)
    $oom = $logTail | Where-Object { $_ -match 'OutOfMemoryError|Java heap space' } | Select-Object -Last 1
    if ($oom) { return [PSCustomObject]@{ Cause = 'JVM_OUT_OF_MEMORY'; Details = $oom.Trim() } }

    $bind = $logTail | Where-Object { $_ -match 'FAILED TO BIND TO PORT' } | Select-Object -Last 1
    if ($bind) { return [PSCustomObject]@{ Cause = 'PORT_BIND_FAILED'; Details = $bind.Trim() } }

    $watchdog = $logTail | Where-Object { $_ -match 'The server has not responded for|WatchdogThread' } | Select-Object -Last 1
    if ($watchdog) { return [PSCustomObject]@{ Cause = 'PAPER_WATCHDOG_FREEZE'; Details = $watchdog.Trim() } }

    $ex = $logTail | Where-Object { $_ -match 'Encountered an unexpected exception' } | Select-Object -Last 1
    if ($ex) { return [PSCustomObject]@{ Cause = 'SERVER_EXCEPTION'; Details = $ex.Trim() } }

    $unexpStop = $logTail | Where-Object { $_ -match 'Stopping the server|Stopping server' } | Select-Object -Last 1
    if ($unexpStop) {
      return [PSCustomObject]@{
        Cause   = 'UNEXPECTED_STOP_COMMAND_OR_SIGNAL'
        Details = "Server logged '$($unexpStop.Trim())' without intentional-stop.flag (WrapperExit=$lastWrapperExit)"
      }
    }
  }

  if ($lastWrapperFatal) {
    return [PSCustomObject]@{ Cause = 'WRAPPER_FATAL'; Details = $lastWrapperFatal }
  }
  if ($lastWrapperExit) {
    return [PSCustomObject]@{ Cause = 'PROCESS_EXITED'; Details = "Wrapper reported exit $lastWrapperExit for PID=$lastWrapperPid" }
  }
  return [PSCustomObject]@{ Cause = 'PROCESS_TERMINATED_EXTERNALLY'; Details = "java.exe PID=$lastWrapperPid disappeared without graceful exit log (OOM killer / taskkill / reboot)" }
}
