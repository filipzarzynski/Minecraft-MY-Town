param(
  [string]$ServerRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$ServiceUser = 'mcserver',
  [string]$TaskPrefix = 'MY-Town',
  [string]$BackupTime = '04:30',
  [switch]$NoStart
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "harden-environment.ps1 must be run from an Administrator PowerShell window."
}

function Resolve-JavaExe {
  $localCorretto = Get-ChildItem -Path (Join-Path $ServerRoot 'Corretto') -Filter 'java.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($localCorretto) { return $localCorretto.FullName }
  $progCorretto = Get-ChildItem -Path 'C:\Program Files\Amazon Corretto' -Filter 'java.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($progCorretto) { return $progCorretto.FullName }
  if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin\java.exe'))) {
    return (Join-Path $env:JAVA_HOME 'bin\java.exe')
  }
  $javaCmd = Get-Command java -ErrorAction SilentlyContinue
  if ($javaCmd) { return $javaCmd.Source }
  throw "Java binary (java.exe) not found."
}

$adminDir = Join-Path $ServerRoot 'admin'
$logFile = Join-Path $adminDir 'harden-report.log'
New-Item -ItemType Directory -Force -Path $adminDir | Out-Null
[System.IO.File]::WriteAllText($logFile, "=== $TaskPrefix Hardening Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===`r`n", (New-Object System.Text.UTF8Encoding $false))

function Log([string]$Msg) {
  $line = "[$(Get-Date -Format 'HH:mm:ss')] $Msg"
  Add-Content -Path $logFile -Value $line
  Write-Host $line
}

try {
  $javaExe = Resolve-JavaExe

  # 1. Remove standalone Playit agent if present (prefer in-JVM plugin)
  Log "Step 1: Checking for standalone DevelopedMethods.playit..."
  $wingetExe = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
  if (-not (Test-Path $wingetExe)) {
    $cmdWinget = Get-Command winget -ErrorAction SilentlyContinue
    if ($cmdWinget) { $wingetExe = $cmdWinget.Source }
  }
  $playitProcs = Get-Process -Name 'playit*' -ErrorAction SilentlyContinue
  if ($playitProcs) {
    $playitProcs | Stop-Process -Force -ErrorAction SilentlyContinue
    Log "Stopped running standalone playit processes."
  }
  if ($wingetExe -and (Test-Path $wingetExe)) {
    $uninstallOut = & $wingetExe uninstall --id DevelopedMethods.playit --silent --accept-source-agreements 2>&1 | Out-String
    if ($uninstallOut.Trim()) { Log $uninstallOut.Trim() }
  }
  if (Test-Path 'C:\Program Files\playit_gg') {
    Remove-Item -Path 'C:\Program Files\playit_gg' -Recurse -Force -ErrorAction SilentlyContinue
    Log "Removed leftover C:\Program Files\playit_gg directory."
  }

  # 2. Create or harden dedicated unprivileged service account
  Log "Step 2: Provisioning/hardening local user '$ServiceUser'..."
  $mcPassFile = Join-Path $adminDir 'mcserver-password.txt'
  if (-not (Test-Path $mcPassFile)) {
    throw "Missing $mcPassFile. Run scripts\bootstrap-server.ps1 first."
  }
  $mcPassPlain = (Get-Content -Path $mcPassFile -Raw).Trim()
  if ([string]::IsNullOrWhiteSpace($mcPassPlain) -or $mcPassPlain -like 'CHANGE-ME*') {
    throw "$mcPassFile still contains a placeholder password. Run scripts\bootstrap-server.ps1 or replace it with a strong password first."
  }
  $mcPassSec = ConvertTo-SecureString $mcPassPlain -AsPlainText -Force

  $existingUser = Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue
  if (-not $existingUser) {
    New-LocalUser -Name $ServiceUser -Password $mcPassSec -PasswordNeverExpires $true -UserMayChangePassword $false -Description 'Unprivileged Minecraft server service account' | Out-Null
    Add-LocalGroupMember -Group 'Users' -Member $ServiceUser -ErrorAction SilentlyContinue
    Log "Created unprivileged local user '$ServiceUser'."
  } else {
    Set-LocalUser -Name $ServiceUser -Password $mcPassSec -PasswordNeverExpires $true -UserMayChangePassword $false
    Enable-LocalUser -Name $ServiceUser
  }
  $mcUser = Get-LocalUser -Name $ServiceUser
  $mcSid = $mcUser.SID.Value
  Log "User=$ServiceUser SID=$mcSid Enabled=$($mcUser.Enabled) UserMayChangePassword=$($mcUser.UserMayChangePassword)"

  $privilegedGroups = @('Administrators', 'Power Users', 'Remote Desktop Users', 'Backup Operators', 'Server Operators')
  foreach ($grp in $privilegedGroups) {
    $members = Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue
    if ($members | Where-Object { $_.SID.Value -eq $mcSid }) {
      Remove-LocalGroupMember -Group $grp -Member $mcSid
      Log "Removed $ServiceUser from privileged group '$grp'."
    }
  }

  # 3. Apply least-privilege NTFS ACLs
  Log "Step 3: Applying least-privilege NTFS ACLs under $ServerRoot..."
  $ownerSid = $identity.User.Value
  function Invoke-Icacls([string[]]$IcaclsArgs) {
    $out = & icacls @IcaclsArgs 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
      throw "icacls $($IcaclsArgs -join ' ') failed ($LASTEXITCODE): $out"
    }
  }

  # Root runtime: service account gets Modify on world/logs/config/plugin data
  Invoke-Icacls @($ServerRoot, '/grant', 'BUILTIN\Administrators:(OI)(CI)F', '/grant', 'NT AUTHORITY\SYSTEM:(OI)(CI)F', '/grant', "*${ownerSid}:(OI)(CI)F", '/grant', "${ServiceUser}:(OI)(CI)M")

  # Admin vault & local backups: Owner, Administrators & SYSTEM only, explicitly deny service account
  foreach ($privateDir in @($adminDir, (Join-Path $ServerRoot 'backups'))) {
    New-Item -ItemType Directory -Force -Path $privateDir | Out-Null
    Invoke-Icacls @($privateDir, '/inheritance:r', '/grant:r', 'BUILTIN\Administrators:(OI)(CI)F', '/grant:r', 'NT AUTHORITY\SYSTEM:(OI)(CI)F', '/grant:r', "*${ownerSid}:(OI)(CI)F", '/deny', "${ServiceUser}:(OI)(CI)F")
  }

  # Immutable code/scripts/JDK/libraries/versions: ReadAndExecute ONLY for service account
  $correttoDir = Join-Path $ServerRoot 'Corretto'
  if (Test-Path $correttoDir) {
    $takeownOut = & takeown.exe /F $correttoDir /R /A /D Y 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
      throw "takeown failed on ${correttoDir} ($LASTEXITCODE): $takeownOut"
    }
  }

  foreach ($roDir in @('scripts', 'Corretto', 'libraries', 'versions', 'cache', 'src', 'config-templates')) {
    $p = Join-Path $ServerRoot $roDir
    if (Test-Path $p) {
      Invoke-Icacls @($p, '/inheritance:r', '/grant:r', 'BUILTIN\Administrators:(OI)(CI)F', '/grant:r', 'NT AUTHORITY\SYSTEM:(OI)(CI)F', '/grant:r', "*${ownerSid}:(OI)(CI)F", '/grant:r', "${ServiceUser}:(OI)(CI)RX")
    }
  }
  if (Test-Path $correttoDir) {
    Invoke-Icacls @((Join-Path $correttoDir '*'), '/reset', '/T', '/Q')
  }

  # Lock executable jars/installers to ReadAndExecute for service account
  $immutableFiles = @()
  $immutableFiles += Get-ChildItem -Path $ServerRoot -Filter 'purpur-*.jar' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
  $immutableFiles += Get-ChildItem -Path $ServerRoot -Filter '*.msi' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
  $immutableFiles += Get-ChildItem -Path (Join-Path $ServerRoot 'plugins') -Filter '*.jar' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName

  foreach ($f in $immutableFiles) {
    if ($f -and (Test-Path $f)) {
      Invoke-Icacls @($f, '/inheritance:r', '/grant:r', 'BUILTIN\Administrators:F', '/grant:r', 'NT AUTHORITY\SYSTEM:F', '/grant:r', "*${ownerSid}:F", '/grant:r', "${ServiceUser}:RX")
    }
  }
  Log "NTFS ACL hardening complete."

  # 4. Windows Defender Firewall SID-bound isolation rules
  Log "Step 4: Creating SID-bound Windows Defender Firewall rules..."
  $sddlUser = "D:(A;;CC;;;$mcSid)"
  $rulePrefix = "${TaskPrefix}-${ServiceUser}-"
  Get-NetFirewallRule -DisplayName "$rulePrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

  $blockedCidrs = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10')
  New-NetFirewallRule -DisplayName "${rulePrefix}Block-Outbound-LAN-Meshnet" `
    -Description "Prevent $ServiceUser from initiating outbound connections to RFC1918 LAN, Link-Local, or VPN Meshnet/CGNAT ranges." `
    -Direction Outbound `
    -Action Block `
    -Protocol Any `
    -RemoteAddress $blockedCidrs `
    -LocalUser $sddlUser `
    -Profile Any `
    -Enabled True | Out-Null

  New-NetFirewallRule -DisplayName "${rulePrefix}Block-Inbound-Java" `
    -Description "Block direct inbound connections to Minecraft java.exe on non-loopback interfaces." `
    -Direction Inbound `
    -Action Block `
    -Protocol Any `
    -Program $javaExe `
    -Profile Any `
    -Enabled True | Out-Null
  Log "Firewall rules configured cleanly."

  # 5. Grant SeBatchLogonRight & register Scheduled Tasks
  Log "Step 5: Ensuring SeBatchLogonRight and registering Scheduled Tasks..."
  $secTempDir = Join-Path $env:TEMP ("mytown-sec-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $secTempDir | Out-Null
  try {
    $infPath = Join-Path $secTempDir 'rights.inf'
    $sdbPath = Join-Path $secTempDir 'rights.sdb'
    & secedit /export /cfg $infPath /areas USER_RIGHTS /quiet
    if ($LASTEXITCODE -ne 0) { throw "secedit /export failed ($LASTEXITCODE)" }

    $lines = [System.Collections.Generic.List[string]](Get-Content -Path $infPath -Encoding Unicode)
    $sidToken = "*$mcSid"
    $foundBatch = $false
    $privSectionIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
      if ($lines[$i].Trim() -eq '[Privilege Rights]') { $privSectionIdx = $i }
      if ($lines[$i] -match '^\s*SeBatchLogonRight\s*=\s*(.*)$') {
        $foundBatch = $true
        $existing = ($Matches[1] -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        if ($existing -notcontains $sidToken -and $existing -notcontains $ServiceUser) {
          $lines[$i] = 'SeBatchLogonRight = ' + (($existing + $sidToken) -join ',')
          [System.IO.File]::WriteAllLines($infPath, $lines, [System.Text.Encoding]::Unicode)
          & secedit /configure /db $sdbPath /cfg $infPath /areas USER_RIGHTS /quiet
          if ($LASTEXITCODE -ne 0) { throw "secedit /configure failed ($LASTEXITCODE)" }
          Log "Granted SeBatchLogonRight to $sidToken."
        } else {
          Log "SeBatchLogonRight already includes $ServiceUser."
        }
        break
      }
    }
    if (-not $foundBatch) {
      if ($privSectionIdx -ge 0) {
        $lines.Insert($privSectionIdx + 1, "SeBatchLogonRight = $sidToken")
      } else {
        $lines.Add('[Privilege Rights]')
        $lines.Add("SeBatchLogonRight = $sidToken")
      }
      [System.IO.File]::WriteAllLines($infPath, $lines, [System.Text.Encoding]::Unicode)
      & secedit /configure /db $sdbPath /cfg $infPath /areas USER_RIGHTS /quiet
      if ($LASTEXITCODE -ne 0) { throw "secedit /configure failed ($LASTEXITCODE)" }
      Log "Added SeBatchLogonRight = $sidToken."
    }
  } finally {
    Remove-Item -Recurse -Force $secTempDir -ErrorAction SilentlyContinue
  }

  $mcTaskName = "${TaskPrefix}-Minecraft-Server"
  $startScript = Join-Path $ServerRoot 'scripts\start-server.ps1'
  Stop-ScheduledTask -TaskName $mcTaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $mcTaskName -Confirm:$false -ErrorAction SilentlyContinue
  $mcAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$startScript`"" `
    -WorkingDirectory $ServerRoot
  $mcTrigger = New-ScheduledTaskTrigger -AtStartup
  $mcSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $mcTaskName `
    -Action $mcAction `
    -Trigger $mcTrigger `
    -Settings $mcSettings `
    -User "$env:COMPUTERNAME\$ServiceUser" `
    -Password $mcPassPlain `
    -RunLevel Limited `
    -Description "Runs $TaskPrefix Purpur server headless under unprivileged $ServiceUser." | Out-Null
  Log "Registered Scheduled Task '$mcTaskName'."

  $bkTaskName = "${TaskPrefix}-Daily-Backup"
  $backupScript = Join-Path $ServerRoot 'scripts\backup-world.ps1'
  Unregister-ScheduledTask -TaskName $bkTaskName -Confirm:$false -ErrorAction SilentlyContinue
  $adminPrincipalName = $identity.Name
  $bkAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$backupScript`"" `
    -WorkingDirectory $ServerRoot
  $bkTrigger = New-ScheduledTaskTrigger -Daily -At $BackupTime
  $bkPrincipal = New-ScheduledTaskPrincipal -UserId $adminPrincipalName -LogonType S4U -RunLevel Highest
  $bkSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $bkTaskName `
    -Action $bkAction `
    -Trigger $bkTrigger `
    -Principal $bkPrincipal `
    -Settings $bkSettings `
    -Description "Daily RCON-safe world backup uploaded to Google Drive via least-privilege rclone." | Out-Null
  Log "Registered Scheduled Task '$bkTaskName' under $adminPrincipalName."

  # 6. Start Minecraft Server Scheduled Task
  if (-not $NoStart) {
    Log "Step 6: Starting Scheduled Task '$mcTaskName'..."
    Start-ScheduledTask -TaskName $mcTaskName
    Start-Sleep -Seconds 5
    $taskInfo = Get-ScheduledTaskInfo -TaskName $mcTaskName
    Log "Task '$mcTaskName' State=$((Get-ScheduledTask -TaskName $mcTaskName).State) LastTaskResult=$($taskInfo.LastTaskResult)"
    $wrapperLog = Join-Path $ServerRoot 'logs\wrapper.log'
    if (Test-Path $wrapperLog) {
      Log "--- wrapper.log ---"
      Get-Content -Path $wrapperLog -Tail 15 | ForEach-Object { Log $_ }
    }
    $javaProc = Get-Process -Name 'java' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $javaExe }
    foreach ($jp in $javaProc) {
      Log "Running java.exe PID=$($jp.Id) ProcessorAffinity=$($jp.ProcessorAffinity) PriorityClass=$($jp.PriorityClass)"
    }
  }
  Log "=== Hardening Complete ==="
} catch {
  Log "ERROR: $_"
  throw
}
