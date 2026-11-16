param(
  [string]$ServerRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$ServiceUser = 'mcserver',
  [string]$InviteCode,
  [switch]$DownloadDeps,
  [switch]$AcceptEula
)

$ErrorActionPreference = 'Stop'

function Resolve-JdkBin {
  $localCorretto = Get-ChildItem -Path (Join-Path $ServerRoot 'Corretto') -Filter 'javac.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($localCorretto) { return $localCorretto.DirectoryName }
  $progCorretto = Get-ChildItem -Path 'C:\Program Files\Amazon Corretto' -Filter 'javac.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($progCorretto) { return $progCorretto.DirectoryName }
  if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin\javac.exe'))) {
    return (Join-Path $env:JAVA_HOME 'bin')
  }
  $javacCmd = Get-Command javac -ErrorAction SilentlyContinue
  if ($javacCmd) { return (Split-Path -Parent $javacCmd.Source) }
  throw "JDK 25 (javac.exe) not found. Install Amazon Corretto 25 or place it under '$ServerRoot\Corretto\'."
}

function New-SecretString([int]$Length, [string]$Charset) {
  $sb = New-Object System.Text.StringBuilder
  for ($i = 0; $i -lt $Length; $i++) {
    $idx = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(0, $Charset.Length)
    [void]$sb.Append($Charset[$idx])
  }
  return $sb.ToString()
}

function Test-NeedsSecret([string]$Path) {
  if (-not (Test-Path $Path)) { return $true }
  $val = (Get-Content -Path $Path -Raw).Trim()
  return ([string]::IsNullOrWhiteSpace($val) -or $val -like 'CHANGE-ME*')
}

function Get-SafeFileName([string]$RawName) {
  $leaf = [System.IO.Path]::GetFileName($RawName)
  if ([string]::IsNullOrWhiteSpace($leaf) -or $leaf -ne $RawName -or $leaf -eq '.' -or $leaf -eq '..') {
    throw "Unsafe remote filename rejected: '$RawName'"
  }
  return $leaf
}

foreach ($d in @('admin', 'backups', 'logs', 'plugins', 'scripts')) {
  New-Item -ItemType Directory -Force -Path (Join-Path $ServerRoot $d) | Out-Null
}

# 1. Rotate any missing or CHANGE-ME placeholder secrets in admin\
$alnum = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
$complex = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#_-+=?'

$mcPassFile = Join-Path $ServerRoot 'admin\mcserver-password.txt'
$rconFile = Join-Path $ServerRoot 'admin\rcon-secret.txt'
$inviteFile = Join-Path $ServerRoot 'admin\invite-code.txt'

if (Test-NeedsSecret $mcPassFile) {
  $mcPass = 'Mc!' + (New-SecretString 29 $complex) + '9A'
  [System.IO.File]::WriteAllText($mcPassFile, $mcPass, (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Generated $ServiceUser service password at $mcPassFile"
}
if (Test-NeedsSecret $rconFile) {
  $rconPass = New-SecretString 32 $alnum
  [System.IO.File]::WriteAllText($rconFile, $rconPass, (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Generated RCON password at $rconFile"
}
if ($InviteCode -or (Test-NeedsSecret $inviteFile)) {
  $code = if ($InviteCode) { $InviteCode.Trim() } else { 'MYTOWN-' + (New-SecretString 12 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789') }
  [System.IO.File]::WriteAllText($inviteFile, $code, (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Set server invite code at $inviteFile"
}

# 2. Download third-party jars from official APIs with cryptographic verification
if ($DownloadDeps) {
  Write-Host "Downloading Purpur 26.3 and third-party plugins from official APIs..."
  $purpurInfo = Invoke-RestMethod 'https://api.purpurmc.org/v2/purpur/26.3'
  $build = [string]$purpurInfo.builds.latest
  $buildMeta = Invoke-RestMethod "https://api.purpurmc.org/v2/purpur/26.3/$build"
  $purpurFileName = Get-SafeFileName "purpur-26.3-$build.jar"
  $purpurJarPath = Join-Path $ServerRoot $purpurFileName
  if (-not (Test-Path -LiteralPath $purpurJarPath)) {
    Invoke-WebRequest -Uri "https://api.purpurmc.org/v2/purpur/26.3/$build/download" -OutFile $purpurJarPath
    if (-not $buildMeta.md5) { throw "Missing MD5 hash in Purpur API response." }
    $actualMd5 = (Get-FileHash -Path $purpurJarPath -Algorithm MD5).Hash.ToLowerInvariant()
    if ($actualMd5 -ne $buildMeta.md5.ToLowerInvariant()) {
      Remove-Item -LiteralPath $purpurJarPath -Force -ErrorAction SilentlyContinue
      throw "MD5 verification failed for $purpurFileName"
    }
    Write-Host "Downloaded & MD5 verified: $purpurJarPath"
  }

  $playitRel = Invoke-RestMethod 'https://api.github.com/repos/playit-cloud/playit-minecraft-plugin/releases/latest'
  $playitAsset = $playitRel.assets | Where-Object { $_.name -like '*.jar' } | Select-Object -First 1
  if ($playitAsset) {
    $safePlayitName = Get-SafeFileName $playitAsset.name
    $playitOut = Join-Path $ServerRoot "plugins\$safePlayitName"
    Invoke-WebRequest -Uri $playitAsset.browser_download_url -OutFile $playitOut
    if (-not $playitAsset.digest -or $playitAsset.digest -notmatch '^sha256:([a-fA-F0-9]{64})$') {
      Remove-Item -LiteralPath $playitOut -Force -ErrorAction SilentlyContinue
      throw "Missing SHA-256 digest in GitHub release metadata for $safePlayitName"
    }
    $expectedSha256 = $Matches[1].ToLowerInvariant()
    $actualSha256 = (Get-FileHash -Path $playitOut -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
      Remove-Item -LiteralPath $playitOut -Force -ErrorAction SilentlyContinue
      throw "SHA-256 verification failed for $safePlayitName"
    }
    Write-Host "Downloaded & SHA-256 verified: $playitOut"
  }

  foreach ($slug in @('chunky', 'purpurextras', 'axvaults')) {
    $vers = Invoke-RestMethod "https://api.modrinth.com/v2/project/$slug/version?loaders=%5B%22paper%22%5D"
    $v = $vers | Select-Object -First 1
    $f = $v.files | Select-Object -First 1
    $safeModName = Get-SafeFileName $f.filename
    $outFile = Join-Path $ServerRoot "plugins\$safeModName"
    Invoke-WebRequest -Uri $f.url -OutFile $outFile
    $actual = (Get-FileHash -Path $outFile -Algorithm SHA512).Hash.ToLowerInvariant()
    if ($actual -ne $f.hashes.sha512.ToLowerInvariant()) {
      Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
      throw "SHA-512 verification failed for $safeModName"
    }
    Write-Host "Downloaded & SHA-512 verified: $outFile"
  }
}

# 3. Pin ServerJar in scripts\ram-mode.json and unpack Purpur server libraries via Paperclip patchonly
$purpurJar = Get-ChildItem -Path $ServerRoot -Filter 'purpur-*.jar' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $purpurJar) {
  throw "No purpur-*.jar found in $ServerRoot. Place Purpur 26.3 jar there or pass -DownloadDeps."
}

$ramModePath = Join-Path $ServerRoot 'scripts\ram-mode.json'
if (Test-Path -LiteralPath $ramModePath) {
  $ramCfg = Get-Content -Path $ramModePath -Raw | ConvertFrom-Json
  if ([string]::IsNullOrWhiteSpace($ramCfg.ServerJar)) {
    $ramCfg.ServerJar = $purpurJar.Name
    $ramCfg | ConvertTo-Json -Depth 4 | Set-Content -Path $ramModePath -Encoding UTF8
    Write-Host "Pinned ServerJar='$($purpurJar.Name)' in $ramModePath"
  }
}

$jdkBin = Resolve-JdkBin
$javaExe = Join-Path $jdkBin 'java.exe'
if (-not (Test-Path (Join-Path $ServerRoot 'libraries\com\mojang\brigadier'))) {
  Write-Host "Unpacking Purpur libraries via Paperclip (-Dpaperclip.patchonly=true)..."
  Push-Location $ServerRoot
  try {
    & $javaExe '-Dpaperclip.patchonly=true' -jar $purpurJar.FullName
    if ($LASTEXITCODE -ne 0) { throw "Paperclip patchonly exited with code $LASTEXITCODE" }
  } finally {
    Pop-Location
  }
}

# 4. Compile MYTownGatekeeper.jar from source and sync invite-code into plugins\MYTownGatekeeper\config.yml
& (Join-Path $PSScriptRoot 'build-gatekeeper.ps1') -ServerRoot $ServerRoot

$inviteVal = (Get-Content -Path $inviteFile -Raw).Trim()
$yamlSafeInvite = $inviteVal.Replace('\', '\\').Replace('"', '\"')
$gkDir = Join-Path $ServerRoot 'plugins\MYTownGatekeeper'
New-Item -ItemType Directory -Force -Path $gkDir | Out-Null
$gkConfig = Join-Path $gkDir 'config.yml'
if (-not (Test-Path $gkConfig)) {
  $cfgText = @"
# MYTownGatekeeper configuration
invite-code: "$yamlSafeInvite"
session-ttl-hours: 24
auth-timeout-seconds: 90
min-password-length: 6
max-password-length: 128
max-failed-attempts: 5
lockout-minutes: 15
"@
  [System.IO.File]::WriteAllText($gkConfig, $cfgText, (New-Object System.Text.UTF8Encoding $false))
} else {
  $gkText = Get-Content -Path $gkConfig -Raw
  if ($gkText -match 'invite-code:\s*"?CHANGE-ME[^"\r\n]*"?' -or $InviteCode) {
    $gkText = [regex]::Replace($gkText, 'invite-code:\s*"?[^"\r\n]*"?', { param($m) "invite-code: `"$yamlSafeInvite`"" })
    [System.IO.File]::WriteAllText($gkConfig, $gkText, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Synced invite code into $gkConfig"
  }
}

# 5. Sync generated RCON & management secrets into server.properties
$propsDest = Join-Path $ServerRoot 'server.properties'
if (Test-Path $propsDest) {
  $rconSecret = (Get-Content -Path $rconFile -Raw).Trim()
  $mgmtSecret = New-SecretString 40 $alnum
  $propsText = Get-Content -Path $propsDest -Raw
  $changed = $false
  if ($propsText -match 'rcon\.password=CHANGE-ME[^\r\n]*') {
    $propsText = [regex]::Replace($propsText, 'rcon\.password=CHANGE-ME[^\r\n]*', { param($m) "rcon.password=$rconSecret" })
    $changed = $true
  }
  if ($propsText -match 'management-server-secret=CHANGE-ME[^\r\n]*') {
    $propsText = [regex]::Replace($propsText, 'management-server-secret=CHANGE-ME[^\r\n]*', { param($m) "management-server-secret=$mgmtSecret" })
    $changed = $true
  }
  if ($changed) {
    [System.IO.File]::WriteAllText($propsDest, $propsText, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Synced generated secrets into $propsDest"
  }
}

# 6. Accept Minecraft EULA if still false
$eulaPath = Join-Path $ServerRoot 'eula.txt'
$eulaAccepted = (Test-Path $eulaPath) -and ((Get-Content -Path $eulaPath -Raw) -match '(?m)^eula\s*=\s*true\s*$')
if (-not $eulaAccepted) {
  if (-not $AcceptEula) {
    $ans = Read-Host "Do you accept the Minecraft EULA (https://aka.ms/MinecraftEULA)? Type 'yes' to accept"
    if ($ans -ne 'yes') { throw "Minecraft EULA was not accepted. Re-run with -AcceptEula once ready." }
  }
  [System.IO.File]::WriteAllText($eulaPath, "# Accepted via bootstrap-server.ps1 (https://aka.ms/MinecraftEULA)`r`neula=true`r`n", (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Accepted EULA in $eulaPath (eula=true)"
}

# 7. Protect cloned Git working tree against accidentally committing live local secrets
if ((Test-Path -LiteralPath (Join-Path $ServerRoot '.git')) -and (Get-Command git -ErrorAction SilentlyContinue)) {
  $secretFiles = @(
    'admin/mcserver-password.txt', 'admin/rcon-secret.txt', 'admin/invite-code.txt',
    'admin/rclone.conf', 'server.properties', 'eula.txt',
    'plugins/MYTownGatekeeper/config.yml', 'plugins/MYTownGatekeeper/accounts.yml',
    'plugins/playit-gg/config.yml', 'scripts/ram-mode.json'
  )
  foreach ($sf in $secretFiles) {
    if (Test-Path -LiteralPath (Join-Path $ServerRoot $sf)) {
      & git -C $ServerRoot update-index --skip-worktree -- $sf 2>$null
    }
  }
  Write-Host "Marked local secret/config files with git --skip-worktree."
}

Write-Host ""
Write-Host "Bootstrap complete! Next step (in an Administrator PowerShell):"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\harden-environment.ps1`""
