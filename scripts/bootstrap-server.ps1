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
  throw "JDK 25 (javac.exe) not found. Install Amazon Corretto 25 or extract it under '$ServerRoot\Corretto\'."
}

function New-SecretString([int]$Length, [string]$Charset) {
  $bytes = New-Object byte[] $Length
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $sb = New-Object System.Text.StringBuilder
  for ($i = 0; $i -lt $Length; $i++) {
    [void]$sb.Append($Charset[$bytes[$i] % $Charset.Length])
  }
  return $sb.ToString()
}

foreach ($d in @('admin', 'backups', 'logs', 'plugins', 'scripts')) {
  New-Item -ItemType Directory -Force -Path (Join-Path $ServerRoot $d) | Out-Null
}

# 1. Generate local secrets if absent
$alnum = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
$complex = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#_-+=?'

$mcPassFile = Join-Path $ServerRoot 'admin\mcserver-password.txt'
$rconFile = Join-Path $ServerRoot 'admin\rcon-secret.txt'
$inviteFile = Join-Path $ServerRoot 'admin\invite-code.txt'

if (-not (Test-Path $mcPassFile)) {
  $mcPass = 'Mc!' + (New-SecretString 29 $complex) + '9A'
  [System.IO.File]::WriteAllText($mcPassFile, $mcPass, (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Generated $ServiceUser service password at $mcPassFile"
}
if (-not (Test-Path $rconFile)) {
  $rconPass = New-SecretString 32 $alnum
  [System.IO.File]::WriteAllText($rconFile, $rconPass, (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Generated RCON password at $rconFile"
}
if (-not (Test-Path $inviteFile)) {
  $code = if ($InviteCode) { $InviteCode.Trim() } else { 'MYTOWN-' + (New-SecretString 12 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789') }
  [System.IO.File]::WriteAllText($inviteFile, $code, (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Generated initial server invite code at $inviteFile"
}

# 2. Download third-party jars from official APIs if requested
if ($DownloadDeps) {
  Write-Host "Downloading Purpur 26.3 and plugins from official APIs..."
  $purpurInfo = Invoke-RestMethod 'https://api.purpurmc.org/v2/purpur/26.3'
  $build = $purpurInfo.builds.latest
  $purpurJarPath = Join-Path $ServerRoot "purpur-26.3-$build.jar"
  if (-not (Test-Path $purpurJarPath)) {
    Invoke-WebRequest -Uri "https://api.purpurmc.org/v2/purpur/26.3/$build/download" -OutFile $purpurJarPath
    Write-Host "Downloaded $purpurJarPath"
  }

  $playitRel = Invoke-RestMethod 'https://api.github.com/repos/playit-cloud/playit-minecraft-plugin/releases/latest'
  $playitAsset = $playitRel.assets | Where-Object { $_.name -like '*.jar' } | Select-Object -First 1
  if ($playitAsset) {
    $playitOut = Join-Path $ServerRoot "plugins\$($playitAsset.name)"
    Invoke-WebRequest -Uri $playitAsset.browser_download_url -OutFile $playitOut
    Write-Host "Downloaded $playitOut"
  }

  foreach ($slug in @('chunky', 'purpurextras')) {
    $vers = Invoke-RestMethod "https://api.modrinth.com/v2/project/$slug/version?loaders=%5B%22paper%22%5D"
    $v = $vers | Select-Object -First 1
    $f = $v.files | Select-Object -First 1
    $outFile = Join-Path $ServerRoot "plugins\$($f.filename)"
    Invoke-WebRequest -Uri $f.url -OutFile $outFile
    $actual = (Get-FileHash -Path $outFile -Algorithm SHA512).Hash.ToLowerInvariant()
    if ($actual -ne $f.hashes.sha512.ToLowerInvariant()) {
      throw "SHA-512 verification failed for $($f.filename)"
    }
    Write-Host "Downloaded & SHA-512 verified: $outFile"
  }
}

# 3. Unpack Purpur server libraries via Paperclip patchonly
$purpurJar = Get-ChildItem -Path $ServerRoot -Filter 'purpur-*.jar' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $purpurJar) {
  throw "No purpur-*.jar found in $ServerRoot. Place Purpur 26.3 jar there or pass -DownloadDeps."
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

# 4. Compile MYTownGatekeeper plugin and write its config.yml
& (Join-Path $PSScriptRoot 'build-gatekeeper.ps1') -ServerRoot $ServerRoot

$inviteVal = (Get-Content -Path $inviteFile -Raw).Trim()
$gkDir = Join-Path $ServerRoot 'plugins\MYTownGatekeeper'
New-Item -ItemType Directory -Force -Path $gkDir | Out-Null
$gkConfig = Join-Path $gkDir 'config.yml'
if (-not (Test-Path $gkConfig)) {
  $cfgText = @"
# MYTownGatekeeper configuration
invite-code: "$inviteVal"
session-ttl-hours: 24
auth-timeout-seconds: 90
min-password-length: 6
max-password-length: 128
max-failed-attempts: 5
lockout-minutes: 15
"@
  [System.IO.File]::WriteAllText($gkConfig, $cfgText, (New-Object System.Text.UTF8Encoding $false))
}

# 5. Write server.properties and eula.txt if not already present
$propsDest = Join-Path $ServerRoot 'server.properties'
if (-not (Test-Path $propsDest)) {
  $template = Get-Content -Path (Join-Path $ServerRoot 'config-templates\server.properties.example') -Raw
  $rconSecret = (Get-Content -Path $rconFile -Raw).Trim()
  $rendered = $template.Replace('__RCON_PASSWORD__', $rconSecret)
  [System.IO.File]::WriteAllText($propsDest, $rendered, (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Created $propsDest"
}

$eulaPath = Join-Path $ServerRoot 'eula.txt'
if (-not (Test-Path $eulaPath)) {
  if (-not $AcceptEula) {
    $ans = Read-Host "Do you accept the Minecraft EULA (https://aka.ms/MinecraftEULA)? Type 'yes' to accept"
    if ($ans -ne 'yes') { throw "Minecraft EULA was not accepted. Re-run with -AcceptEula once ready." }
  }
  [System.IO.File]::WriteAllText($eulaPath, "eula=true`r`n", (New-Object System.Text.UTF8Encoding $false))
  Write-Host "Created $eulaPath (eula=true)"
}

Write-Host ""
Write-Host "Bootstrap complete! Next step (in an Administrator PowerShell):"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\harden-environment.ps1`""
