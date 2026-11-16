param(
  [string]$ServerRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$RemoteTarget = 'gdrive:MY-Town-Backups',
  [int]$MaxLocalBackups = 2,
  [int]$RemoteRetentionDays = 14
)

$ErrorActionPreference = 'Stop'

$mcCmd = Join-Path $ServerRoot 'scripts\mc-cmd.ps1'
$rcloneConfig = Join-Path $ServerRoot 'admin\rclone.conf'
$backupDir = Join-Path $ServerRoot 'backups'
$logFile = Join-Path $ServerRoot 'admin\backup.log'

New-Item -ItemType Directory -Force -Path $backupDir, (Split-Path -Parent $logFile) | Out-Null

function Write-BackupLog([string]$Message) {
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[$ts] $Message"
  Add-Content -Path $logFile -Value $line
  Write-Host $line
}

function Resolve-RclonePath {
  $cmd = Get-Command rclone -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $wingetLink = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\rclone.exe'
  if (Test-Path $wingetLink) { return $wingetLink }
  $pkgExe = Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages') -Filter 'rclone.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
  if ($pkgExe) { return $pkgExe }
  throw "rclone.exe not found. Install Rclone.Rclone first."
}

$rcloneExe = Resolve-RclonePath
if (-not (Test-Path $rcloneConfig)) {
  throw "Missing rclone config at $rcloneConfig. Run: rclone config create gdrive drive scope drive.file --config `"$rcloneConfig`""
}
if ((Get-Content -Path $rcloneConfig -Raw) -match 'CHANGE-ME') {
  throw "$rcloneConfig still contains placeholder OAuth tokens. Run: rclone config create gdrive drive scope drive.file --config `"$rcloneConfig`""
}

$stamp = (Get-Date).ToString('yyyy-MM-dd_HHmm')
$stagingDir = Join-Path $backupDir "_staging_$stamp"
$zipPath = Join-Path $backupDir "MY-Town-$stamp.zip"

$serverRunning = $false
try {
  $tcp = New-Object System.Net.Sockets.TcpClient
  $iar = $tcp.BeginConnect('127.0.0.1', 25575, $null, $null)
  if ($iar.AsyncWaitHandle.WaitOne(1000, $false)) {
    $tcp.EndConnect($iar)
    $serverRunning = $true
  }
  $tcp.Dispose()
} catch {
  $serverRunning = $false
}

Write-BackupLog "Starting backup $stamp (ServerOnline=$serverRunning)"
New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null

try {
  if ($serverRunning) {
    & $mcCmd -Command 'save-off' | Out-Null
    & $mcCmd -Command 'save-all flush' | Out-Null
    Start-Sleep -Seconds 2
  }

  $foldersToCopy = @('world', 'world_nether', 'world_the_end', 'config')
  foreach ($folder in $foldersToCopy) {
    $src = Join-Path $ServerRoot $folder
    if (Test-Path $src) {
      $dst = Join-Path $stagingDir $folder
      & robocopy $src $dst /E /R:1 /W:1 /XF session.lock /NFL /NDL /NJH /NJS /NC /NS | Out-Null
      if ($LASTEXITCODE -ge 8) {
        throw "robocopy failed for $folder with exit code $LASTEXITCODE"
      }
    }
  }

  $filesToCopy = @(
    'server.properties',
    'purpur.yml',
    'bukkit.yml',
    'spigot.yml',
    'plugins\MYTownGatekeeper\accounts.yml',
    'plugins\MYTownGatekeeper\config.yml',
    'plugins\playit-gg\config.yml'
  )
  foreach ($rel in $filesToCopy) {
    $src = Join-Path $ServerRoot $rel
    if (Test-Path $src) {
      $dst = Join-Path $stagingDir $rel
      New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
      Copy-Item -Path $src -Destination $dst -Force
    }
  }
} finally {
  if ($serverRunning) {
    try {
      & $mcCmd -Command 'save-on' | Out-Null
    } catch {
      Write-BackupLog "WARNING: Failed to re-enable saving via RCON: $_"
    }
  }
}

Write-BackupLog "Compressing staging directory to $zipPath"
Add-Type -AssemblyName System.IO.Compression.FileSystem
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($stagingDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
Remove-Item -Recurse -Force $stagingDir

$sizeMB = [Math]::Round((Get-Item $zipPath).Length / 1MB, 2)
Write-BackupLog "Archive created: $zipPath ($sizeMB MB). Uploading to $RemoteTarget..."

& $rcloneExe copy $zipPath $RemoteTarget --config $rcloneConfig --stats-one-line
if ($LASTEXITCODE -ne 0) {
  throw "rclone upload failed with exit code $LASTEXITCODE. Local archive kept at $zipPath."
}
Write-BackupLog "Uploaded $zipPath to $RemoteTarget successfully."

& $rcloneExe delete $RemoteTarget --min-age "${RemoteRetentionDays}d" --config $rcloneConfig
if ($LASTEXITCODE -ne 0) {
  Write-BackupLog "WARNING: rclone remote pruning exited with code $LASTEXITCODE"
}

$localZips = Get-ChildItem -Path $backupDir -Filter 'MY-Town-*.zip' | Sort-Object LastWriteTime -Descending
if ($localZips.Count -gt $MaxLocalBackups) {
  $localZips | Select-Object -Skip $MaxLocalBackups | ForEach-Object {
    Remove-Item $_.FullName -Force
    Write-BackupLog "Pruned old local backup: $($_.Name)"
  }
}

Write-BackupLog "Backup job completed."
