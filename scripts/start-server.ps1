param(
  [string]$ServerRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

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

function Assert-NotReparsePoint([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw "SECURITY ABORT: ReparsePoint detected at $Path"
  }
}

$ramConfigFile = Join-Path $ServerRoot 'scripts\ram-mode.json'
$logFile = Join-Path $ServerRoot 'logs\wrapper.log'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $logFile) | Out-Null

function Write-WrapperLog([string]$Message) {
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  Add-Content -Path $logFile -Value "[$ts] $Message"
}

try {
  Assert-NotReparsePoint $ServerRoot
  Assert-NotReparsePoint $ramConfigFile

  $javaExe = Resolve-JavaExe
  Assert-NotReparsePoint $javaExe

  $cfg = Get-Content -Path $ramConfigFile -Raw | ConvertFrom-Json
  if (-not [string]::IsNullOrWhiteSpace($cfg.ServerJar)) {
    $jarName = [System.IO.Path]::GetFileName([string]$cfg.ServerJar)
    $purpurJarPath = Join-Path $ServerRoot $jarName
    if (-not (Test-Path -LiteralPath $purpurJarPath)) { throw "Pinned ServerJar not found: $purpurJarPath" }
    $purpurJar = Get-Item -LiteralPath $purpurJarPath
  } else {
    $candidates = @(Get-ChildItem -Path $ServerRoot -Filter 'purpur-*.jar' -File)
    if ($candidates.Count -ne 1) {
      throw "ServerJar is not pinned in ram-mode.json and found $($candidates.Count) purpur-*.jar files. Run bootstrap-server.ps1 or set ServerJar."
    }
    $purpurJar = $candidates[0]
  }
  Assert-NotReparsePoint $purpurJar.FullName

  $mode = $cfg.Mode
  $memFlags = switch ($mode) {
    'Prealloc' { $cfg.PreallocFlags }
    'Dynamic'  { $cfg.DynamicFlags }
    default    { throw "Unknown RAM Mode '$mode' in $ramConfigFile" }
  }

  $activeProcs = if ($cfg.ActiveProcessorCount) { [int]$cfg.ActiveProcessorCount } else { 3 }
  $affinityMask = if ($cfg.AffinityMask) { [long]$cfg.AffinityMask } else { 56 }
  $priorityName = if ($cfg.PriorityClass) { [string]$cfg.PriorityClass } else { 'BelowNormal' }

  $jvmArgs = @(
    "-XX:ActiveProcessorCount=$activeProcs",
    '-XX:+PerfDisableSharedMem'
  ) + ($memFlags -split '\s+' | Where-Object { $_ }) + @(
    '-jar', $purpurJar.FullName,
    '--nogui'
  )

  Write-WrapperLog "Starting $($purpurJar.Name) (Mode=$mode, Cores=$activeProcs, Affinity=$affinityMask, Priority=$priorityName)"

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $javaExe
  $psi.WorkingDirectory = $ServerRoot
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true
  $psi.Arguments = ($jvmArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '

  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  [void]$proc.Start()

  try {
    $proc.ProcessorAffinity = [IntPtr]$affinityMask
    $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::$priorityName
    Write-WrapperLog "Started java.exe PID=$($proc.Id) with Affinity=$($proc.ProcessorAffinity) Priority=$($proc.PriorityClass)"
  } catch {
    Write-WrapperLog "WARNING: Failed to set affinity/priority on PID=$($proc.Id): $_"
  }

  $proc.WaitForExit()
  Write-WrapperLog "Server exited with code $($proc.ExitCode)"
  exit $proc.ExitCode
} catch {
  Write-WrapperLog "FATAL: $_"
  throw
}
