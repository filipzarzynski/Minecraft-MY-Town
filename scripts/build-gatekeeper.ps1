param(
  [string]$ServerRoot = (Split-Path -Parent $PSScriptRoot)
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
  throw "JDK 25 (javac.exe) not found."
}

$jdkBin = Resolve-JdkBin
$javac = Join-Path $jdkBin 'javac.exe'
$jarExe = Join-Path $jdkBin 'jar.exe'
$srcRoot = Join-Path $ServerRoot 'src\MYTownGatekeeper'
$javaDir = Join-Path $srcRoot 'src\main\java'
$resDir = Join-Path $srcRoot 'src\main\resources'
$librariesDir = Join-Path $ServerRoot 'libraries'
$libCache = Join-Path $ServerRoot '.build-libs'
$outClasses = Join-Path $srcRoot 'build\classes'
$outJar = Join-Path $ServerRoot 'plugins\MYTownGatekeeper.jar'

$cpJars = [System.Collections.Generic.List[string]]::new()
$seenNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

if (Test-Path $librariesDir) {
  Get-ChildItem -Path $librariesDir -Recurse -Filter '*.jar' | ForEach-Object {
    if ($seenNames.Add($_.Name)) { $cpJars.Add($_.FullName) }
  }
}
if (Test-Path $libCache) {
  Get-ChildItem -Path $libCache -Recurse -Filter '*.jar' | ForEach-Object {
    if ($seenNames.Add($_.Name)) { $cpJars.Add($_.FullName) }
  }
}

if ($cpJars.Count -eq 0) {
  throw "No API dependency jars found in '$librariesDir'. Run bootstrap-server.ps1 or java -Dpaperclip.patchonly=true -jar purpur-*.jar first."
}

$cp = $cpJars -join ';'
if (Test-Path $outClasses) { Remove-Item -Recurse -Force $outClasses }
New-Item -ItemType Directory -Force -Path $outClasses | Out-Null

$javaFiles = Get-ChildItem -Path $javaDir -Recurse -Filter '*.java' | ForEach-Object { $_.FullName }
if (-not $javaFiles) { throw "No Java sources found in $javaDir" }

& $javac --release 25 -encoding UTF-8 '-Xlint:all,-classfile' -cp $cp -d $outClasses $javaFiles
if ($LASTEXITCODE -ne 0) {
  throw "javac failed with exit code $LASTEXITCODE"
}

Copy-Item -Path (Join-Path $resDir '*') -Destination $outClasses -Recurse -Force

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $outJar) | Out-Null
& $jarExe --create --file $outJar -C $outClasses .
if ($LASTEXITCODE -ne 0) {
  throw "jar packaging failed with exit code $LASTEXITCODE"
}

Remove-Item -Recurse -Force (Join-Path $srcRoot 'build') -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $libCache -ErrorAction SilentlyContinue

Write-Host "Built $outJar successfully."
