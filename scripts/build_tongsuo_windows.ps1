# Build Tongsuo on Windows (MSVC + nmake)
# If not running in a VS Developer Command Prompt, this script will try to
# locate VsDevCmd.bat and re-run itself inside it.
[CmdletBinding()]
param(
  [string]$SourceDir,
  [string]$BuildDir,
  [string]$Prefix = $env:TONGSUO_PREFIX,
  [string]$ConfigOpts = $env:TONGSUO_CONFIG_OPTS,
  [string]$InstallTargets = $env:TONGSUO_INSTALL_TARGETS,
  [switch]$NoBootstrap
)

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
  if ($MyInvocation.MyCommand.Path) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
  } else {
    $scriptDir = (Get-Location).Path
  }
}

if ([string]::IsNullOrWhiteSpace($SourceDir)) {
  $SourceDir = Join-Path $scriptDir "third_party\tongsuo"
}
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
  $BuildDir = Join-Path $scriptDir "third_party\tongsuo-build"
}

function Test-DevEnv {
  $hasNmake = Get-Command nmake -ErrorAction SilentlyContinue
  $hasCl = Get-Command cl -ErrorAction SilentlyContinue
  return ($hasNmake -and $hasCl)
}

function Find-VsDevCmd {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path -LiteralPath $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not [string]::IsNullOrWhiteSpace($vsPath)) {
      $candidate = Join-Path $vsPath "Common7\Tools\VsDevCmd.bat"
      if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
  }

  $candidates = @(
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\Common7\\Tools\\VsDevCmd.bat",
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\Tools\\VsDevCmd.bat",
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\Common7\\Tools\\VsDevCmd.bat",
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\Common7\\Tools\\VsDevCmd.bat",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\BuildTools\\Common7\\Tools\\VsDevCmd.bat",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\Common7\\Tools\\VsDevCmd.bat",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\Common7\\Tools\\VsDevCmd.bat",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\Common7\\Tools\\VsDevCmd.bat"
  )

  foreach ($c in $candidates) {
    if (Test-Path -LiteralPath $c) { return $c }
  }

  return $null
}

function Get-PowerShellPath {
  try {
    $p = (Get-Process -Id $PID).Path
    if ($p) { return $p }
  } catch {}
  $cmd = Get-Command pwsh -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $cmd = Get-Command powershell -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return "powershell.exe"
}

function Invoke-InDevCmd {
  param([string]$VsDevCmdPath)

  $psExe = Get-PowerShellPath
  $args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$PSCommandPath`"",
    "-SourceDir", "`"$SourceDir`"",
    "-BuildDir", "`"$BuildDir`"",
    "-Prefix", "`"$Prefix`"",
    "-ConfigOpts", "`"$ConfigOpts`"",
    "-InstallTargets", "`"$InstallTargets`"",
    "-NoBootstrap"
  )
  $argString = $args -join ' '
  $cmd = "`"$VsDevCmdPath`" -arch=amd64 -host_arch=amd64 && `"$psExe`" $argString"

  cmd /c $cmd
  exit $LASTEXITCODE
}

if ([string]::IsNullOrWhiteSpace($Prefix)) { $Prefix = $SourceDir }
if ([string]::IsNullOrWhiteSpace($ConfigOpts)) { $ConfigOpts = "enable-ntls" }
if ([string]::IsNullOrWhiteSpace($InstallTargets)) { $InstallTargets = "install" }

if (-not (Test-Path -LiteralPath $SourceDir)) {
  Write-Error "Tongsuo source not found at $SourceDir. Run: git submodule update --init --recursive"
  exit 1
}

if (-not $NoBootstrap -and -not (Test-DevEnv)) {
  $vsDevCmd = Find-VsDevCmd
  if (-not $vsDevCmd) {
    Write-Error "MSVC build tools not found. Open a Developer Command Prompt for Visual Studio and retry."
    exit 1
  }
  Invoke-InDevCmd -VsDevCmdPath $vsDevCmd
}

if (-not (Get-Command perl -ErrorAction SilentlyContinue)) {
  Write-Error "perl not found. Install Perl 5 (with Text::Template) and retry."
  exit 1
}
if (-not (Get-Command nmake -ErrorAction SilentlyContinue)) {
  Write-Error "nmake not found. Open a Developer Command Prompt for Visual Studio and retry."
  exit 1
}

if (-not (Test-Path -LiteralPath $BuildDir)) {
  New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

Push-Location $BuildDir
try {
  $cfgArgs = @()
  $cfgArgs += ($ConfigOpts -split '\s+' | Where-Object { $_ -ne "" })
  $cfgArgs += "--prefix=$Prefix"

  & perl (Join-Path $SourceDir "Configure") @cfgArgs
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  & nmake
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  foreach ($t in ($InstallTargets -split '\s+')) {
    & nmake $t
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  }
}
finally {
  Pop-Location
}

Write-Host "Build complete. Install prefix: $Prefix"