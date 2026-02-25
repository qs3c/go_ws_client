# Build Tongsuo on Windows (MSVC + nmake)
# If not running in a VS Developer Command Prompt, this script will try to
# locate VsDevCmd.bat and re-run itself inside it.
[CmdletBinding()]
param(
  [string]$ProjectRoot,
  [string]$SourceDir,
  [string]$BuildDir,
  [string]$Prefix = $env:TONGSUO_PREFIX,
  [string]$ConfigOpts = $env:TONGSUO_CONFIG_OPTS,
  [string]$InstallTargets = $env:TONGSUO_INSTALL_TARGETS,
  [string]$Target = $env:TONGSUO_TARGET,
  [string]$OpenSSLDir = $env:TONGSUO_OPENSSLDIR,
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
$defaultRepoRoot = Split-Path -Parent $scriptDir
if ([string]::IsNullOrWhiteSpace($defaultRepoRoot)) { $defaultRepoRoot = $scriptDir }

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
  $cwd = (Get-Location).Path
  if (Test-Path -LiteralPath (Join-Path $cwd "crypto\sm2keyexch")) {
    $ProjectRoot = $cwd
  } else {
    $ProjectRoot = $defaultRepoRoot
  }
}
$repoRoot = $ProjectRoot

if ([string]::IsNullOrWhiteSpace($SourceDir)) {
  $SourceDir = Join-Path $repoRoot "third_party\tongsuo"
}
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
  $BuildDir = Join-Path $repoRoot "third_party\tongsuo-build"
}
if ([string]::IsNullOrWhiteSpace($Prefix)) {
  $Prefix = Join-Path $repoRoot "third_party\tongsuo-install"
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
    "-ProjectRoot", "`"$ProjectRoot`"",
    "-SourceDir", "`"$SourceDir`"",
    "-BuildDir", "`"$BuildDir`"",
    "-Prefix", "`"$Prefix`"",
    "-ConfigOpts", "`"$ConfigOpts`"",
    "-InstallTargets", "`"$InstallTargets`"",
    "-Target", "`"$Target`"",
    "-OpenSSLDir", "`"$OpenSSLDir`"",
    "-NoBootstrap"
  )
  $argString = $args -join ' '
  $cmd = "`"$VsDevCmdPath`" -arch=amd64 -host_arch=amd64 && `"$psExe`" $argString"

  cmd /c $cmd
  exit $LASTEXITCODE
}

if ([string]::IsNullOrWhiteSpace($ConfigOpts)) { $ConfigOpts = "enable-ntls" }
if ([string]::IsNullOrWhiteSpace($InstallTargets)) { $InstallTargets = "install" }
if ([string]::IsNullOrWhiteSpace($Target)) { $Target = "VC-WIN64A" }
if ([string]::IsNullOrWhiteSpace($OpenSSLDir)) { $OpenSSLDir = (Join-Path $Prefix "ssl") }

if (-not (Test-Path -LiteralPath $SourceDir)) {
  Write-Error "Tongsuo source not found at $SourceDir. Run: git submodule update --init --recursive"
  exit 1
}

$srcFull = [System.IO.Path]::GetFullPath($SourceDir)
$prefixFull = [System.IO.Path]::GetFullPath($Prefix)
if ($srcFull -ieq $prefixFull) {
  Write-Error "Refusing to install into source directory. Set TONGSUO_PREFIX to a separate install path."
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
  $cfgTokens = ($ConfigOpts -split '\s+' | Where-Object { $_ -ne "" })
  $hasTarget = $false
  $hasOpenSSLDir = $false
  foreach ($t in $cfgTokens) {
    if ($t -match '^(VC-|mingw|mingw64)$') { $hasTarget = $true }
    if ($t -match '^--openssldir=') { $hasOpenSSLDir = $true }
  }
  if (-not $hasTarget) { $cfgArgs += $Target }
  $cfgArgs += $cfgTokens
  if (-not $hasOpenSSLDir) { $cfgArgs += "--openssldir=$OpenSSLDir" }
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

Write-Host "Building sm2keyexch..."
$keyExDir = Join-Path $repoRoot "crypto\sm2keyexch"
Push-Location $keyExDir
try {
  $inc1 = Join-Path $Prefix "include"
  $inc2 = Join-Path $SourceDir "include"
  
  & cl /c /O2 /nologo /DOPENSSL_API_COMPAT=0x10100000L /I"$inc1" /I"$inc2" keyexchange.c
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  
  & lib /nologo /out:keyexchange.lib keyexchange.obj
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  
    Write-Host "Built $(Join-Path $keyExDir 'keyexchange.lib')"
  
  }
  
  finally {
  
    Pop-Location
  
  }
  
  
  
  Write-Host "Build complete. Install prefix: $Prefix"
  
  
  
  # Automatically trigger environment setup for the current session
  
  $envScript = Join-Path $scriptDir "set_tongsuo_env.ps1"
  
  if (Test-Path $envScript) {
  
      Write-Host "Automatically setting up runtime environment..." -ForegroundColor Cyan
  
      & $envScript
  
  }
  
  