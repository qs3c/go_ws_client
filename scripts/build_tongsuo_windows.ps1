# Build Tongsuo on Windows (MSVC + nmake)
# Run this from a Developer Command Prompt for Visual Studio.
param(
  [string]$SourceDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "third_party\tongsuo"),
  [string]$BuildDir = (Join-Path (Split-Path -Parent $PSScriptRoot) "third_party\tongsuo-build"),
  [string]$Prefix = $env:TONGSUO_PREFIX,
  [string]$ConfigOpts = $env:TONGSUO_CONFIG_OPTS,
  [string]$InstallTargets = $env:TONGSUO_INSTALL_TARGETS
)

if ([string]::IsNullOrWhiteSpace($Prefix)) { $Prefix = $SourceDir }
if ([string]::IsNullOrWhiteSpace($ConfigOpts)) { $ConfigOpts = "enable-ntls" }
if ([string]::IsNullOrWhiteSpace($InstallTargets)) { $InstallTargets = "install" }

if (-not (Test-Path -LiteralPath $SourceDir)) {
  Write-Error "Tongsuo source not found at $SourceDir. Run: git submodule update --init --recursive"
  exit 1
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