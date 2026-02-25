# Sets runtime env vars for the vendored Tongsuo copy under third_party/tongsuo
$defaultRepoRoot = Split-Path -Parent $PSScriptRoot
$cwd = (Get-Location).Path
if (Test-Path -LiteralPath (Join-Path $cwd "third_party\tongsuo-install")) {
  $repoRoot = $cwd
} else {
  $repoRoot = $defaultRepoRoot
}
$tongsuoHome = Join-Path $repoRoot "third_party\tongsuo-install"

if (-not (Test-Path -LiteralPath $tongsuoHome)) {
  Write-Error "Tongsuo not found at $tongsuoHome. Build or copy your Tongsuo tree there first."
  exit 1
}

$env:TONGSUO_HOME = $tongsuoHome

# Make sure DLLs are found at runtime (prefer bin if present)
$dllDir = if (Test-Path -LiteralPath (Join-Path $env:TONGSUO_HOME 'bin')) { Join-Path $env:TONGSUO_HOME 'bin' } else { $env:TONGSUO_HOME }
$env:PATH = "$dllDir;$env:PATH"

Write-Host "TONGSUO_HOME set to $env:TONGSUO_HOME"