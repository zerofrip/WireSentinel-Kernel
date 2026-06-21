param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Solution = Join-Path $Root "guardian\guardian.sln"

Write-Host "Building Guardian.sys ($Configuration|$Platform)..."
msbuild $Solution /p:Configuration=$Configuration /p:Platform=$Platform /m

Write-Host "Building usermode controller..."
Push-Location $Root
cargo build --workspace --release
Pop-Location

Write-Host "Done. Output: $Root\bin\$Platform\$Configuration\Guardian.sys"
