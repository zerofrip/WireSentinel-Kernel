param(
    [switch]$SkipDriverTests
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

if (-not $SkipDriverTests) {
    Write-Host "Running driver integration tests (requires Guardian.sys loaded)..."
}

Push-Location $Root
cargo test --workspace -- --nocapture
$code = $LASTEXITCODE
Pop-Location

if ($code -ne 0) {
    exit $code
}

Write-Host "All tests passed."
exit 0
