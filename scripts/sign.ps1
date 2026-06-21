param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [string]$PfxPath = "",
    [string]$PfxPassword = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Sys = Join-Path $Root "bin\$Platform\$Configuration\Guardian.sys"

if (-not (Test-Path $Sys)) {
    & (Join-Path $PSScriptRoot "build.ps1") -Configuration $Configuration -Platform $Platform
}

if (-not $PfxPath) {
    Write-Warning "PfxPath not set — skipping Authenticode signing"
    exit 0
}

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signtool) {
    throw "signtool.exe not found"
}

& signtool sign /fd SHA256 /f $PfxPath /p $PfxPassword /tr http://timestamp.digicert.com /td SHA256 $Sys
Write-Host "Signed $Sys"
