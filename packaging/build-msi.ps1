<#
.SYNOPSIS
    Builds the WinGuard agent MSI.

.DESCRIPTION
    1. publishes src/WinGuard.Agent for win-x64,
    2. copies native/winguard_native.dll into the publish output when it has been
       built (Windows CI builds it; see .github/workflows/ci.yml),
    3. harvests the published files with WiX `heat` into Files.wxs,
    4. compiles and links packaging/winguard-agent.wxs + Files.wxs into
       packaging/bin/WinGuardAgent-<version>.msi.

    Requires the .NET 8 SDK and the WiX Toolset v3 (`candle`, `light`, `heat`) on
    PATH. Install it with:  choco install wixtoolset

.PARAMETER Configuration
    Build configuration to publish. Defaults to Release.

.PARAMETER Version
    Product version recorded in the MSI. Defaults to 1.0.0.
#>
[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$publishDir = Join-Path $root "packaging/publish"
$buildDir = Join-Path $root "packaging/bin"
$harvestFile = Join-Path $buildDir "Files.wxs"
$msiPath = Join-Path $buildDir "WinGuardAgent-$Version.msi"

foreach ($tool in @("candle", "light", "heat")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool was not found on PATH. Install the WiX Toolset v3 (choco install wixtoolset)."
    }
}

Write-Host "==> Publishing the agent ($Configuration, win-x64)"
if (Test-Path $publishDir) { Remove-Item -Recurse -Force $publishDir }
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

dotnet publish (Join-Path $root "src/WinGuard.Agent/WinGuard.Agent.csproj") `
    -c $Configuration -r win-x64 --self-contained false `
    -p:Version=$Version -o $publishDir | Out-Null

Write-Host "==> Copying the native collector (if built)"
$native = Get-ChildItem -Path (Join-Path $root "native/out") -Recurse -Filter winguard_native.dll -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($native) {
    Copy-Item $native.FullName $publishDir -Force
    Write-Host "    $($native.FullName) -> $publishDir"
} else {
    Write-Warning "winguard_native.dll not found under native/out; the MSI will not include the Win32/ETW collector."
}

New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

Write-Host "==> Harvesting published files (heat)"
# The agent executable is declared by hand in winguard-agent.wxs (it hosts the
# service), so it is excluded from the harvest to avoid two components owning it.
heat dir $publishDir `
    -cg HarvestedAgentFiles `
    -gg -g1 -srd -sfrag -sreg -scom `
    -dr AgentFolder `
    -var var.PublishDir `
    -x "WinGuard.Agent.exe" `
    -out $harvestFile

Write-Host "==> Compiling (candle)"
candle -nologo `
    -arch x64 `
    -ext WixUtilExtension `
    -dPublishDir="$publishDir" `
    -dVersion="$Version" `
    -out (Join-Path $buildDir "winguard-agent.wixobj") `
    (Join-Path $root "packaging/winguard-agent.wxs")
candle -nologo -arch x64 -dPublishDir="$publishDir" -out (Join-Path $buildDir "Files.wixobj") $harvestFile

Write-Host "==> Linking (light)"
light -nologo `
    -ext WixUtilExtension `
    -sice:ICE61 `
    -out $msiPath `
    (Join-Path $buildDir "winguard-agent.wixobj") `
    (Join-Path $buildDir "Files.wixobj")

Write-Host ""
Write-Host "Built $msiPath"
Write-Host ""
Write-Host "Install:   msiexec /i `"$msiPath`" /qn"
Write-Host "Uninstall: msiexec /x `"$msiPath`" /qn"
