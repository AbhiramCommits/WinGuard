<#
.SYNOPSIS
    Stops and removes the WinGuard agent Windows Service.

.DESCRIPTION
    Stops the service, deletes it with sc.exe and (optionally) removes the
    spool directory. Run from an elevated PowerShell prompt; removing a service
    requires administrative rights.

.PARAMETER ServiceName
    Service name. Defaults to WinGuardAgent.

.PARAMETER InstallPath
    Directory the agent was installed to. When supplied, the spool directory is
    removed as well. Defaults to the folder this script lives in.

.PARAMETER KeepData
    Keep the spool directory (unsent detection batches) instead of deleting it.
#>
[CmdletBinding()]
param(
    [string]$ServiceName = "WinGuardAgent",
    [string]$InstallPath = "",
    [switch]$KeepData
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell prompt."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") {
        Write-Host "==> Stopping $ServiceName"
        sc.exe stop $ServiceName | Out-Null
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }

    Write-Host "==> Deleting $ServiceName"
    sc.exe delete $ServiceName | Out-Null
} else {
    Write-Host "Service '$ServiceName' is not installed."
}

if (-not $KeepData) {
    if ([string]::IsNullOrWhiteSpace($InstallPath)) {
        $InstallPath = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    }

    $spoolDir = Join-Path $InstallPath "data/spool"
    if (Test-Path $spoolDir) {
        Write-Host "==> Removing the spool directory $spoolDir"
        Remove-Item -Recurse -Force $spoolDir
    }
} else {
    Write-Host "Keeping the spool directory (unsent events preserved)."
}

Write-Host "Uninstalled."
