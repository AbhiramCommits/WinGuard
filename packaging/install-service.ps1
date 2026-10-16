<#
.SYNOPSIS
    Installs the WinGuard agent as a Windows Service with least privilege.

.DESCRIPTION
    Use this when you are deploying from a plain folder rather than the MSI
    (packaging/build-msi.ps1). It:

      * creates the service with sc.exe,
      * runs it as **NT AUTHORITY\LocalService** (no administrative rights),
      * grants LocalService write access only to the spool directory,
      * configures automatic restart on failure.

    Must be run from an elevated PowerShell prompt (creating a service requires
    administrative rights; running the service itself does not).

.PARAMETER InstallPath
    Directory containing WinGuard.Agent.exe. Defaults to the folder this script
    lives in.

.PARAMETER ServiceName
    Service name. Defaults to WinGuardAgent.

.PARAMETER ConfigPath
    appsettings.json applied to the service. Defaults to the one next to the exe.
#>
[CmdletBinding()]
param(
    [string]$InstallPath = "",
    [string]$ServiceName = "WinGuardAgent",
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell prompt."
}

if ([string]::IsNullOrWhiteSpace($InstallPath)) {
    $InstallPath = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
}
$InstallPath = (Resolve-Path $InstallPath).Path

$exe = Join-Path $InstallPath "WinGuard.Agent.exe"
if (-not (Test-Path $exe)) {
    throw "WinGuard.Agent.exe not found in $InstallPath. Publish the agent first: dotnet publish src/WinGuard.Agent -c Release -o `"$InstallPath`""
}

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $InstallPath "appsettings.json"
}

$dataDir = Join-Path $InstallPath "data"
$spoolDir = Join-Path $dataDir "spool"
New-Item -ItemType Directory -Force -Path $spoolDir | Out-Null

Write-Host "==> Registering service '$ServiceName' (LocalService, automatic)"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "    service already exists; stopping and reconfiguring"
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    sc.exe config $ServiceName binPath= "`"$exe`"" obj= "NT AUTHORITY\LocalService" start= auto | Out-Null
} else {
    sc.exe create $ServiceName `
        binPath= "`"$exe`"" `
        obj= "NT AUTHORITY\LocalService" `
        start= auto `
        DisplayName= "WinGuard Endpoint Integrity Agent" | Out-Null
    sc.exe description $ServiceName "Collects process, module and code-signing telemetry and reports tamper indicators to the WinGuard API." | Out-Null
}

# Automatic recovery: restart twice, then back off.
sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/none | Out-Null

# Environment: point the service at its configuration if it is not the default.
sc.exe env $ServiceName set "DOTNET_ENVIRONMENT=Production" | Out-Null

Write-Host "==> Granting LocalService write access to $spoolDir only"
$acl = Get-Acl $spoolDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\LocalService", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule)
Set-Acl -Path $spoolDir -AclObject $acl

Write-Host "==> Starting the service"
sc.exe start $ServiceName

Write-Host ""
Write-Host "Installed. Status:"
Get-Service -Name $ServiceName | Format-Table -AutoSize
Write-Host "Configuration: $ConfigPath"
Write-Host "Least privilege: the service runs as NT AUTHORITY\LocalService with write access only to $spoolDir."
