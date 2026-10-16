<#
.SYNOPSIS
    WinGuard end-to-end run.

.DESCRIPTION
    1. starts the API on SQLite with a throwaway database,
    2. runs the agent against the committed replay corpus, pointed at the API,
    3. waits for ingest to settle,
    4. queries the same endpoints the dashboard uses and prints a summary.

.PARAMETER Corpus
    JSONL corpus to replay. Defaults to data/corpus/labeled.jsonl.

.PARAMETER Url
    Base URL for the API. Defaults to http://localhost:5199.
#>
[CmdletBinding()]
param(
    [string]$Corpus = "",
    [string]$Url = "http://localhost:5199"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

if ([string]::IsNullOrWhiteSpace($Corpus)) {
    $Corpus = Join-Path $root "data/corpus/labeled.jsonl"
}

if (-not (Test-Path $Corpus)) {
    throw "Corpus not found: $Corpus. Generate it with: dotnet run --project src/WinGuard.Eval -- gen-corpus"
}

$dbPath = Join-Path $root "data/e2e.db"
$spoolDir = Join-Path $root "data/spool"
$apiLog = Join-Path $root "data/e2e-api.log"

Write-Host "==> Preparing a clean SQLite database at $dbPath"
Remove-Item -Force "$dbPath", "$dbPath-shm", "$dbPath-wal" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $spoolDir -ErrorAction SilentlyContinue

Write-Host "==> Building (Release)"
dotnet build -c Release --nologo -v quiet | Out-Null

Write-Host "==> Starting the API at $Url"
$env:ASPNETCORE_ENVIRONMENT = "Production"
$env:ASPNETCORE_URLS = $Url
$env:Database__Provider = "Sqlite"
$env:Database__MigrateOnStartup = "true"
$env:ConnectionStrings__Sqlite = "Data Source=$dbPath"
$env:Security__Signing__Enabled = "true"
$env:Security__Signing__MasterSecret = "dev-only-master-secret-change-me"

$api = Start-Process -FilePath "dotnet" `
    -ArgumentList @("run", "-c", "Release", "--no-build", "--no-launch-profile", "--project", "src/WinGuard.Api") `
    -RedirectStandardOutput $apiLog -RedirectStandardError "$apiLog.err" -PassThru -NoNewWindow

try {
    Write-Host "==> Waiting for /healthz"
    $healthy = $false
    foreach ($attempt in 1..60) {
        try {
            $health = Invoke-RestMethod -Uri "$Url/healthz" -TimeoutSec 2
            $healthy = $true
            break
        } catch {
            if ($api.HasExited) { throw "API exited during startup; see $apiLog" }
            Start-Sleep -Seconds 1
        }
    }

    if (-not $healthy) { throw "API did not become healthy in time; see $apiLog" }
    Write-Host "    healthz OK"

    Write-Host "==> Running the agent against $Corpus"
    $env:Api__Enabled = "true"
    $env:Api__BaseUrl = $Url
    $env:Api__HeartbeatIntervalSeconds = "5"
    $env:Api__BatchSize = "50"
    $env:Api__SpoolDirectory = $spoolDir
    $env:Replay__CorpusPath = $Corpus
    $env:Replay__RatePerSecond = "0"

    dotnet run -c Release --no-build --project src/WinGuard.Agent | Out-Null

    Write-Host "==> Waiting for ingest to settle"
    $previous = -1
    foreach ($attempt in 1..60) {
        $detections = Invoke-RestMethod -Uri "$Url/api/v1/detections/recent?limit=1000"
        $count = @($detections).Count
        if ($count -eq $previous -and $count -ne 0) { break }
        $previous = $count
        Start-Sleep -Seconds 1
    }

    $hosts = Invoke-RestMethod -Uri "$Url/api/v1/hosts"
    $detections = Invoke-RestMethod -Uri "$Url/api/v1/detections/recent?limit=1000"

    Write-Host ""
    Write-Host "==> Dashboard endpoints"
    Write-Host ("    GET /healthz                   -> " + (Invoke-WebRequest -Uri "$Url/healthz").StatusCode)
    Write-Host ("    GET /index.html                -> " + (Invoke-WebRequest -Uri "$Url/").StatusCode)
    Write-Host ("    GET /api/v1/hosts              -> " + (Invoke-WebRequest -Uri "$Url/api/v1/hosts").StatusCode)
    Write-Host ("    GET /api/v1/detections/recent  -> " + (Invoke-WebRequest -Uri "$Url/api/v1/detections/recent").StatusCode)

    Write-Host ""
    Write-Host "==> Results"
    $statuses = $hosts | Group-Object status | ForEach-Object { "$($_.Name)=$($_.Count)" }
    $rules = $detections | Group-Object ruleId | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" }
    $highest = ($detections | Measure-Object -Property severity -Maximum).Maximum

    Write-Host ("  hosts                 : " + @($hosts).Count)
    Write-Host ("  host status           : " + ($statuses -join ", "))
    Write-Host ("  detections ingested   : " + @($detections).Count)
    Write-Host ("  highest severity      : " + [int]$highest)
    Write-Host ("  detections per rule   : " + ($rules -join ", "))

    if (@($detections).Count -eq 0) { throw "FAILED: no detections were ingested" }
    if (@($hosts).Count -eq 0) { throw "FAILED: no hosts registered" }

    Write-Host ""
    Write-Host "  Dashboard: $Url/  (open in a browser while the API is running)"
    Write-Host ""
    Write-Host "End-to-end run complete."
}
finally {
    if ($api -and -not $api.HasExited) {
        Stop-Process -Id $api.Id -Force -ErrorAction SilentlyContinue
    }
}
