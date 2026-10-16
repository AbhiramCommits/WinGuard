<#
.SYNOPSIS
    Generates a development PKI for WinGuard mutual TLS.

.DESCRIPTION
    Creates, under the output directory:
      ca.crt / ca.key           - development root CA
      server.crt / server.key   - API server certificate (localhost SAN)
      agent.crt / agent.key     - agent client certificate
      agent.pfx                 - agent client cert + key as PKCS#12

    The API uses server.* when running with the "mtls" launch profile; the agent
    presents agent.crt. Requires OpenSSL on PATH (Git for Windows ships it).

.PARAMETER OutputDirectory
    Directory to write the certificates to. Defaults to certs/dev.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = "certs/dev"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "openssl was not found on PATH. Install Git for Windows (or OpenSSL) and retry."
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
Push-Location $OutputDirectory

try {
    if ((Test-Path ca.crt) -and (Test-Path server.crt) -and (Test-Path agent.crt)) {
        Write-Host "Certificates already exist in $(Get-Location); delete them to regenerate."
        return
    }

    $days = 825
    Write-Host "Generating development CA in $(Get-Location)"

    # Root CA
    openssl req -x509 -newkey rsa:4096 -sha256 -days $days -nodes `
        -keyout ca.key -out ca.crt `
        -subj "/CN=WinGuard Development CA/O=WinGuard/C=US" `
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" `
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    # Server certificate
    @"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
"@ | Set-Content -Encoding ascii server.ext

    openssl req -newkey rsa:2048 -sha256 -nodes `
        -keyout server.key -out server.csr `
        -subj "/CN=localhost/O=WinGuard/C=US"

    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial `
        -out server.crt -days $days -sha256 -extfile server.ext

    # Agent client certificate
    @"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:winguard-agent
"@ | Set-Content -Encoding ascii agent.ext

    openssl req -newkey rsa:2048 -sha256 -nodes `
        -keyout agent.key -out agent.csr `
        -subj "/CN=winguard-agent/O=WinGuard/C=US"

    openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial `
        -out agent.crt -days $days -sha256 -extfile agent.ext

    # PKCS#12 bundle for the .NET agent
    openssl pkcs12 -export -out agent.pfx `
        -inkey agent.key -in agent.crt -certfile ca.crt `
        -passout pass:winguard

    Remove-Item -Force server.csr, agent.csr, server.ext, agent.ext, ca.srl -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "Wrote:"
    Get-ChildItem ca.crt, ca.key, server.crt, server.key, agent.crt, agent.key, agent.pfx | Select-Object -ExpandProperty Name
    Write-Host ""
    Write-Host "Enable mutual TLS by running the API with the 'mtls' launch profile:"
    Write-Host "  dotnet run --project src/WinGuard.Api --launch-profile mtls"
}
finally {
    Pop-Location
}
