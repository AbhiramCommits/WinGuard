#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Generates a development PKI for WinGuard mutual TLS:
#
#   certs/dev/ca.crt|ca.key             - development root CA
#   certs/dev/server.crt|server.key     - API server certificate (localhost SAN)
#   certs/dev/agent.crt|agent.key       - agent client certificate
#   certs/dev/agent.pfx                 - agent client cert + key as PKCS#12
#
# The API uses server.* when running with the "mtls" profile; the agent presents
# agent.crt. The CA is stored alongside them so both sides can be pinned without
# touching the machine trust store.
#
# Usage: scripts/gen-dev-certs.sh [output-dir]
# ---------------------------------------------------------------------------
set -euo pipefail

OUT_DIR="${1:-certs/dev}"
DAYS=825

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

if [[ -f ca.crt && -f server.crt && -f agent.crt ]]; then
  echo "Certificates already exist in $(pwd); delete them to regenerate."
  exit 0
fi

echo "Generating development CA in $(pwd)"

# --- Root CA ---------------------------------------------------------------
openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS" -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=WinGuard Development CA/O=WinGuard/C=US" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# --- Server certificate ----------------------------------------------------
cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EOF

openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost/O=WinGuard/C=US" 2>/dev/null

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -sha256 -extfile server.ext 2>/dev/null

# --- Agent client certificate ---------------------------------------------
cat > agent.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:winguard-agent
EOF

openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout agent.key -out agent.csr \
  -subj "/CN=winguard-agent/O=WinGuard/C=US" 2>/dev/null

openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out agent.crt -days "$DAYS" -sha256 -extfile agent.ext 2>/dev/null

# --- PKCS#12 bundle for the .NET agent ------------------------------------
openssl pkcs12 -export -out agent.pfx \
  -inkey agent.key -in agent.crt -certfile ca.crt \
  -passout pass:winguard 2>/dev/null

rm -f server.csr agent.csr server.ext agent.ext ca.srl

echo
echo "Wrote:"
ls -1 ca.crt ca.key server.crt server.key agent.crt agent.key agent.pfx
echo
echo "Enable mutual TLS by running the API with the 'mtls' launch profile:"
echo "  dotnet run --project src/WinGuard.Api --launch-profile mtls"
