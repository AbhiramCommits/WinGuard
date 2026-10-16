#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# WinGuard end-to-end run.
#
#   1. starts the API on SQLite with a throwaway database,
#   2. runs the agent against the committed replay corpus, pointed at the API,
#   3. waits for ingest to settle,
#   4. queries the same endpoints the dashboard uses and prints a summary.
#
# Usage: scripts/run-e2e.sh [--corpus path/to.jsonl] [--url http://host:port]
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CORPUS="$ROOT/data/corpus/labeled.jsonl"
BASE_URL="http://localhost:5199"
SPOOL_DIR="$ROOT/data/spool"
DB_PATH="$ROOT/data/e2e.db"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --corpus) CORPUS="$2"; shift 2 ;;
    --url)    BASE_URL="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ! -f "$CORPUS" ]]; then
  echo "Corpus not found: $CORPUS" >&2
  echo "Generate it first: dotnet run --project src/WinGuard.Eval -- gen-corpus" >&2
  exit 1
fi

API_PID=""
cleanup() {
  if [[ -n "$API_PID" ]] && kill -0 "$API_PID" 2>/dev/null; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "==> Preparing a clean SQLite database at $DB_PATH"
rm -f "$DB_PATH" "$DB_PATH-shm" "$DB_PATH-wal"
rm -rf "$SPOOL_DIR"

echo "==> Building (Release)"
dotnet build -c Release --nologo -v quiet

echo "==> Starting the API at $BASE_URL"
ASPNETCORE_ENVIRONMENT=Production \
ASPNETCORE_URLS="$BASE_URL" \
Database__Provider=Sqlite \
Database__MigrateOnStartup=true \
ConnectionStrings__Sqlite="Data Source=$DB_PATH" \
Security__Signing__Enabled=true \
Security__Signing__MasterSecret=dev-only-master-secret-change-me \
  dotnet run -c Release --no-build --no-launch-profile --project src/WinGuard.Api \
  > "$ROOT/data/e2e-api.log" 2>&1 &
API_PID=$!

echo "==> Waiting for /healthz"
for _ in $(seq 1 60); do
  if curl -fsS "$BASE_URL/healthz" > /dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$API_PID" 2>/dev/null; then
    echo "API exited during startup; log:" >&2
    tail -30 "$ROOT/data/e2e-api.log" >&2
    exit 1
  fi
  sleep 1
done

if ! curl -fsS "$BASE_URL/healthz" > /dev/null 2>&1; then
  echo "API did not become healthy in time." >&2
  tail -30 "$ROOT/data/e2e-api.log" >&2
  exit 1
fi
echo "    healthz OK: $(curl -fsS "$BASE_URL/healthz")"

echo "==> Running the agent against $CORPUS"
Api__Enabled=true \
Api__BaseUrl="$BASE_URL" \
Api__HeartbeatIntervalSeconds=5 \
Api__BatchSize=50 \
Api__SpoolDirectory="$SPOOL_DIR" \
Replay__CorpusPath="$CORPUS" \
Replay__RatePerSecond=0 \
  dotnet run -c Release --no-build --project src/WinGuard.Agent

echo "==> Waiting for ingest to settle"
previous=-1
for _ in $(seq 1 60); do
  count=$(curl -fsS "$BASE_URL/api/v1/detections/recent?limit=1000" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
  if [[ "$count" == "$previous" && "$count" != "0" ]]; then
    break
  fi
  previous="$count"
  sleep 1
done

echo
echo "==> Dashboard endpoints"
echo "    GET /healthz                       -> $(curl -fsS "$BASE_URL/healthz")"
echo "    GET /index.html                    -> HTTP $(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/")"
echo "    GET /api/v1/hosts                  -> HTTP $(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/v1/hosts")"
echo "    GET /api/v1/detections/recent      -> HTTP $(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/v1/detections/recent")"
echo
echo "    security headers:"
curl -sI "$BASE_URL/" | grep -iE '^(content-security-policy|x-content-type-options|x-frame-options):' | sed 's/^/      /'

echo
echo "==> Results"
curl -fsS "$BASE_URL/api/v1/hosts" > "$ROOT/data/e2e-hosts.json"
curl -fsS "$BASE_URL/api/v1/detections/recent?limit=1000" > "$ROOT/data/e2e-detections.json"

python3 - "$ROOT/data/e2e-hosts.json" "$ROOT/data/e2e-detections.json" <<'PY'
import json, sys
from collections import Counter

hosts = json.load(open(sys.argv[1]))
detections = json.load(open(sys.argv[2]))

statuses = Counter(h["status"] for h in hosts)
rules = Counter(d["ruleId"] for d in detections)
pids = {(d["hostId"], d["pid"]) for d in detections}
highest = max((d["severity"] for d in detections), default=0)
worst = next((d for d in detections if d["severity"] == highest), None)

print(f"  hosts                 : {len(hosts)}")
print(f"  host status           : {', '.join(f'{k}={v}' for k, v in sorted(statuses.items()))}")
print(f"  detections ingested   : {len(detections)}")
print(f"  processes with hits    : {len(pids)}")
print(f"  highest severity      : {highest}" + (f" ({worst['severityBucket']}, {worst['ruleId']} on {worst['processName']})" if worst else ""))
print("  detections per rule   : " + ", ".join(f"{r}={rules[r]}" for r in sorted(rules)))

if not detections:
    raise SystemExit("FAILED: no detections were ingested")
if not hosts:
    raise SystemExit("FAILED: no hosts registered")
PY

echo
echo "  Dashboard: $BASE_URL/  (open in a browser while the API is running)"
echo
echo "End-to-end run complete."
