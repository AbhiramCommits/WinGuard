# WinGuard

**WinGuard is a Windows endpoint integrity agent plus a security-operations API and analyst
dashboard.** An anti-cheat-style tamper-detection system: a native Win32/ETW collector gathers
process, module-load and code-signing telemetry from each endpoint; a scored detection engine flags
tamper indicators (injected DLLs, patched process memory, unsigned or hollowed modules, RWX private
memory); the agent signs and ships heartbeats and detection events over HTTPS to an ASP.NET Core API
that persists them to SQL Server; and a dependency-free browser console shows live host status, a
detection timeline and a per-process drill-down with the evidence behind every rule hit.

---

## Architecture

```
                    ENDPOINT (Windows)                                    SERVER
 ┌───────────────────────────────────────────────┐        ┌─────────────────────────────────────────┐
 │  native/winguard_native  (C++ / Win32 + ETW)  │        │  WinGuard.Api  (ASP.NET Core 8)         │
 │    wg_enumerate_processes                    │        │    SignedPayloadMiddleware  (HMAC-SHA256│
 │    wg_enumerate_modules  (psapi + Authenticode)│       │      + nonce cache + 5-min skew window) │
 │    wg_read_text_section  (ReadProcessMemory)  │        │    CertificateAuthenticationHandler (mTLS│
 │    etw_consumer.cpp      (Kernel-Process)     │        │    DataAnnotations validation, 1 MiB cap│
 │            ▲ P/Invoke                          │        │    RateLimiter, security headers        │
 │            │                                   │        │            │                            │
 │  WinGuard.Agent  (worker service)             │        │            ▼ EF Core                   │
 │    ITelemetrySource ──► DetectionEngine ──►   │  HTTPS │    WinGuardDbContext                   │
 │    ApiClient (signs, retries, spools)  ───────┼───────►│      Hosts / Heartbeats /               │
 │            ▲                                   │        │      Detections / ProcessObservations   │
 │            │ (non-Windows: ReplayTelemetrySource)       │            │                            │
 └───────────────────────────────────────────────┘        │            ▼                            │
                                                          │    SQL Server  (prod)                   │
                                                          │    SQLite      (local / CI / tests)     │
                                                          │            │                            │
                                                          │            ▼                            │
                                                          │    wwwroot: index.html / app.js /       │
                                                          │    styles.css  (vanilla JS console)     │
                                                          └─────────────────────────────────────────┘
```

### Components

| Component | Project | Responsibility |
| --- | --- | --- |
| **Native collector** | `native/winguard_native` (C++17, CMake) | Exports a C ABI: toolhelp process enumeration, `EnumProcessModulesEx` + `GetModuleFileNameExW`, `VirtualQueryEx` memory walk, `ReadProcessMemory` of the mapped `.text`, Authenticode verification via `WinVerifyTrust`/`WinTrust`, and a real-time ETW consumer for `Microsoft-Windows-Kernel-Process` image loads. |
| **Agent** | `src/WinGuard.Agent` | Hosts the collector, runs the detection engine over each snapshot, signs and ships heartbeats / detection events / process observations, retries with exponential backoff and spools to disk when the API is unreachable. Runs as a Windows Service (LocalService) or a console app. |
| **Detection engine** | `src/WinGuard.Core` | Six rules, a severity scorer (signer trust + process criticality + same-PID correlation), a dedupe window, and the strongly-typed `Detection` configuration. |
| **API** | `src/WinGuard.Api` | Signed ingest (`/api/v1/*`), EF Core persistence, fleet/status/timeline/drill-down queries, the `healthz` probe, and the static analyst console. |
| **Database** | SQL Server / SQLite | One schema, two providers, each with its own committed migration set. |
| **Dashboard** | `src/WinGuard.Api/wwwroot` | Vanilla JS, no framework, no build step, no CDN. |
| **Eval harness** | `src/WinGuard.Eval` | Deterministic corpus generator and the detection benchmark that produces `results/`. |

### The `ITelemetrySource` split (and why it exists)

Everything in this repository must build, test and produce real evaluation numbers on macOS and
Linux as well as Windows. Telemetry *collection* is therefore the only platform-specific layer,
behind one interface (`WinGuard.Core.Telemetry.ITelemetrySource`):

| Implementation | Platform | What it does |
| --- | --- | --- |
| `Win32EtwTelemetrySource` | Windows only | P/Invokes `winguard_native.dll` and subscribes to ETW. Throws `PlatformNotSupportedException` anywhere else and is registered in DI only inside an `OperatingSystem.IsWindows()` guard. |
| `ReplayTelemetrySource` | any | Replays a JSONL telemetry corpus from disk, preserving the file's ordering and timestamps, at an optional configurable rate. |

The detection engine, API, database, dashboard, tests and benchmark all run identically against
either source. Nothing is stubbed for the non-Windows path: the Win32/C++ collector is real,
compilable interop code (the CI `windows-latest` job builds it), it simply is not exercised off
Windows.

---

## Detection rules

Severity starts at the rule's base weight, then a scorer applies signer-trust and
protected-process modifiers plus a same-PID correlation bonus (+8 per additional rule, capped at
+25), clamps to 0-100 and buckets the result Low / Medium / High / Critical.

| Rule | Detects | How | Base severity |
| --- | --- | --- | ---: |
| **R001** UnsignedModuleLoaded | A module that is not validly signed, loaded into a protected process | `WinVerifyTrust` gives `Unsigned`/`SelfSigned` for a file-backed module; the process is protected if the collector says so or its name is on the protected-process allowlist | 45 |
| **R002** InjectedModulePath | A module mapped from outside the allowed roots (System32, SysWOW64, WinSxS, .NET, Program Files, and the process's own directory) | Case-insensitive directory-boundary comparison of the module path against the configured roots | 60 |
| **R003** UnbackedExecutableMemory | Executable memory with no backing file — manual mapping / reflective loading | `VirtualQueryEx` region walk: executable `MEM_PRIVATE` region whose `GetMappedFileNameW` lookup yields no file | 65 |
| **R004** PatchedCodeSection | A signed module whose code was patched in memory | SHA-256 of the mapped `.text` bytes (read with `ReadProcessMemory`) compared with the SHA-256 of the same section on disk | 75 |
| **R005** RwxPrivateRegion | A private read-write-execute region in a protected process | Region walk for `MEM_PRIVATE` + executable + writable, gated on the protected-process allowlist | 55 |
| **R006** ProcessHollowing | The image was replaced after load | PEB-reported image base/size compared against the on-disk PE optional header (`ImageBase`, `SizeOfImage`) | 70 |

Rules can be individually disabled and re-weighted in `Detection:Rules` in `appsettings.json`.

---

## Security design

| Control | Implementation |
| --- | --- |
| **HMAC-SHA256 request signing** | Canonical string `METHOD \n path \n timestamp \n nonce \n lowercase-hex(sha256(body))`, signed with a per-host key derived as `HMAC-SHA256(server master secret, hostId)` so the API never stores agent secrets. Verified in `SignedPayloadMiddleware`; the verified host id is authoritative and a mismatched payload host id is rejected with `403`. |
| **Replay rejection** | Single-use nonce cache keyed by host + nonce, with a configurable retention window. |
| **Clock-skew rejection** | Requests outside `MaxClockSkewSeconds` (default 300) are rejected. |
| **No information leakage** | Every rejection is a bare `401`/`413` (`{"error":"unauthorized"}`, `Cache-Control: no-store`) so the endpoint cannot be used as an oracle. |
| **Mutual TLS** | `CertificateAuthenticationHandler` maps a client-certificate **thumbprint** to a registered `HostId`; a certificate not bound to a host is rejected. Kestrel requires client certificates in the `mtls` launch profile; `scripts/gen-dev-certs.sh\|ps1` creates a dev CA, a server certificate and an agent client certificate. |
| **Least-privilege service account** | The MSI and `packaging/install-service.ps1` register the agent as **`NT AUTHORITY\LocalService`**, grant write access only to the spool directory, and configure automatic restart on failure. |
| **Browser hardening** | Strict `Content-Security-Policy` (no `unsafe-inline`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `Permissions-Policy`. All server values are rendered with `textContent` — never `innerHTML`. |
| **Input validation & limits** | `[ApiController]` + DataAnnotations (`[MaxLength]`, `[Range]`, `[Required]`), a Kestrel 1 MiB body cap **and** a middleware content-length check returning `413`, and clamped query limits (max 1000). |
| **Rate limiting** | Built-in `RateLimiter` fixed window on the ingest endpoints, partitioned by verified host id (falling back to client IP). |
| **Logging hygiene** | Structured logs carry host id, counts and rule ids only; bodies and secrets are never logged. |

The full analysis — assets, trust boundaries, a STRIDE table of what is mitigated versus explicitly
deferred, and what a local administrator on the endpoint can still do — is in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

---

## How to run

### Prerequisites

- .NET 8 SDK
- `python3` (used by the e2e script to summarise JSON)
- Optional: OpenSSL (dev certificates), WiX Toolset v3 + CMake + MSVC (Windows MSI and native collector)

```bash
git clone <this repo> && cd WinGuard
dotnet build          # zero warnings; warnings are errors
```

### 1. Generate the telemetry corpus (once)

```bash
dotnet run --project src/WinGuard.Eval -- gen-corpus
```

Writes `data/corpus/benign.jsonl` (500 snapshots) and `data/corpus/labeled.jsonl`
(2000 snapshots, 300 tampered, each line carrying ground-truth `labels`). Both files are committed
so results are reproducible.

### 2. Development certificates (for mTLS)

```bash
bash scripts/gen-dev-certs.sh          # or: pwsh -File scripts/gen-dev-certs.ps1
```

Creates `certs/dev/{ca,server,agent}.crt|key` and `agent.pfx`.

### 3. Run the API

```bash
# HTTP, SQLite, no client certificates (default dev profile) -> http://localhost:5199
dotnet run --project src/WinGuard.Api

# Mutual TLS: requires certs/dev, serves https://localhost:7199 and demands a client cert
dotnet run --project src/WinGuard.Api --launch-profile mtls
```

`GET /healthz` returns `200` with the active provider. The analyst console is at `/`.

### 4. Run the agent

Console mode (any OS — uses the replay corpus off Windows):

```bash
dotnet run --project src/WinGuard.Agent
```

Windows Service mode (from a published folder, as an administrator):

```powershell
dotnet publish src/WinGuard.Agent -c Release -o "C:\Program Files\WinGuard\Agent"
pwsh -File packaging/install-service.ps1 -InstallPath "C:\Program Files\WinGuard\Agent"
# ... later
pwsh -File packaging/uninstall-service.ps1 -InstallPath "C:\Program Files\WinGuard\Agent"
```

Or build an MSI that installs the agent and its service as `LocalService`:

```powershell
pwsh -File packaging/build-msi.ps1 -Configuration Release -Version 1.0.0
msiexec /i packaging/bin/WinGuardAgent-1.0.0.msi /qn
```

`build-msi.ps1` publishes the agent, copies in a freshly built `winguard_native.dll` when present,
harvests the published files with WiX `heat`, and links `packaging/winguard-agent.wxs`.

### 5. End-to-end run

Starts the API on a throwaway SQLite database, replays the corpus through the agent into it, waits
for ingest to settle, then prints the fleet summary:

```bash
bash scripts/run-e2e.sh                # or: pwsh -File scripts/run-e2e.ps1
```

### 6. Benchmark

```bash
dotnet test                                  # 130 tests
dotnet run -c Release --project src/WinGuard.Eval -- benchmark --test-count 130
```

Writes `results/metrics.json` and `results/metrics.md`.

### 7. Switch the database to SQL Server

Everything is provider-agnostic; only configuration changes:

```jsonc
// src/WinGuard.Api/appsettings.json
"Database": { "Provider": "SqlServer", "MigrateOnStartup": true },
"ConnectionStrings": {
  "SqlServer": "Server=sql01;Database=WinGuard;User Id=winguard;Password=…;TrustServerCertificate=False;Encrypt=True"
}
```

The SQL Server migration set is already committed at
`src/WinGuard.Api/Data/Migrations/SqlServer/`; add new ones with:

```bash
dotnet tool restore
dotnet dotnet-ef migrations add <Name> --context SqlServerWinGuardDbContext \
  --output-dir Data/Migrations/SqlServer --project src/WinGuard.Api
dotnet dotnet-ef migrations add <Name> --context SqliteWinGuardDbContext \
  --output-dir Data/Migrations/Sqlite --project src/WinGuard.Api
```

---

## Results

Every number below comes from the committed [`results/metrics.json`](results/metrics.json),
produced by the command in §6.

```
Run:       2026-10-16T07:50:02Z
Machine:   Abhirams-MacBook-Air — Darwin 27.0.0 (Arm64, 8 CPUs), .NET 8.0.31 (osx-arm64)
Telemetry: ReplayTelemetrySource (the Win32/ETW collector requires Windows; it is compiled by CI
           on windows-latest but not exercised on this host)
Tests:     130 passing
```

### Corpus

| Corpus | Snapshots | Tampered | Rule instances |
| --- | ---: | ---: | ---: |
| `data/corpus/labeled.jsonl` | 2000 | 300 | 440 |
| `data/corpus/benign.jsonl` | 500 | 0 | 0 |

### Detection quality

| Rule | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| R001 UnsignedModuleLoaded | 107 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R002 InjectedModulePath | 55 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R003 UnbackedExecutableMemory | 111 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R004 PatchedCodeSection | 57 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R005 RwxPrivateRegion | 55 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R006 ProcessHollowing | 55 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **overall (micro)** | **440** | **0** | **0** | **1.0000** | **1.0000** | **1.0000** |

### False positives on the benign corpus

| Metric | Value |
| --- | ---: |
| Benign snapshots evaluated | 500 |
| False-positive findings | 0 |
| False-positive rate (findings ÷ (snapshots × rules)) | 0.0000 % |
| True negatives | 3000 |

### Performance

| Metric | Value |
| --- | ---: |
| Detection latency p50 | 0.004 ms |
| Detection latency p95 | 0.012 ms |
| Detection latency p99 | 0.018 ms |
| Detection latency mean / max | 0.005 ms / 0.101 ms |
| Detection throughput | 188 932 snapshots/s |
| Ingest throughput (events + observations) | 3 002 items/s |
| Ingested detection events / observations | 452 / 301 |
| Managed heap high-water mark | 65.13 MB |
| Process working set high-water mark | 201.28 MB |
| Total allocated (managed) | 199.1 MB |

Latency is the steady-state time for one snapshot to pass through all six rules and the scorer
(2000 samples, after a 200-snapshot warm-up). Ingest throughput posts the engine's real output
through the real HTTP pipeline — routing, HMAC verification, nonce checking, validation, rate
limiting and EF Core persistence, hosted in-process — and is therefore dominated by SQLite writes,
not by detection.

### CI platforms

`.github/workflows/ci.yml` runs on **`ubuntu-latest`** and **`windows-latest`**: restore, build
with warnings-as-errors, `dotnet test --collect:"XPlat Code Coverage"`, the benchmark with
`results/` uploaded as an artifact. A third `windows-latest` job configures CMake and builds
`native/winguard_native` so the Win32/ETW C++ code is proven to compile on every push.

---

## Limitations and next steps

- **The corpus is synthetic.** 2000 labeled snapshots across 42 simulated endpoints, generated
  deterministically from a fixed seed. Precision/recall of 1.0000 measures that the rules implement
  the *stated* semantics exactly; it is not a claim about accuracy against real-world malware. The
  corpus deliberately includes hard negatives (legitimate self-signed/unsigned modules in
  non-protected processes, private non-executable regions), but real-world distributions are far
  messier.
- **No kernel-mode component.** A sufficiently privileged attacker who can load a driver can lie to
  user-mode APIs, hide modules or patch our reads. Real anti-cheat products pair user-mode
  detection with an ELAM-signed kernel driver and PatchGuard/VBS; that is out of scope here.
- **Known real-world false-positive sources** that the corpus does not model: JIT engines that
  commit executable private memory (RWX JIT pages), packed/self-modifying legitimate binaries,
  in-memory instrumentation agents and AV hooking all overlap with R003/R004/R005. Production
  tuning needs per-process allowlists and a reputation signal.
- **R006 compares raw PEB values to the on-disk preferred base.** Real ASLR relocates images, so a
  production implementation must account for the loader's relocation delta rather than comparing
  the values directly; the corpus encodes the simplified comparison the rule implements.
- **The nonce cache is per-process.** A multi-instance API deployment needs a shared nonce store
  (Redis or a SQL table) or replay protection silently becomes per-instance.
- **The dashboard has no analyst authentication.** It is an intentionally dependency-free console to
  be deployed behind an authenticating reverse proxy or an OIDC front door.
- **Partial Windows-service hardening.** The service runs as `LocalService`, but there is no
  self-integrity check on the agent binary, no code-signing verification of its own DLLs, and no
  protection against `TerminateProcess` beyond Windows Service recovery settings.
- **No alerting/SIEM integration.** Events are persisted and displayed; forwarding (syslog, webhook,
  OTLP) and per-analyst triage state are not implemented.
- **No fuzzing or property tests.** Input validation is exercised by integration tests; the parsers
  (PE reader, JSONL reader, TDH decoding) would benefit from fuzz coverage.
- **Next steps**, in rough priority order: a shared nonce store, analyst authentication, richer
  memory-region rules (thread start addresses, hook detection), a
  `Microsoft-Windows-Kernel-Process` replay corpus so ETW decoding is testable off Windows, alert
  forwarding, and per-host detection tuning profiles.

---

## Repository layout

```
src/WinGuard.Core/      contracts, telemetry sources, detection rules, scorer, signing primitives
src/WinGuard.Agent/     worker service, Win32 P/Invoke, API client, spooling
src/WinGuard.Api/       signed ingest API, EF Core, migrations, wwwroot dashboard
src/WinGuard.Eval/      deterministic corpus generator, benchmark harness
tests/WinGuard.Tests/   130 tests (rules, scorer, replay, signing, API, EF, benchmark regression)
native/                 C++ Win32 + ETW collector (Windows only)
packaging/              WiX MSI and PowerShell service install/uninstall
scripts/                dev certificates, end-to-end run
data/corpus/            committed telemetry corpus
results/                committed benchmark results (metrics.json + metrics.md)
docs/THREAT-MODEL.md    assets, trust boundaries, STRIDE, attacker capability
```
