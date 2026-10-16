# WinGuard threat model

Scope: the endpoint agent, the transport, the ingest API, the database and the
analyst console in this repository. Nothing outside the repo (SIEM, cloud IAM,
enterprise PKI) is assumed to be in place.

## 1. Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| Raw telemetry (process, module, memory) | Ground truth for tamper detection; may contain sensitive process names and command lines | Agent memory on the endpoint |
| Detection events + severity | What analysts act on; corrupting them is a denial-of-detection | Agent memory, spool files, API, database |
| Per-host signing keys | Forge any request as that host if disclosed | Agent config/memory; derived by the API from its master secret |
| Host identity (MachineGuid / certificate thumbprint) | Binding of telemetry to an endpoint | Agent, API `Hosts` table |
| Database contents | Fleet history and evidence | SQL Server (prod) / SQLite (dev, CI) |
| Analyst console integrity | A tampered console hides detections | Browser, served from `wwwroot` |
| Agent binary + native collector | If replaced, all telemetry lies | Program Files on the endpoint |

## 2. Trust boundaries

```
 (1) Endpoint            (2) Transport          (3) API                (4) DB            (5) Analyst browser
 ┌──────────────┐        ┌──────────────┐      ┌────────────────┐     ┌──────────┐      ┌──────────────┐
 │ collected    │  TLS   │  mTLS +      │ HTTP │  ASP.NET Core  │ EF  │ SQL      │ HTTP │  vanilla JS  │
 │ telemetry,   │ ─────► │  HMAC-SHA256 │ ───► │  ingest + query│ ──► │ Server / │ ◄─── │  dashboard   │
 │ detection    │        │  signatures  │      │  validation    │     │ SQLite   │      │              │
 └──────────────┘        └──────────────┘      └────────────────┘     └──────────┘      └──────────────┘
    untrusted host            untrusted              hardened             trusted          untrusted user
```

1. **Endpoint → transport.** The endpoint is the least trusted part of the
   system: a local administrator can run anything on it.
2. **Transport.** The network and anything terminating TLS are untrusted;
   requests must be independently authenticated at the application layer.
3. **API.** Public attack surface: every byte is attacker-controlled until
   validated and authenticated.
4. **Database.** Trusted to the extent the API protects it; holds the fleet's
   history.
5. **Analyst browser.** Untrusted user agent: any value rendered from telemetry
   is potentially attacker-authored (process names, module paths).

## 3. STRIDE

| # | Category | Threat | Mitigation in this repo | Status |
| --- | --- | --- | --- | --- |
| T1 | Spoofing | Anyone POSTs heartbeats/events pretending to be a host | HMAC-SHA256 over `method + path + timestamp + nonce + SHA256(body)` with a per-host key; verified in `SignedPayloadMiddleware` (`401`, no detail) | Implemented |
| T2 | Spoofing | Stolen client certificate replayed | Optional mTLS with `CertificateAuthenticationHandler` mapping the certificate **thumbprint** to a registered host; an unbound certificate is rejected | Implemented (scheme + Kestrel profile); CA lifecycle deferred to enterprise PKI |
| T3 | Spoofing | Analyst console impersonation | Dashboard is served by the API; the repo does not ship analyst auth — deploy behind an authenticating reverse proxy or add OIDC | **Deferred** (documented) |
| T4 | Tampering | Request body modified in flight | Body hash is part of the signed canonical string; a modified body fails verification (`TamperedBodyIsRejected`) | Implemented |
| T5 | Tampering | Replay of a captured signed request | Per-host nonce cache rejects reuse inside the retention window; timestamp window (default 300 s) bounds the rest | Implemented (in-memory; a multi-instance deployment needs a shared store — see §6) |
| T6 | Tampering | Injection into the dashboard (stored XSS via process name / module path) | All server values written with `textContent`; strict CSP without `unsafe-inline`; `X-Content-Type-Options: nosniff`; regression test asserts the only `innerHTML` mention is a comment | Implemented |
| T7 | Tampering | Click-jacking the console | `frame-ancestors 'none'` + `X-Frame-Options: DENY` | Implemented |
| T8 | Tampering | MIME confusion on served assets | `X-Content-Type-Options: nosniff` | Implemented |
| T9 | Repudiation | A host denies sending telemetry | Signature is bound to a host id and a timestamp; ingest rows store `ReceivedAtUtc` and the event id for idempotency. No immutable audit log or non-repudiation signature is shipped | **Partial** |
| T10 | Information disclosure | Signature/secret material in logs | Structured logging records host id, counts and rule ids only; raw payloads are never logged | Implemented |
| T11 | Information disclosure | Error responses leak why a signature failed | Every rejection returns a bare `401`/`413` with `{"error":"unauthorized"}` and `Cache-Control: no-store` | Implemented |
| T12 | Information disclosure | Oversized payload as a memory-exhaustion oracle | Kestrel `MaxRequestBodySize` (1 MiB) **and** a middleware content-length check → `413` | Implemented |
| T13 | DoS | Event flood from one host | Built-in rate limiter (`AddRateLimiter`, fixed window partitioned by verified host id, else client IP) on the ingest endpoints | Implemented |
| T14 | DoS | Unbounded query results | All read endpoints clamp `limit` (max 1000) and order server-side | Implemented |
| T15 | Elevation of privilege | Agent runs as SYSTEM and is abused as a local attack surface | Installer registers the service as **LocalService** with `sc.exe`/WiX; the collector requests only `PROCESS_QUERY_INFORMATION`/`PROCESS_VM_READ` and the ETW session it needs | Implemented (packaging) |
| T16 | Elevation of privilege | SQL injection | EF Core only; no string-concatenated SQL; all inputs are bound parameters | Implemented |
| T17 | Elevation of privilege | Mass assignment / unbounded entity fields | DTOs with `[MaxLength]`/`[Range]` and `[ApiController]` auto-validation; the entity is never bound directly from the request | Implemented |
| T18 | Tampering | Agent binary or native collector replaced | Not prevented by the app itself: relies on code-signing + Windows Service hardening (ACLs on Program Files, service SID). See §4 | **Deferred** (documented) |

## 4. Attacker capability: local administrator on the endpoint

WinGuard runs on a machine an attacker may fully control. Assume the attacker
can start processes, load DLLs, patch memory and stop services.

What the design does about it:

- **Assume compromise of the agent's output.** Every rule is a *heuristic on
  observed state*, not a proof. Tuning and the analyst's judgement are the
  compensating control.
- **Keep the detection logic out of the agent's writable paths.** The rules and
  the corpus live in the repository/CI, and the measured accuracy in
  `results/metrics.json` is produced by that same code — the agent cannot
  rewrite the scoring.
- **Signature-verify every request.** An attacker who owns the endpoint can
  read the derived key from agent memory and forge telemetry *for that host*.
  They cannot impersonate other hosts: keys are derived per host id from a
  server-side master secret that never reaches the endpoint.
- **Bound the damage of a stopped agent.** Host status is derived from heartbeat
  age, so an agent that is killed or blocked shows up as `Stale`/`Offline`
  instead of silently disappearing.
- **Spool-then-send means a network blackout does not lose evidence**, and the
  spool directory can be protected with restrictive ACLs.

Explicitly **out of scope** (and why):

- Kernel-mode tamper resistance (a driver the attacker loads can lie to us) —
  a real product needs ELAM/PatchGuard and a signed kernel component.
- Protecting the agent's own process from `TerminateProcess` — mitigated only by
  Windows Service recovery settings, not by this code.
- Detecting tampering of the *detector* (self-integrity of the managed agent) —
  worth adding, not implemented.
- Host firmware/UEFI, hypervisor-level (`VBS`) isolation, and secure boot
  attestation — platform work, not application work.

## 5. Residual risk summary

| Risk | Severity | Notes |
| --- | --- | --- |
| Compromised endpoint forges its own telemetry | High | Inherent to any user-mode agent; per-host keys stop lateral forgery |
| Analyst console has no built-in authentication | High | Must be deployed behind an authenticating proxy/OIDC |
| Nonce cache is per-process | Medium | Multi-instance API deployments need Redis/SQL-backed nonces |
| Synthetic corpus overstates real-world accuracy | Medium | See the README's limitations section |
| No SIEM/alerting integration | Low | Out of scope |

## 6. Deployment notes that change the risk picture

- Run the API behind TLS with a real certificate; enable the `mtls` profile and
  pin the agent CA when the fleet can be provisioned with certificates.
- Replace `Security:Signing:MasterSecret` with a secret from a vault, and rotate
  it deliberately (rotation invalidates every derived host key).
- Front the dashboard with an authenticating reverse proxy, and enable
  `Content-Security-Policy` reporting if you add endpoints.
- Keep the SQL Server account least-privilege (the schema needs only DML on the
  four tables plus migration DDL during deployment).
