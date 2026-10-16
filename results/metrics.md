# WinGuard benchmark results

Run: **2026-10-16T07:50:02.1641490+00:00**  
Machine: `Abhirams-MacBook-Air` — Darwin 27.0.0 Darwin Kernel Version 27.0.0: Tue Aug 11 21:05:41 PDT 2026; root:xnu-13432.1.9~1/RELEASE_ARM64_T8122 (Arm64, 8 CPUs)  
Runtime: .NET 8.0.31 (`osx-arm64`)  
Telemetry source: `ReplayTelemetrySource` — Corpus replay: the Win32/ETW collector requires Windows and is compiled but not exercised on this host.

## Corpus

| Corpus | Snapshots | Tampered |
| --- | ---: | ---: |
| `labeled.jsonl` | 2000 | 300 |
| `benign.jsonl` | 500 | 0 |

## Detection quality (per rule)

| Rule | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| R001 | 107 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R002 | 55 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R003 | 111 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R004 | 57 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R005 | 55 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| R006 | 55 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **overall (micro)** | **440** | **0** | **0** | **1.0000** | **1.0000** | **1.0000** |

## False positives on the benign corpus

- benign snapshots: **500**
- false-positive findings: **0**
- false-positive rate (findings / (snapshots x rules)): **0.0000 %**
- true negatives: 3000

## Performance

| Metric | Value |
| --- | ---: |
| Detection latency p50 | 0.004 ms |
| Detection latency p95 | 0.012 ms |
| Detection latency p99 | 0.018 ms |
| Detection latency mean | 0.005 ms |
| Detection latency max | 0.101 ms |
| Detection throughput | 188932 snapshots/s |
| Ingest throughput (events + observations) | 3002 items/s |
| Ingested detection events | 452 |
| Ingested observations | 301 |
| Managed heap high-water mark | 65.13 MB |
| Process working set high-water mark | 201.28 MB |
| Total allocated (managed) | 199.1 MB |

## Test suite

- tests passing at the time of this run: **130**

## Notes

Accuracy is measured against the ground-truth `labels` array on every corpus line. Ingest throughput is measured by posting engine output through the real HTTP pipeline (HMAC verification, validation, rate limiting, EF Core persistence) hosted in-process.

