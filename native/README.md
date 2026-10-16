# WinGuard native collector (`winguard_native`)

This directory holds the **real** Win32/ETW telemetry collector used by
`WinGuard.Agent` on Windows. It is genuine C++ interop code — not a stub — but
it deliberately only compiles and runs on Windows.

## Why it is isolated here

WinGuard must build, test and produce real evaluation numbers on macOS and
Linux as well as Windows. The telemetry *collection* layer is therefore behind
`WinGuard.Core.Telemetry.ITelemetrySource`:

| Source                   | Platform   | Description                                                       |
| ------------------------ | ---------- | ----------------------------------------------------------------- |
| `Win32EtwTelemetrySource`| Windows    | P/Invokes `winguard_native.dll` (this project) + ETW image loads. |
| `ReplayTelemetrySource`  | any        | Replays a JSONL telemetry corpus from disk as if it were live.     |

Everything downstream — detection engine, API ingest, SQL persistence,
dashboard, tests and the evaluation harness — runs identically against either
source. Nothing is stubbed out; only the *source* changes.

## Building

Windows only, MSVC + CMake (>= 3.20):

```powershell
cmake -S native/winguard_native -B native/out -A x64
cmake --build native/out --config Release
```

The build produces `winguard_native.dll`, which the managed agent expects next
to its own binaries (`AppContext.BaseDirectory`). The CI `windows-latest` job
builds it on every push to prove the Win32/ETW code compiles.

## Exported C ABI

| Export                                   | Purpose                                                        |
| ---------------------------------------- | -------------------------------------------------------------- |
| `wg_enumerate_processes`                 | Toolhelp32 process list with parent PID and image path.        |
| `wg_enumerate_modules(pid)`              | Loaded module list, Authenticode status and in-memory `.text`. |
| `wg_read_text_section(pid, base, out, len)`| `ReadProcessMemory` of the mapped `.text` for hashing.        |
| `wg_native_abi_version`                  | ABI version, so a stale DLL can be detected and rejected.      |
| `wg_etw_start` / `wg_etw_stop`           | ETW consumer for `Microsoft-Windows-Kernel-Process` image loads.|
