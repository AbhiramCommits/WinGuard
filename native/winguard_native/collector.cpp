// ---------------------------------------------------------------------------
// WinGuard native telemetry shim — placeholder.
//
// Step 2 replaces this file with the real Win32/ETW collector exporting the
// C ABI consumed by WinGuard.Agent via P/Invoke:
//
//   wg_enumerate_processes
//   wg_enumerate_modules(pid)
//   wg_read_text_section(pid, base, out, len)
//
// The file lives here from Step 1 so the CMake project, the native README and
// the CI Windows job exist from the first commit.
// ---------------------------------------------------------------------------

#if defined(_WIN32)
#define WG_EXPORT extern "C" __declspec(dllexport)
#else
#define WG_EXPORT extern "C"
#endif

WG_EXPORT int wg_native_abi_version()
{
    // Bumped whenever the exported C ABI changes so the managed side can detect
    // a stale native binary sitting next to the agent.
    return 1;
}
