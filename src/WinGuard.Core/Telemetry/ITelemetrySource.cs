using WinGuard.Core.Models;

namespace WinGuard.Core.Telemetry;

/// <summary>
/// Platform-agnostic source of process telemetry.
/// </summary>
/// <remarks>
/// WinGuard has two implementations and the rest of the system cannot tell them
/// apart:
/// <list type="bullet">
///   <item><description>
///     <c>Win32EtwTelemetrySource</c> — the real Win32/ETW collector. It is only
///     constructible on Windows and P/Invokes <c>winguard_native.dll</c>.
///   </description></item>
///   <item><description>
///     <c>ReplayTelemetrySource</c> — replays a JSONL corpus from disk. This is
///     what makes the detection engine, API, dashboard, tests and the evaluation
///     harness runnable with real numbers on macOS and Linux.
///   </description></item>
/// </list>
/// </remarks>
public interface ITelemetrySource
{
    /// <summary>
    /// Streams process snapshots in observation order. The enumerable completes
    /// when the underlying source is exhausted (replay) or the token fires.
    /// </summary>
    IAsyncEnumerable<ProcessSnapshot> StreamAsync(CancellationToken ct);

    /// <summary>Describes the local host once, for registration and heartbeats.</summary>
    HostInfo DescribeHost();
}
