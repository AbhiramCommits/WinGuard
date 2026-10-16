namespace WinGuard.Core.Models;

/// <summary>
/// Periodic liveness + health message from an agent. The API derives host
/// status (Online / Stale / Offline) purely from the age of the last heartbeat.
/// </summary>
public sealed record Heartbeat
{
    public required string HostId { get; init; }

    public string AgentVersion { get; init; } = string.Empty;

    /// <summary>Monotonic per-agent sequence number, used to detect gaps.</summary>
    public long Sequence { get; init; }

    public DateTimeOffset TimestampUtc { get; init; } = DateTimeOffset.UtcNow;

    public int ProcessCount { get; init; }

    public int PendingEventCount { get; init; }

    /// <summary>Agent self-reported health: <c>Healthy</c>, <c>Degraded</c>, <c>SpoolingOffline</c>.</summary>
    public string Status { get; init; } = "Healthy";
}
