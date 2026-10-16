namespace WinGuard.Core.Models;

/// <summary>
/// Identity and platform description of the endpoint the agent runs on. Sent
/// once at registration and refreshed on every heartbeat.
/// </summary>
public sealed record HostInfo
{
    /// <summary>Stable host identifier. On Windows this is the MachineGuid; the corpus uses synthetic ids.</summary>
    public required string HostId { get; init; }

    public required string Hostname { get; init; }

    public string OsVersion { get; init; } = string.Empty;

    public string Architecture { get; init; } = string.Empty;

    public string AgentVersion { get; init; } = string.Empty;

    public string Domain { get; init; } = string.Empty;

    public string UserName { get; init; } = string.Empty;

    public DateTimeOffset CollectedAtUtc { get; init; } = DateTimeOffset.UtcNow;
}
