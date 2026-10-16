using System.ComponentModel.DataAnnotations;

namespace WinGuard.Api.Data.Entities;

/// <summary>A liveness + health message from an agent.</summary>
public class HeartbeatRecord
{
    public long Id { get; set; }

    [MaxLength(128)]
    public string HostId { get; set; } = string.Empty;

    public Host? Host { get; set; }

    public long Sequence { get; set; }

    [MaxLength(32)]
    public string AgentVersion { get; set; } = string.Empty;

    [MaxLength(32)]
    public string Status { get; set; } = "Healthy";

    public int ProcessCount { get; set; }

    public int PendingEventCount { get; set; }

    public DateTimeOffset TimestampUtc { get; set; }

    public DateTimeOffset ReceivedAtUtc { get; set; }
}
