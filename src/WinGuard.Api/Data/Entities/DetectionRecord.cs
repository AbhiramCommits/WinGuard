using System.ComponentModel.DataAnnotations;

namespace WinGuard.Api.Data.Entities;

/// <summary>A persisted tamper detection produced by the agent's detection engine.</summary>
public class DetectionRecord
{
    public long Id { get; set; }

    /// <summary>Agent-generated event id, used for idempotent ingest.</summary>
    [MaxLength(64)]
    public string EventId { get; set; } = string.Empty;

    [MaxLength(128)]
    public string HostId { get; set; } = string.Empty;

    public Host? Host { get; set; }

    public int Pid { get; set; }

    [MaxLength(260)]
    public string ProcessName { get; set; } = string.Empty;

    [MaxLength(520)]
    public string ImagePath { get; set; } = string.Empty;

    [MaxLength(16)]
    public string RuleId { get; set; } = string.Empty;

    /// <summary>Final 0-100 severity after scoring.</summary>
    public int Severity { get; set; }

    [MaxLength(16)]
    public string SeverityBucket { get; set; } = string.Empty;

    [MaxLength(128)]
    public string Title { get; set; } = string.Empty;

    /// <summary>Evidence key/value pairs serialized as JSON.</summary>
    public string EvidenceJson { get; set; } = "{}";

    public DateTimeOffset ObservedAtUtc { get; set; }

    public DateTimeOffset ReceivedAtUtc { get; set; }
}
