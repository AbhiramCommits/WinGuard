using System.ComponentModel.DataAnnotations;

namespace WinGuard.Core.Contracts;

// ---------------------------------------------------------------------------
// Wire contracts shared by the agent (producer) and the API (consumer). Living
// in WinGuard.Core keeps the agent free of any ASP.NET dependency while still
// guaranteeing byte-identical JSON on both sides.
// ---------------------------------------------------------------------------

/// <summary>Agent registration payload.</summary>
public sealed class RegisterHostRequest
{
    [Required]
    [MaxLength(128)]
    public string HostId { get; set; } = string.Empty;

    [Required]
    [MaxLength(256)]
    public string Hostname { get; set; } = string.Empty;

    [MaxLength(128)]
    public string OsVersion { get; set; } = string.Empty;

    [MaxLength(32)]
    public string Architecture { get; set; } = string.Empty;

    [MaxLength(32)]
    public string AgentVersion { get; set; } = string.Empty;

    [MaxLength(128)]
    public string Domain { get; set; } = string.Empty;

    [MaxLength(128)]
    public string UserName { get; set; } = string.Empty;
}

/// <summary>
/// Registration response. The per-host signing key is handed to the agent once;
/// the API derives it again from the host id, so it never stores agent secrets.
/// </summary>
public sealed record RegisterHostResponse(
    string HostId,
    string SigningKey,
    string SigningAlgorithm,
    int HeartbeatIntervalSeconds,
    DateTimeOffset ServerTimeUtc);

/// <summary>Periodic liveness message.</summary>
public sealed class HeartbeatRequest
{
    [Required]
    [MaxLength(128)]
    public string HostId { get; set; } = string.Empty;

    [MaxLength(32)]
    public string AgentVersion { get; set; } = string.Empty;

    public long Sequence { get; set; }

    public DateTimeOffset TimestampUtc { get; set; }

    public int ProcessCount { get; set; }

    public int PendingEventCount { get; set; }

    [MaxLength(32)]
    public string Status { get; set; } = "Healthy";
}

/// <summary>Heartbeat acknowledgement.</summary>
public sealed record HeartbeatResponse(string HostId, DateTimeOffset ServerTimeUtc, bool Accepted);

/// <summary>Batch ingest payload: detection events plus optional process observations.</summary>
public sealed class EventsRequest
{
    [Required]
    [MaxLength(128)]
    public string HostId { get; set; } = string.Empty;

    [Required]
    public List<DetectionEventDto> Events { get; set; } = [];

    /// <summary>Process observations that back the analyst drill-down (optional).</summary>
    public List<ProcessObservationDto> Observations { get; set; } = [];
}

/// <summary>A single tamper detection as produced by the agent's detection engine.</summary>
public sealed class DetectionEventDto
{
    [MaxLength(64)]
    public string? EventId { get; set; }

    [Required]
    [MaxLength(16)]
    public string RuleId { get; set; } = string.Empty;

    [Range(0, 100)]
    public int Severity { get; set; }

    public int Pid { get; set; }

    [MaxLength(260)]
    public string ProcessName { get; set; } = string.Empty;

    [MaxLength(520)]
    public string ImagePath { get; set; } = string.Empty;

    [MaxLength(128)]
    public string Title { get; set; } = string.Empty;

    [MaxLength(16)]
    public string SeverityBucket { get; set; } = string.Empty;

    public DateTimeOffset ObservedAtUtc { get; set; }

    public Dictionary<string, string> Evidence { get; set; } = new(StringComparer.Ordinal);
}

/// <summary>Point-in-time process observation used by the drill-down view.</summary>
public sealed class ProcessObservationDto
{
    public int Pid { get; set; }

    [MaxLength(260)]
    public string ProcessName { get; set; } = string.Empty;

    [MaxLength(520)]
    public string ImagePath { get; set; } = string.Empty;

    public int ParentPid { get; set; }

    [MaxLength(128)]
    public string UserName { get; set; } = string.Empty;

    [MaxLength(1024)]
    public string CommandLine { get; set; } = string.Empty;

    public bool IsProtected { get; set; }

    public List<ModuleDto> Modules { get; set; } = [];

    public List<MemoryRegionDto> MemoryRegions { get; set; } = [];

    public DateTimeOffset ObservedAtUtc { get; set; }
}

/// <summary>
/// Module as reported to the dashboard. Addresses are hex strings so a browser's
/// double-precision numbers cannot corrupt a 64-bit image base.
/// </summary>
public sealed class ModuleDto
{
    [MaxLength(520)]
    public string Path { get; set; } = string.Empty;

    [MaxLength(260)]
    public string Name { get; set; } = string.Empty;

    public string BaseAddress { get; set; } = "0x0";

    public long Size { get; set; }

    public string SignatureStatus { get; set; } = "Unknown";

    [MaxLength(260)]
    public string SignerName { get; set; } = string.Empty;

    [MaxLength(64)]
    public string OnDiskSha256 { get; set; } = string.Empty;

    [MaxLength(64)]
    public string InMemoryTextSha256 { get; set; } = string.Empty;

    public bool IsBackedByFile { get; set; } = true;

    [MaxLength(64)]
    public string MemoryProtection { get; set; } = string.Empty;
}

/// <summary>Memory region as reported to the dashboard.</summary>
public sealed class MemoryRegionDto
{
    public string BaseAddress { get; set; } = "0x0";

    public long Size { get; set; }

    [MaxLength(64)]
    public string Protection { get; set; } = string.Empty;

    [MaxLength(32)]
    public string RegionType { get; set; } = string.Empty;

    public bool IsExecutable { get; set; }

    public bool IsWritable { get; set; }

    public bool IsBackedByFile { get; set; }

    [MaxLength(520)]
    public string? BackingFile { get; set; }
}

/// <summary>Batch ingest acknowledgement.</summary>
public sealed record EventsResponse(
    string HostId,
    int AcceptedDetectionCount,
    int DuplicateDetectionCount,
    int AcceptedObservationCount,
    DateTimeOffset ServerTimeUtc);
