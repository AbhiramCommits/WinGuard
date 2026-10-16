using WinGuard.Core.Contracts;

namespace WinGuard.Api.Contracts;

// Read models returned by the analyst/query APIs. The ingest wire contracts live
// in WinGuard.Core.Contracts so the agent can produce them without depending on ASP.NET.

/// <summary>Fleet-view row: one host with its derived status and worst finding.</summary>
public sealed record HostSummaryDto(
    string HostId,
    string Hostname,
    string Domain,
    string AgentVersion,
    string Status,
    DateTimeOffset? LastHeartbeatUtc,
    int DetectionCount,
    int HighestSeverity,
    string HighestSeverityBucket);

/// <summary>A persisted detection as returned by the read APIs.</summary>
public sealed record DetectionDto(
    string EventId,
    string HostId,
    int Pid,
    string ProcessName,
    string ImagePath,
    string RuleId,
    string Title,
    int Severity,
    string SeverityBucket,
    DateTimeOffset ObservedAtUtc,
    IReadOnlyDictionary<string, string> Evidence);

/// <summary>One point on a process's detection timeline.</summary>
public sealed record ProcessTimelineEntryDto(
    string RuleId,
    string Title,
    int Severity,
    string SeverityBucket,
    DateTimeOffset ObservedAtUtc);

/// <summary>Everything the analyst drill-down needs for one PID on one host.</summary>
public sealed record ProcessDrilldownDto(
    string HostId,
    int Pid,
    string ProcessName,
    string ImagePath,
    int ParentPid,
    string UserName,
    string CommandLine,
    bool IsProtected,
    DateTimeOffset? ObservedAtUtc,
    IReadOnlyList<ModuleDto> Modules,
    IReadOnlyList<MemoryRegionDto> MemoryRegions,
    IReadOnlyList<DetectionDto> Detections,
    IReadOnlyList<ProcessTimelineEntryDto> Timeline);

/// <summary>Health probe response.</summary>
public sealed record HealthResponse(
    string Status,
    string Version,
    string DatabaseProvider,
    DateTimeOffset ServerTimeUtc);
