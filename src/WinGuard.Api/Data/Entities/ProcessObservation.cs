using System.ComponentModel.DataAnnotations;

namespace WinGuard.Api.Data.Entities;

/// <summary>
/// A point-in-time observation of one process, as sent by the agent. Module and
/// memory-region lists are stored as JSON because they are only ever consumed
/// whole, by the analyst drill-down view.
/// </summary>
public class ProcessObservation
{
    public long Id { get; set; }

    [MaxLength(128)]
    public string HostId { get; set; } = string.Empty;

    public Host? Host { get; set; }

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

    /// <summary>Modules serialized as JSON.</summary>
    public string ModulesJson { get; set; } = "[]";

    /// <summary>Memory regions serialized as JSON.</summary>
    public string MemoryRegionsJson { get; set; } = "[]";

    public DateTimeOffset ObservedAtUtc { get; set; }

    public DateTimeOffset ReceivedAtUtc { get; set; }
}
