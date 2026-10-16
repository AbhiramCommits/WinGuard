namespace WinGuard.Core.Models;

/// <summary>
/// A point-in-time observation of a single process: its identity, the image
/// header facts used for hollowing detection, every loaded module and the
/// interesting memory regions. This is the unit of work the detection engine
/// consumes; it is produced either by the Win32/ETW collector or by the JSONL
/// replay source.
/// </summary>
public sealed record ProcessSnapshot
{
    public required string HostId { get; init; }

    public required int Pid { get; init; }

    public required string ProcessName { get; init; }

    public string ImagePath { get; init; } = string.Empty;

    public int ParentPid { get; init; }

    public string CommandLine { get; init; } = string.Empty;

    public string UserName { get; init; } = string.Empty;

    /// <summary>Image base address as reported by the PEB (in-memory).</summary>
    public ulong ImageBaseAddress { get; init; }

    /// <summary>Mapped image size as reported by the PEB (<c>PEB.ImageBaseAddress</c> region / SizeOfImage).</summary>
    public ulong PebImageSize { get; init; }

    /// <summary>Preferred image base read from the on-disk PE optional header.</summary>
    public ulong OnDiskImageBase { get; init; }

    /// <summary>SizeOfImage read from the on-disk PE optional header.</summary>
    public ulong OnDiskImageSize { get; init; }

    /// <summary>
    /// Marks the process as protected / high-value (a game client, a security
    /// product). Rules that only apply to protected processes gate on this.
    /// </summary>
    public bool IsProtected { get; init; }

    public bool IsWow64 { get; init; }

    public DateTimeOffset StartedAtUtc { get; init; }

    public DateTimeOffset ObservedAtUtc { get; init; }

    public IReadOnlyList<ModuleRecord> Modules { get; init; } = [];

    public IReadOnlyList<MemoryRegionRecord> MemoryRegions { get; init; } = [];

    /// <summary>
    /// Ground-truth rule ids expected to fire for this snapshot. Empty for benign
    /// snapshots. Populated only by the corpus generator; never by the live agent.
    /// </summary>
    public IReadOnlyList<string> Labels { get; init; } = [];
}
