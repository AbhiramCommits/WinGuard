namespace WinGuard.Core.Models;

/// <summary>
/// A committed memory region inside a process, as reported by
/// <c>VirtualQueryEx</c>. Used to find unbacked executable memory and
/// read-write-execute private pages.
/// </summary>
public sealed record MemoryRegionRecord
{
    public required ulong BaseAddress { get; init; }

    public required long Size { get; init; }

    /// <summary>Win32 page protection constant, e.g. <c>PAGE_EXECUTE_READWRITE</c>.</summary>
    public string Protection { get; init; } = string.Empty;

    /// <summary>Win32 region type: <c>MEM_IMAGE</c>, <c>MEM_MAPPED</c> or <c>MEM_PRIVATE</c>.</summary>
    public string RegionType { get; init; } = string.Empty;

    public bool IsExecutable { get; init; }

    public bool IsWritable { get; init; }

    /// <summary>True when the region maps a file on disk (image/mapped) rather than private commit.</summary>
    public bool IsBackedByFile { get; init; }

    /// <summary>Backing file path when known (image-backed regions).</summary>
    public string? BackingFile { get; init; }
}
