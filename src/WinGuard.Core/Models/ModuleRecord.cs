namespace WinGuard.Core.Models;

/// <summary>
/// A single module (executable image) loaded into a process, together with the
/// properties the detection engine needs to reason about tampering.
/// </summary>
public sealed record ModuleRecord
{
    /// <summary>Full image path as reported by the process (may be empty for manually mapped images).</summary>
    public required string Path { get; init; }

    /// <summary>Mapped base address of the module in the target process.</summary>
    public required ulong BaseAddress { get; init; }

    /// <summary>Size of the mapped image in bytes.</summary>
    public required long Size { get; init; }

    /// <summary>Friendly module name (for example <c>kernel32.dll</c>), used for display only.</summary>
    public string Name { get; init; } = string.Empty;

    public SignatureStatus SignatureStatus { get; init; } = SignatureStatus.Unknown;

    /// <summary>Common name (CN) of the signer, or empty when unsigned/unknown.</summary>
    public string SignerName { get; init; } = string.Empty;

    /// <summary>SHA-256 of the on-disk file.</summary>
    public string OnDiskSha256 { get; init; } = string.Empty;

    /// <summary>SHA-256 of the mapped <c>.text</c> section read out of process memory.</summary>
    public string InMemoryTextSha256 { get; init; } = string.Empty;

    /// <summary>
    /// False when the executable region has no file backing (manual map / reflective load).
    /// True for ordinary loader-mapped images.
    /// </summary>
    public bool IsBackedByFile { get; init; } = true;

    /// <summary>Protection of the module's main executable region, e.g. <c>PAGE_EXECUTE_READ</c>.</summary>
    public string MemoryProtection { get; init; } = string.Empty;
}
