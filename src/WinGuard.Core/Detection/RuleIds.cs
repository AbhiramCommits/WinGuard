namespace WinGuard.Core.Detection;

/// <summary>
/// Canonical detection rule ids. Shared by the rules themselves, the corpus
/// generator's ground-truth labels, the API, the dashboard and the benchmark so
/// a rule can never silently drift from its label.
/// </summary>
public static class RuleIds
{
    /// <summary>Unsigned or self-signed module loaded into a protected process.</summary>
    public const string UnsignedModuleLoaded = "R001";

    /// <summary>Module mapped from a path outside the allowed roots (injected DLL).</summary>
    public const string InjectedModulePath = "R002";

    /// <summary>Executable memory with no file backing (manual map / reflective load).</summary>
    public const string UnbackedExecutableMemory = "R003";

    /// <summary>In-memory .text hash differs from the on-disk hash (patched code).</summary>
    public const string PatchedCodeSection = "R004";

    /// <summary>Private read-write-execute region in a protected process.</summary>
    public const string RwxPrivateRegion = "R005";

    /// <summary>PEB image base/size disagrees with the on-disk PE headers (hollowing).</summary>
    public const string ProcessHollowing = "R006";

    /// <summary>All rule ids in evaluation order.</summary>
    public static readonly string[] All =
    [
        UnsignedModuleLoaded,
        InjectedModulePath,
        UnbackedExecutableMemory,
        PatchedCodeSection,
        RwxPrivateRegion,
        ProcessHollowing,
    ];

    /// <summary>Human-readable rule titles used in events and on the dashboard.</summary>
    public static readonly IReadOnlyDictionary<string, string> Titles = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        [UnsignedModuleLoaded] = "UnsignedModuleLoaded",
        [InjectedModulePath] = "InjectedModulePath",
        [UnbackedExecutableMemory] = "UnbackedExecutableMemory",
        [PatchedCodeSection] = "PatchedCodeSection",
        [RwxPrivateRegion] = "RwxPrivateRegion",
        [ProcessHollowing] = "ProcessHollowing",
    };

    public static string Title(string ruleId)
        => Titles.TryGetValue(ruleId, out var title) ? title : ruleId;
}
