using WinGuard.Core.Models;

namespace WinGuard.Core.Detection;

/// <summary>
/// Per-snapshot evaluation context handed to every rule: the snapshot under
/// test, the effective options, whether the process is protected, and the list
/// of module roots considered legitimate for this process.
/// </summary>
public sealed class DetectionRuleContext
{
    public DetectionRuleContext(ProcessSnapshot snapshot, DetectionOptions options)
    {
        Snapshot = snapshot;
        Options = options;
        IsProtected = snapshot.IsProtected
            || options.ProtectedProcessNames.Contains(snapshot.ProcessName, StringComparer.OrdinalIgnoreCase);
        AllowedRoots = ModulePathPolicy.AllowedRootsFor(snapshot, options);
    }

    public ProcessSnapshot Snapshot { get; }

    public DetectionOptions Options { get; }

    /// <summary>True when the process is protected (flagged by the collector or on the allowlist).</summary>
    public bool IsProtected { get; }

    public IReadOnlyList<string> AllowedRoots { get; }

    public bool IsRuleEnabled(string ruleId) => Options.IsRuleEnabled(ruleId);

    public int BaseWeight(string ruleId, int fallback) => Options.BaseWeightFor(ruleId, fallback);

    public bool IsAllowedModulePath(string path) => ModulePathPolicy.IsAllowed(path, AllowedRoots);

    /// <summary>Builds an event carrying the rule's base weight; the scorer finalises severity.</summary>
    public DetectionEvent CreateEvent(string ruleId, int baseWeight, IReadOnlyDictionary<string, string> evidence)
        => new()
        {
            RuleId = ruleId,
            Severity = baseWeight,
            HostId = Snapshot.HostId,
            Pid = Snapshot.Pid,
            ProcessName = Snapshot.ProcessName,
            ImagePath = Snapshot.ImagePath,
            Title = RuleIds.Title(ruleId),
            Evidence = new Dictionary<string, string>(evidence, StringComparer.Ordinal),
            ObservedAtUtc = Snapshot.ObservedAtUtc,
        };

    /// <summary>Evidence key describing how much the signer of the implicated module can be trusted.</summary>
    public static string SignerTrust(SignatureStatus status) => status switch
    {
        SignatureStatus.Signed => "trusted",
        SignatureStatus.Unsigned => "untrusted",
        SignatureStatus.SelfSigned => "untrusted",
        _ => "unknown",
    };
}
