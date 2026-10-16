using WinGuard.Core.Models;

namespace WinGuard.Core.Detection.Rules;

/// <summary>
/// R001 — an unsigned or self-signed module is loaded into a protected process.
/// </summary>
/// <remarks>
/// Only applies to protected processes (the protected-process allowlist).
/// Modules with no file backing are excluded: Authenticode cannot be evaluated
/// for them, and they are covered by R003 instead.
/// </remarks>
public sealed class UnsignedModuleLoadedRule : IDetectionRule
{
    public string RuleId => RuleIds.UnsignedModuleLoaded;

    public string Title => "Unsigned or self-signed module loaded into a protected process";

    public int DefaultBaseWeight => 45;

    public IReadOnlyList<DetectionEvent> Evaluate(DetectionRuleContext context)
    {
        if (!context.IsProtected)
        {
            return [];
        }

        var events = new List<DetectionEvent>();

        foreach (var module in context.Snapshot.Modules)
        {
            if (!module.IsBackedByFile || module.SignatureStatus == SignatureStatus.Signed)
            {
                continue;
            }

            events.Add(context.CreateEvent(RuleId, context.BaseWeight(RuleId, DefaultBaseWeight), new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["moduleName"] = module.Name,
                ["modulePath"] = module.Path,
                ["signatureStatus"] = module.SignatureStatus.ToString(),
                ["signerName"] = module.SignerName,
                ["signerTrust"] = DetectionRuleContext.SignerTrust(module.SignatureStatus),
                ["protectedProcess"] = "true",
            }));
        }

        return events;
    }
}
