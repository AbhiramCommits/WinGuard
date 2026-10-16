using WinGuard.Core.Models;

namespace WinGuard.Core.Detection.Rules;

/// <summary>
/// R002 — a module was mapped from a path outside the allowed roots
/// (System32, Program Files, WinSxS and the process's own directory).
/// </summary>
/// <remarks>
/// Injected DLLs are almost always loaded from a user-writable location such as
/// <c>%TEMP%</c>, <c>Downloads</c> or a public folder. Modules with no file
/// backing are skipped here and reported by R003.
/// </remarks>
public sealed class InjectedModulePathRule : IDetectionRule
{
    public string RuleId => RuleIds.InjectedModulePath;

    public string Title => "Module loaded from a path outside the allowed roots";

    public int DefaultBaseWeight => 60;

    public IReadOnlyList<DetectionEvent> Evaluate(DetectionRuleContext context)
    {
        var events = new List<DetectionEvent>();

        foreach (var module in context.Snapshot.Modules)
        {
            if (string.IsNullOrWhiteSpace(module.Path) || !module.IsBackedByFile)
            {
                continue;
            }

            if (context.IsAllowedModulePath(module.Path))
            {
                continue;
            }

            events.Add(context.CreateEvent(RuleId, context.BaseWeight(RuleId, DefaultBaseWeight), new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["moduleName"] = module.Name,
                ["modulePath"] = module.Path,
                ["imagePath"] = context.Snapshot.ImagePath,
                ["signatureStatus"] = module.SignatureStatus.ToString(),
                ["signerTrust"] = DetectionRuleContext.SignerTrust(module.SignatureStatus),
                ["allowedRoots"] = string.Join(';', context.AllowedRoots),
            }));
        }

        return events;
    }
}
