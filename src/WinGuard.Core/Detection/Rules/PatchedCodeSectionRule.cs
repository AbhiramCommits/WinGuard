using WinGuard.Core.Models;

namespace WinGuard.Core.Detection.Rules;

/// <summary>
/// R004 — a signed module's in-memory <c>.text</c> hash differs from the hash of
/// the same section on disk, i.e. its code was patched in memory.
/// </summary>
/// <remarks>
/// Hashing the <c>.text</c> raw bytes on both sides keeps the comparison
/// apples-to-apples: the mapped section is byte-identical to the file for an
/// unmodified image.
/// </remarks>
public sealed class PatchedCodeSectionRule : IDetectionRule
{
    public string RuleId => RuleIds.PatchedCodeSection;

    public string Title => "In-memory .text section differs from the on-disk image";

    public int DefaultBaseWeight => 75;

    public IReadOnlyList<DetectionEvent> Evaluate(DetectionRuleContext context)
    {
        var events = new List<DetectionEvent>();

        foreach (var module in context.Snapshot.Modules)
        {
            if (module.SignatureStatus != SignatureStatus.Signed)
            {
                continue;
            }

            if (string.IsNullOrEmpty(module.OnDiskSha256) || string.IsNullOrEmpty(module.InMemoryTextSha256))
            {
                continue;
            }

            if (string.Equals(module.OnDiskSha256, module.InMemoryTextSha256, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            events.Add(context.CreateEvent(RuleId, context.BaseWeight(RuleId, DefaultBaseWeight), new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["moduleName"] = module.Name,
                ["modulePath"] = module.Path,
                ["onDiskSha256"] = module.OnDiskSha256,
                ["inMemoryTextSha256"] = module.InMemoryTextSha256,
                ["baseAddress"] = $"0x{module.BaseAddress:X}",
                ["signerName"] = module.SignerName,
                ["signerTrust"] = "trusted",
            }));
        }

        return events;
    }
}
