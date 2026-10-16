using WinGuard.Core.Models;

namespace WinGuard.Core.Detection.Rules;

/// <summary>
/// R005 — a private read-write-execute memory region exists in a protected
/// process. RWX private commit is the classic shellcode / injected-stub pattern.
/// </summary>
public sealed class RwxPrivateRegionRule : IDetectionRule
{
    private const string PrivateRegion = "MEM_PRIVATE";

    public string RuleId => RuleIds.RwxPrivateRegion;

    public string Title => "Private read-write-execute region in a protected process";

    public int DefaultBaseWeight => 55;

    public IReadOnlyList<DetectionEvent> Evaluate(DetectionRuleContext context)
    {
        if (!context.IsProtected)
        {
            return [];
        }

        var events = new List<DetectionEvent>();

        foreach (var region in context.Snapshot.MemoryRegions)
        {
            if (!string.Equals(region.RegionType, PrivateRegion, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!region.IsExecutable || !region.IsWritable)
            {
                continue;
            }

            events.Add(context.CreateEvent(RuleId, context.BaseWeight(RuleId, DefaultBaseWeight), new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["regionBase"] = $"0x{region.BaseAddress:X}",
                ["regionSize"] = region.Size.ToString(),
                ["protection"] = region.Protection,
                ["regionType"] = region.RegionType,
                ["protectedProcess"] = "true",
                ["signerTrust"] = "unknown",
            }));
        }

        return events;
    }
}
