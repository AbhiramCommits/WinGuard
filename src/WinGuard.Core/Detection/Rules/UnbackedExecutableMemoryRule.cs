using WinGuard.Core.Models;

namespace WinGuard.Core.Detection.Rules;

/// <summary>
/// R003 — an executable private memory region with no backing file exists in the
/// process (manual mapping / reflective loading).
/// </summary>
public sealed class UnbackedExecutableMemoryRule : IDetectionRule
{
    private const string PrivateRegion = "MEM_PRIVATE";

    public string RuleId => RuleIds.UnbackedExecutableMemory;

    public string Title => "Executable memory region with no backing file";

    public int DefaultBaseWeight => 65;

    public IReadOnlyList<DetectionEvent> Evaluate(DetectionRuleContext context)
    {
        var events = new List<DetectionEvent>();

        foreach (var region in context.Snapshot.MemoryRegions)
        {
            if (!string.Equals(region.RegionType, PrivateRegion, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!region.IsExecutable || region.IsBackedByFile)
            {
                continue;
            }

            events.Add(context.CreateEvent(RuleId, context.BaseWeight(RuleId, DefaultBaseWeight), new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["regionBase"] = $"0x{region.BaseAddress:X}",
                ["regionSize"] = region.Size.ToString(),
                ["protection"] = region.Protection,
                ["regionType"] = region.RegionType,
                ["backingFile"] = region.BackingFile ?? string.Empty,
                ["signerTrust"] = "unknown",
            }));
        }

        return events;
    }
}
