using WinGuard.Core.Models;

namespace WinGuard.Core.Detection.Rules;

/// <summary>
/// R006 — the image base or size reported by the PEB disagrees with the on-disk
/// PE optional header, the signature of process hollowing / image replacement.
/// </summary>
public sealed class ProcessHollowingRule : IDetectionRule
{
    public string RuleId => RuleIds.ProcessHollowing;

    public string Title => "PEB image base/size disagrees with the on-disk PE headers";

    public int DefaultBaseWeight => 70;

    public IReadOnlyList<DetectionEvent> Evaluate(DetectionRuleContext context)
    {
        var snapshot = context.Snapshot;

        // Nothing to compare against: the on-disk image was not readable.
        if (snapshot.OnDiskImageBase == 0 || snapshot.OnDiskImageSize == 0)
        {
            return [];
        }

        var baseMismatch = snapshot.ImageBaseAddress != snapshot.OnDiskImageBase;
        var sizeMismatch = snapshot.PebImageSize != snapshot.OnDiskImageSize;

        if (!baseMismatch && !sizeMismatch)
        {
            return [];
        }

        return
        [
            context.CreateEvent(RuleId, context.BaseWeight(RuleId, DefaultBaseWeight), new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["imagePath"] = snapshot.ImagePath,
                ["imageBaseAddress"] = $"0x{snapshot.ImageBaseAddress:X}",
                ["onDiskImageBase"] = $"0x{snapshot.OnDiskImageBase:X}",
                ["pebImageSize"] = snapshot.PebImageSize.ToString(),
                ["onDiskImageSize"] = snapshot.OnDiskImageSize.ToString(),
                ["baseMismatch"] = baseMismatch ? "true" : "false",
                ["sizeMismatch"] = sizeMismatch ? "true" : "false",
                ["signerTrust"] = "unknown",
            }),
        ];
    }
}
