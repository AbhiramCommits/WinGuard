using WinGuard.Core.Detection;
using WinGuard.Core.Detection.Rules;

namespace WinGuard.Tests.Detection;

public sealed class RwxPrivateRegionRuleTests
{
    private readonly RwxPrivateRegionRule _rule = new();

    [Fact]
    public void FlagsRwxPrivateRegionInProtectedProcess()
    {
        var snapshot = DetectionTestData.Game() with
        {
            MemoryRegions = [DetectionTestData.UnbackedExecutableRegion(protection: "PAGE_EXECUTE_READWRITE", writable: true)],
        };

        var events = _rule.Evaluate(DetectionTestData.Context(snapshot));

        var detection = Assert.Single(events);
        Assert.Equal(RuleIds.RwxPrivateRegion, detection.RuleId);
        Assert.Equal("PAGE_EXECUTE_READWRITE", detection.Evidence["protection"]);
    }

    [Fact]
    public void FlagsRwxRegionWhenProcessIsProtectedByName()
    {
        var snapshot = DetectionTestData.Base("r5apex.exe", @"C:\Games\Apex\r5apex.exe", isProtected: false) with
        {
            MemoryRegions = [DetectionTestData.UnbackedExecutableRegion(protection: "PAGE_EXECUTE_READWRITE", writable: true)],
        };

        Assert.Single(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }

    [Fact]
    public void IgnoresRwxRegionsInUnprotectedProcesses()
    {
        var snapshot = DetectionTestData.NonGame() with
        {
            MemoryRegions = [DetectionTestData.UnbackedExecutableRegion(protection: "PAGE_EXECUTE_READWRITE", writable: true)],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }

    [Fact]
    public void IgnoresExecuteReadAndWritableNonExecutableRegions()
    {
        var snapshot = DetectionTestData.Game() with
        {
            MemoryRegions =
            [
                DetectionTestData.UnbackedExecutableRegion(protection: "PAGE_EXECUTE_READ"),
                DetectionTestData.PrivateHeapRegion(),
            ],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }
}
