using WinGuard.Core.Detection;
using WinGuard.Core.Detection.Rules;

namespace WinGuard.Tests.Detection;

public sealed class UnbackedExecutableMemoryRuleTests
{
    private readonly UnbackedExecutableMemoryRule _rule = new();

    [Fact]
    public void FlagsPrivateExecutableRegionWithNoBackingFile()
    {
        var snapshot = DetectionTestData.Game() with
        {
            MemoryRegions = [DetectionTestData.ImageRegion(), DetectionTestData.UnbackedExecutableRegion()],
        };

        var events = _rule.Evaluate(DetectionTestData.Context(snapshot));

        var detection = Assert.Single(events);
        Assert.Equal(RuleIds.UnbackedExecutableMemory, detection.RuleId);
        Assert.Equal("PAGE_EXECUTE_READ", detection.Evidence["protection"]);
    }

    [Fact]
    public void FlagsEachUnbackedExecutableRegion()
    {
        var snapshot = DetectionTestData.NonGame() with
        {
            MemoryRegions =
            [
                DetectionTestData.UnbackedExecutableRegion(0x1000),
                DetectionTestData.UnbackedExecutableRegion(0x9000),
            ],
        };

        Assert.Equal(2, _rule.Evaluate(DetectionTestData.Context(snapshot)).Count);
    }

    [Fact]
    public void IgnoresImageBackedAndNonExecutableRegions()
    {
        var snapshot = DetectionTestData.Game() with
        {
            MemoryRegions =
            [
                DetectionTestData.ImageRegion(),
                DetectionTestData.PrivateHeapRegion(),
            ],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }
}
