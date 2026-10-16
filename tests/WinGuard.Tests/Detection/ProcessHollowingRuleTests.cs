using WinGuard.Core.Detection;
using WinGuard.Core.Detection.Rules;

namespace WinGuard.Tests.Detection;

public sealed class ProcessHollowingRuleTests
{
    private readonly ProcessHollowingRule _rule = new();

    [Fact]
    public void FlagsImageBaseMismatch()
    {
        var snapshot = DetectionTestData.Game() with
        {
            ImageBaseAddress = 0x00007FF6_00021000,
        };

        var events = _rule.Evaluate(DetectionTestData.Context(snapshot));

        var detection = Assert.Single(events);
        Assert.Equal(RuleIds.ProcessHollowing, detection.RuleId);
        Assert.Equal("true", detection.Evidence["baseMismatch"]);
        Assert.Equal("false", detection.Evidence["sizeMismatch"]);
    }

    [Fact]
    public void FlagsImageSizeMismatch()
    {
        var snapshot = DetectionTestData.Game() with
        {
            PebImageSize = 0x00220000,
        };

        var events = _rule.Evaluate(DetectionTestData.Context(snapshot));

        Assert.Single(events);
        Assert.Equal("true", events[0].Evidence["sizeMismatch"]);
    }

    [Fact]
    public void IgnoresConsistentHeaders()
    {
        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(DetectionTestData.Game())));
    }

    [Fact]
    public void IgnoresSnapshotsWhereTheOnDiskImageWasNotRead()
    {
        var snapshot = DetectionTestData.Game() with
        {
            OnDiskImageBase = 0,
            OnDiskImageSize = 0,
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }
}
