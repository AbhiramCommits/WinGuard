using WinGuard.Core.Detection;
using WinGuard.Core.Models;

namespace WinGuard.Tests.Detection;

public sealed class SeverityScorerTests
{
    private static DetectionEvent Event(string ruleId, int severity, string signerTrust = "unknown", int pid = 4242)
        => new()
        {
            RuleId = ruleId,
            Severity = severity,
            HostId = "host-test",
            Pid = pid,
            ProcessName = "cs2.exe",
            Evidence = new Dictionary<string, string>(StringComparer.Ordinal) { ["signerTrust"] = signerTrust },
            ObservedAtUtc = DateTimeOffset.UnixEpoch,
        };

    [Fact]
    public void CorrelationPushesSeverityIntoTheCriticalBucket()
    {
        var options = new DetectionOptions();
        var scorer = new SeverityScorer(options);
        var context = DetectionTestData.Context(DetectionTestData.Game(), options);

        var events = new List<DetectionEvent>
        {
            Event(RuleIds.InjectedModulePath, 60, "untrusted"),
            Event(RuleIds.RwxPrivateRegion, 55, "unknown"),
        };

        var scored = scorer.Score(events, context);

        // 60 (base) + 5 (untrusted signer) + 10 (protected process) + 8 (one extra rule).
        var injected = scored.Single(e => e.RuleId == RuleIds.InjectedModulePath);
        Assert.Equal(83, injected.Severity);
        Assert.Equal("Critical", injected.SeverityBucket);

        // Same correlation bonus, but no signer surcharge.
        var rwx = scored.Single(e => e.RuleId == RuleIds.RwxPrivateRegion);
        Assert.Equal(73, rwx.Severity);
        Assert.Equal("High", rwx.SeverityBucket);
    }

    [Fact]
    public void SingleRuleInProtectedProcessDoesNotReachCritical()
    {
        var options = new DetectionOptions();
        var scorer = new SeverityScorer(options);
        var context = DetectionTestData.Context(DetectionTestData.Game(), options);

        var scored = scorer.Score([Event(RuleIds.InjectedModulePath, 60)], context);

        Assert.Equal(70, scored[0].Severity);
        Assert.Equal("High", scored[0].SeverityBucket);
    }

    [Fact]
    public void UntrustedSignerAddsAndTrustedSignerRelieves()
    {
        var options = new DetectionOptions();
        var scorer = new SeverityScorer(options);
        var context = DetectionTestData.Context(DetectionTestData.Game(), options);

        var untrusted = scorer.Score([Event(RuleIds.PatchedCodeSection, 75, "untrusted")], context)[0];
        var trusted = scorer.Score([Event(RuleIds.PatchedCodeSection, 75, "trusted")], context)[0];

        Assert.Equal(90, untrusted.Severity); // 75 + 10 (protected) + 5 (untrusted)
        Assert.Equal(80, trusted.Severity);   // 75 + 10 (protected) - 5 (trusted)
        Assert.Equal(10, untrusted.Severity - trusted.Severity);
    }

    [Fact]
    public void CorrelationBonusIsCapped()
    {
        var options = new DetectionOptions();
        var scorer = new SeverityScorer(options);
        var context = DetectionTestData.Context(DetectionTestData.Game(), options);

        var events = new List<DetectionEvent>
        {
            Event(RuleIds.UnsignedModuleLoaded, 45),
            Event(RuleIds.InjectedModulePath, 60),
            Event(RuleIds.UnbackedExecutableMemory, 65),
            Event(RuleIds.PatchedCodeSection, 75),
            Event(RuleIds.RwxPrivateRegion, 55),
            Event(RuleIds.ProcessHollowing, 70),
        };

        var scored = scorer.Score(events, context);

        // 6 distinct rules would be 5 * 8 = 40, capped at MaxCorrelationBonus (25).
        var check = scored.Single(e => e.RuleId == RuleIds.UnsignedModuleLoaded);
        Assert.Equal(45 + options.ProtectedProcessBonus + options.MaxCorrelationBonus, check.Severity);
    }

    [Fact]
    public void SeverityIsClampedToHundred()
    {
        var options = new DetectionOptions();
        var scorer = new SeverityScorer(options);
        var context = DetectionTestData.Context(DetectionTestData.Game(), options);

        var events = new List<DetectionEvent>
        {
            Event(RuleIds.PatchedCodeSection, 95, "untrusted"),
            Event(RuleIds.InjectedModulePath, 90, "untrusted"),
        };

        var scored = scorer.Score(events, context);

        Assert.All(scored, e => Assert.Equal(100, e.Severity));
        Assert.All(scored, e => Assert.Equal("Critical", e.SeverityBucket));
    }

    [Theory]
    [InlineData(10, "Low")]
    [InlineData(30, "Medium")]
    [InlineData(60, "High")]
    [InlineData(95, "Critical")]
    public void BucketsMapFromScore(int score, string expectedBucket)
    {
        var bucket = SeverityBuckets.FromScore(score, new DetectionOptions());
        Assert.Equal(expectedBucket, SeverityBuckets.Name(bucket));
    }

    [Fact]
    public void ScoreBatchGroupsCorrelationByProcess()
    {
        var options = new DetectionOptions();
        var scorer = new SeverityScorer(options);

        var batch = new List<(DetectionEvent Event, bool IsProtected)>
        {
            (Event(RuleIds.InjectedModulePath, 60, pid: 1), true),
            (Event(RuleIds.RwxPrivateRegion, 55, pid: 1), true),
            (Event(RuleIds.UnbackedExecutableMemory, 65, pid: 2), false),
            (Event(RuleIds.PatchedCodeSection, 75, pid: 2), false),
        };

        var scored = scorer.ScoreBatch(batch.Select(x => (x.Event, x.IsProtected)));

        // pid 1: protected, two rules => 60 + 10 + 8 = 78.
        Assert.Equal(78, scored[0].Severity);
        // pid 2: unprotected, two rules => 65 + 0 + 8 = 73.
        Assert.Equal(73, scored[2].Severity);
    }
}
