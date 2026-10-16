using WinGuard.Core.Detection;
using WinGuard.Core.Models;

namespace WinGuard.Tests.Detection;

public sealed class DetectionEngineTests
{
    [Fact]
    public void EmitsScoredEventsForATamperedSnapshot()
    {
        var engine = DetectionEngine.CreateDefault();

        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.SignedModule(), DetectionTestData.UnsignedModule(@"C:\Users\Public\payload.dll")],
            MemoryRegions = [DetectionTestData.UnbackedExecutableRegion(protection: "PAGE_EXECUTE_READWRITE", writable: true)],
        };

        var events = engine.Evaluate(snapshot);
        var rules = events.Select(e => e.RuleId).ToHashSet(StringComparer.Ordinal);

        Assert.Contains(RuleIds.UnsignedModuleLoaded, rules);
        Assert.Contains(RuleIds.InjectedModulePath, rules);
        Assert.Contains(RuleIds.UnbackedExecutableMemory, rules);
        Assert.Contains(RuleIds.RwxPrivateRegion, rules);
        Assert.All(events, e => Assert.InRange(e.Severity, 1, 100));
        Assert.All(events, e => Assert.False(string.IsNullOrEmpty(e.SeverityBucket)));
    }

    [Fact]
    public void EmitsNothingForABenignSnapshot()
    {
        var engine = DetectionEngine.CreateDefault();

        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.SignedModule()],
            MemoryRegions = [DetectionTestData.ImageRegion(), DetectionTestData.PrivateHeapRegion()],
        };

        Assert.Empty(engine.Evaluate(snapshot));
    }

    [Fact]
    public void SuppressesDuplicateFindingsWithinTheDedupeWindow()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var clock = new MutableClock(now);

        var engine = DetectionEngine.CreateDefault(new DetectionOptions { DedupeWindowSeconds = 60 }, clock: () => clock.Now);

        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.SignedModule(), DetectionTestData.UnsignedModule(@"C:\Users\Public\payload.dll")],
        };

        var first = engine.Evaluate(snapshot);
        Assert.NotEmpty(first);

        var second = engine.Evaluate(snapshot);
        Assert.Empty(second);

        // Past the window, the same finding is reported again.
        clock.Now = now.AddSeconds(61);
        var third = engine.Evaluate(snapshot);
        Assert.Equal(first.Count, third.Count);
    }

    [Fact]
    public void DedupeIsScopedToHostProcessRuleAndEvidence()
    {
        var engine = DetectionEngine.CreateDefault();

        var baseline = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.UnsignedModule(@"C:\Windows\System32\drivers\evil.sys")],
        };

        Assert.Single(engine.Evaluate(baseline));

        // A different PID is a different finding.
        Assert.Single(engine.Evaluate(baseline with { Pid = 9999 }));

        // A different module path yields different evidence.
        var other = baseline with
        {
            Modules = [DetectionTestData.UnsignedModule(@"C:\Windows\System32\drivers\other.sys")],
        };
        Assert.Single(engine.Evaluate(other));
    }

    [Fact]
    public void DisabledRulesDoNotRun()
    {
        var options = new DetectionOptions();
        options.Rules[RuleIds.UnsignedModuleLoaded] = new RuleSettings { Enabled = false, BaseWeight = 45 };
        var engine = DetectionEngine.CreateDefault(options);

        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.UnsignedModule(@"C:\Windows\System32\drivers\evil.sys")],
        };

        Assert.Empty(engine.Evaluate(snapshot));
    }

    [Fact]
    public void ConfiguredWeightsOverrideBuiltInWeights()
    {
        var options = new DetectionOptions();
        options.Rules[RuleIds.UnsignedModuleLoaded] = new RuleSettings { Enabled = true, BaseWeight = 90 };
        var engine = DetectionEngine.CreateDefault(options);

        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.UnsignedModule(@"C:\Windows\System32\drivers\evil.sys")],
        };

        var detection = Assert.Single(engine.Evaluate(snapshot));
        Assert.Equal("Critical", detection.SeverityBucket);
        Assert.True(detection.Severity > 90);
    }

    [Fact]
    public void EvaluateStreamPreservesSnapshotOrder()
    {
        var engine = DetectionEngine.CreateDefault();

        var snapshots = new[]
        {
            DetectionTestData.NonGame("notepad.exe"),
            DetectionTestData.Game(),
            DetectionTestData.NonGame("calc.exe"),
        };

        var streamed = engine.EvaluateStream(snapshots).ToList();

        Assert.Equal(3, streamed.Count);
        Assert.Equal(snapshots[1].Pid, streamed[1].Snapshot.Pid);
    }

    [Fact]
    public void FingerprintIsStableRegardlessOfEvidenceOrdering()
    {
        var a = new DetectionEvent
        {
            RuleId = RuleIds.InjectedModulePath,
            Severity = 60,
            HostId = "h",
            Pid = 1,
            Evidence = new Dictionary<string, string> { ["b"] = "2", ["a"] = "1" },
        };

        var b = a with
        {
            Evidence = new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" },
        };

        Assert.Equal(EvidenceHasher.Fingerprint(a), EvidenceHasher.Fingerprint(b));
    }

    private sealed class MutableClock
    {
        public MutableClock(DateTimeOffset now) => Now = now;

        public DateTimeOffset Now { get; set; }
    }
}
