using WinGuard.Core.Detection;
using WinGuard.Core.Telemetry;

namespace WinGuard.Tests.Telemetry;

/// <summary>
/// Guards the committed corpus: the benchmark results are only meaningful if the
/// corpus actually contains the promised shape (counts, label distribution,
/// known rule ids).
/// </summary>
public sealed class CorpusIntegrityTests
{
    private static readonly CancellationToken None = CancellationToken.None;

    [Fact]
    public async Task LabeledCorpusHasAtLeastTwoThousandSnapshotsAcrossManyHosts()
    {
        var snapshots = await ReadAllAsync("labeled.jsonl");

        Assert.True(snapshots.Count >= 2000, $"Expected >=2000 labeled snapshots, found {snapshots.Count}.");
        Assert.True(snapshots.Select(s => s.HostId).Distinct().Count() >= 30);
    }

    [Fact]
    public async Task TamperedFractionIsRoughlyFifteenPercent()
    {
        var snapshots = await ReadAllAsync("labeled.jsonl");
        var tampered = snapshots.Count(s => s.Labels.Count > 0);
        var fraction = (double)tampered / snapshots.Count;

        Assert.InRange(fraction, 0.10, 0.20);
    }

    [Fact]
    public async Task EveryLabelIsARecognisedRuleId()
    {
        var snapshots = await ReadAllAsync("labeled.jsonl");

        foreach (var snapshot in snapshots)
        {
            foreach (var label in snapshot.Labels)
            {
                Assert.Contains(label, RuleIds.All);
            }
        }
    }

    [Fact]
    public async Task AllSixRulesAppearInTheCorpus()
    {
        var snapshots = await ReadAllAsync("labeled.jsonl");
        var labels = snapshots.SelectMany(s => s.Labels).ToHashSet(StringComparer.Ordinal);

        foreach (var ruleId in RuleIds.All)
        {
            Assert.Contains(ruleId, labels);
        }
    }

    [Fact]
    public async Task BenignCorpusCarriesNoLabels()
    {
        var snapshots = await ReadAllAsync("benign.jsonl");

        Assert.True(snapshots.Count >= 500, $"Expected >=500 benign snapshots, found {snapshots.Count}.");
        Assert.All(snapshots, s => Assert.Empty(s.Labels));
    }

    private static async Task<List<Core.Models.ProcessSnapshot>> ReadAllAsync(string file)
    {
        var snapshots = new List<Core.Models.ProcessSnapshot>();
        await foreach (var snapshot in TelemetryJsonl.ReadAsync(TestPaths.CorpusFile(file), None))
        {
            snapshots.Add(snapshot);
        }

        return snapshots;
    }
}
