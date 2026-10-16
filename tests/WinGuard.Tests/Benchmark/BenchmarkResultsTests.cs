using System.Text.Json;
using WinGuard.Core.Detection;
using WinGuard.Eval.Benchmark;

namespace WinGuard.Tests.Benchmark;

/// <summary>
/// Locks the committed benchmark results: the numbers in <c>results/metrics.json</c>
/// must still be reproducible from the current code, and detection quality must
/// not regress below the measured value.
/// </summary>
public sealed class BenchmarkResultsTests
{
    /// <summary>Allowed slack below the recorded F1 before the suite fails.</summary>
    private const double F1Tolerance = 0.02;

    private static BenchmarkResults Recorded()
    {
        var path = Path.Combine(TestPaths.ResultsDirectory, "metrics.json");
        Assert.True(File.Exists(path), $"Missing {path}. Run: dotnet run -c Release --project src/WinGuard.Eval -- benchmark");

        var json = File.ReadAllText(path);
        var results = JsonSerializer.Deserialize<BenchmarkResults>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        });

        Assert.NotNull(results);
        return results!;
    }

    [Fact]
    public void MetricsFileIsCompleteAndSelfDescribing()
    {
        var results = Recorded();

        Assert.Equal(RuleIds.All.Length + 1, results.PerRule.Count + 1); // per-rule rows + overall
        Assert.True(results.LabeledCorpusSnapshots >= 2000);
        Assert.True(results.LabeledCorpusTamperedSnapshots > 0);
        Assert.True(results.BenignCorpusSnapshots > 0);
        Assert.True(results.DetectionLatency.SampleCount >= 2000);
        Assert.False(string.IsNullOrWhiteSpace(results.Environment.RunTimestampUtc));
        Assert.False(string.IsNullOrWhiteSpace(results.Environment.FrameworkDescription));
        Assert.False(string.IsNullOrWhiteSpace(results.Environment.TelemetrySource));
        Assert.True(results.IngestedDetectionEvents > 0);
        Assert.True(results.IngestThroughputEventsPerSecond > 0);
        Assert.True(results.ManagedHeapHighWaterMarkMb > 0);
        Assert.True(results.TestCount > 0, "results/metrics.json should record the test count used for the README.");
    }

    [Fact]
    public void EveryRuleIsEvaluatedAndPresent()
    {
        var results = Recorded();

        foreach (var ruleId in RuleIds.All)
        {
            var rule = results.PerRule.SingleOrDefault(r => r.RuleId == ruleId);
            Assert.NotNull(rule);
            Assert.True(rule!.TruePositives > 0, $"{ruleId} had no true positives in the recorded run.");
        }
    }

    [Fact]
    public void RecordedPrecisionRecallAndF1MatchAFreshEvaluation()
    {
        var results = Recorded();
        var fresh = CorpusEvaluator.EvaluateFile(TestPaths.CorpusFile("labeled.jsonl"));

        Assert.Equal(results.Overall.TruePositives, fresh.Overall.TruePositives);
        Assert.Equal(results.Overall.FalsePositives, fresh.Overall.FalsePositives);
        Assert.Equal(results.Overall.FalseNegatives, fresh.Overall.FalseNegatives);
        Assert.Equal(results.Overall.Precision, fresh.Overall.Precision, 6);
        Assert.Equal(results.Overall.Recall, fresh.Overall.Recall, 6);
        Assert.Equal(results.Overall.F1, fresh.Overall.F1, 6);
    }

    [Fact]
    public void OverallF1DoesNotRegressBelowTheRecordedValue()
    {
        var results = Recorded();
        var fresh = CorpusEvaluator.EvaluateFile(TestPaths.CorpusFile("labeled.jsonl"));

        Assert.True(
            fresh.Overall.F1 >= results.Overall.F1 - F1Tolerance,
            $"F1 regressed: recorded {results.Overall.F1:F4}, now {fresh.Overall.F1:F4} (tolerance {F1Tolerance}).");
    }

    [Fact]
    public void BenignFalsePositiveRateDoesNotRegress()
    {
        var results = Recorded();
        var fresh = CorpusEvaluator.EvaluateFile(TestPaths.CorpusFile("benign.jsonl"));

        Assert.True(
            fresh.Overall.FalsePositives <= results.BenignFalsePositives,
            $"Benign false positives increased from {results.BenignFalsePositives} to {fresh.Overall.FalsePositives}.");
    }

    [Fact]
    public void MarkdownReportIsGeneratedNextToTheJson()
    {
        var markdown = Path.Combine(TestPaths.ResultsDirectory, "metrics.md");
        Assert.True(File.Exists(markdown), $"Missing {markdown}.");

        var content = File.ReadAllText(markdown);
        Assert.Contains("## Detection quality (per rule)", content, StringComparison.Ordinal);
        Assert.Contains("| Rule | TP | FP | FN | Precision | Recall | F1 |", content, StringComparison.Ordinal);
        Assert.Contains("Detection latency p95", content, StringComparison.Ordinal);
        Assert.Contains("false-positive rate", content, StringComparison.OrdinalIgnoreCase);
    }
}
