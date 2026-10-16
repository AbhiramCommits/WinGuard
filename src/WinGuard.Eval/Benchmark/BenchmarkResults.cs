namespace WinGuard.Eval.Benchmark;

/// <summary>Detection-quality metrics for one rule (or the aggregate), as written to results/.</summary>
public sealed record RuleMetricsResult(
    string RuleId,
    int TruePositives,
    int FalsePositives,
    int FalseNegatives,
    double Precision,
    double Recall,
    double F1);

/// <summary>Latency distribution of a single-snapshot detection pass, in milliseconds.</summary>
public sealed record LatencyResult(
    double P50Ms,
    double P95Ms,
    double P99Ms,
    double MeanMs,
    double MaxMs,
    int SampleCount);

/// <summary>Environment description recorded alongside the numbers.</summary>
public sealed record EnvironmentInfo(
    string RunTimestampUtc,
    string MachineName,
    string OsDescription,
    string OsArchitecture,
    string ProcessArchitecture,
    string FrameworkDescription,
    string RuntimeIdentifier,
    int ProcessorCount,
    string TelemetrySource,
    string DetectorPlatformNote);

/// <summary>
/// Everything the benchmark measures. Written verbatim to results/metrics.json;
/// results/metrics.md is generated from it.
/// </summary>
public sealed record BenchmarkResults(
    EnvironmentInfo Environment,
    string LabeledCorpusPath,
    string BenignCorpusPath,
    int LabeledCorpusSnapshots,
    int LabeledCorpusTamperedSnapshots,
    int LabeledRuleInstances,
    IReadOnlyList<RuleMetricsResult> PerRule,
    RuleMetricsResult Overall,
    int BenignCorpusSnapshots,
    int BenignFalsePositives,
    int BenignTrueNegatives,
    double BenignFalsePositiveRate,
    LatencyResult DetectionLatency,
    double DetectionThroughputSnapshotsPerSecond,
    double DetectionPhaseSeconds,
    int IngestedDetectionEvents,
    int IngestedObservations,
    double IngestThroughputEventsPerSecond,
    double IngestPhaseSeconds,
    double ManagedHeapHighWaterMarkMb,
    long TotalAllocatedBytes,
    double ProcessWorkingSetHighWaterMarkMb,
    bool ProcessWorkingSetAvailable,
    int TestCount,
    string Notes);
