using System.Diagnostics;
using System.Runtime.InteropServices;
using WinGuard.Core;
using WinGuard.Core.Contracts;
using WinGuard.Core.Detection;
using WinGuard.Core.Models;

namespace WinGuard.Eval.Benchmark;

/// <summary>
/// The detection benchmark: replays the committed corpus through the real
/// detection engine and the real API ingest path, then measures accuracy,
/// latency, throughput and memory.
/// </summary>
public sealed class BenchmarkRunner
{
    private readonly BenchmarkOptions _options;
    private readonly Action<string> _log;

    public BenchmarkRunner(BenchmarkOptions options, Action<string>? log = null)
    {
        _options = options;
        _log = log ?? Console.WriteLine;
    }

    public async Task<BenchmarkResults> RunAsync(CancellationToken ct = default)
    {
        var labeledSnapshots = TelemetryJsonlRead(_options.LabeledCorpusPath);
        var benignSnapshots = TelemetryJsonlRead(_options.BenignCorpusPath);

        _log($"Loaded {labeledSnapshots.Count} labeled and {benignSnapshots.Count} benign snapshots.");

        // ---------------------------------------------------------------
        // 1. Detection accuracy against ground truth
        // ---------------------------------------------------------------
        var options = new DetectionOptions();

        // The engine's dedupe cache is a live-stream concern; replaying a whole
        // corpus with it enabled would suppress genuine repeats.
        options.DedupeWindowSeconds = 0;

        var evaluator = new CorpusEvaluator(DetectionEngine.CreateDefault(options));
        var labeled = evaluator.Evaluate(labeledSnapshots);
        var benign = evaluator.Evaluate(benignSnapshots);

        _log($"Detection: P={labeled.Overall.Precision:F4} R={labeled.Overall.Recall:F4} F1={labeled.Overall.F1:F4}; "
            + $"benign false positives={benign.Overall.FalsePositives}");

        // ---------------------------------------------------------------
        // 2. Latency + memory of a single-snapshot detection pass
        // ---------------------------------------------------------------
        var latencyEngine = DetectionEngine.CreateDefault(new DetectionOptions { DedupeWindowSeconds = 0 });

        // Warm up (JIT, tiered compilation, first-touch allocations) so the
        // measured percentiles describe steady state, then measure fresh.
        foreach (var snapshot in labeledSnapshots.Take(Math.Min(200, labeledSnapshots.Count)))
        {
            latencyEngine.Evaluate(snapshot);
        }

        var heapHighWater = GC.GetTotalMemory(forceFullCollection: true);
        var workingSet = TryGetWorkingSet();
        var workingSetHighWater = workingSet ?? 0;
        var workingSetAvailable = workingSet is not null;

        var latencies = new List<double>(labeledSnapshots.Count);
        var detectionPhase = Stopwatch.StartNew();

        foreach (var snapshot in labeledSnapshots)
        {
            ct.ThrowIfCancellationRequested();

            var start = Stopwatch.GetTimestamp();
            latencyEngine.Evaluate(snapshot);
            var elapsedMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            latencies.Add(elapsedMs);

            if (latencies.Count % 200 == 0)
            {
                heapHighWater = Math.Max(heapHighWater, GC.GetTotalMemory(forceFullCollection: false));
                if (workingSetAvailable)
                {
                    workingSetHighWater = Math.Max(workingSetHighWater, TryGetWorkingSet() ?? workingSetHighWater);
                }
            }
        }

        detectionPhase.Stop();

        heapHighWater = Math.Max(heapHighWater, GC.GetTotalMemory(forceFullCollection: false));
        var latency = Percentiles(latencies);
        var detectionThroughput = labeledSnapshots.Count / Math.Max(detectionPhase.Elapsed.TotalSeconds, 1e-9);

        _log($"Detection latency p50={latency.P50Ms:F3}ms p95={latency.P95Ms:F3}ms p99={latency.P99Ms:F3}ms; "
            + $"throughput={detectionThroughput:F0} snapshots/s");

        // ---------------------------------------------------------------
        // 3. Real API ingest path
        // ---------------------------------------------------------------
        var events = new List<DetectionEventDto>();
        var observations = new List<ProcessObservationDto>();
        var ingestEngine = DetectionEngine.CreateDefault(new DetectionOptions { DedupeWindowSeconds = 0 });

        foreach (var snapshot in labeledSnapshots)
        {
            var detected = ingestEngine.Evaluate(snapshot);
            if (detected.Count == 0)
            {
                continue;
            }

            events.AddRange(detected.Select(e => e.ToDto()));
            observations.Add(snapshot.ToObservationDto());
        }

        await using var api = await ApiIngestBenchmark.StartAsync().ConfigureAwait(false);
        var (ingestSeconds, acceptedEvents, acceptedObservations) = await api
            .IngestAsync(events, observations, _options.IngestBatchSize, ct)
            .ConfigureAwait(false);

        var ingestedTotal = acceptedEvents + acceptedObservations;
        var ingestThroughput = ingestedTotal / Math.Max(ingestSeconds, 1e-9);

        var roundTripped = await api.CountHostDetectionsAsync(ct).ConfigureAwait(false);

        _log($"Ingest: {acceptedEvents} events + {acceptedObservations} observations in {ingestSeconds:F2}s "
            + $"= {ingestThroughput:F0} items/s (read back {roundTripped} rows)");

        workingSet = TryGetWorkingSet();
        if (workingSetAvailable && workingSet is not null)
        {
            workingSetHighWater = Math.Max(workingSetHighWater, workingSet.Value);
        }

        // ---------------------------------------------------------------
        // 4. Assemble the results
        // ---------------------------------------------------------------
        var environment = new EnvironmentInfo(
            DateTimeOffset.UtcNow.ToString("O"),
            Environment.MachineName,
            RuntimeInformation.OSDescription,
            RuntimeInformation.OSArchitecture.ToString(),
            RuntimeInformation.ProcessArchitecture.ToString(),
            RuntimeInformation.FrameworkDescription,
            RuntimeInformation.RuntimeIdentifier,
            Environment.ProcessorCount,
            DetectedTelemetrySource,
            DetectedTelemetrySource == "Win32EtwTelemetrySource"
                ? "Real Win32/ETW collector (native winguard_native.dll)."
                : "Corpus replay: the Win32/ETW collector requires Windows and is compiled but not exercised on this host.");

        var benignRuleSlots = benign.SnapshotCount * RuleIds.All.Length;
        var benignFalsePositiveRate = benignRuleSlots == 0
            ? 0
            : (double)benign.Overall.FalsePositives / benignRuleSlots;

        return new BenchmarkResults(
            environment,
            Path.GetFullPath(_options.LabeledCorpusPath),
            Path.GetFullPath(_options.BenignCorpusPath),
            labeled.SnapshotCount,
            labeled.TamperedSnapshotCount,
            labeled.LabeledRuleInstances,
            labeled.PerRule.Select(ToResult).ToList(),
            ToResult(labeled.Overall),
            benign.SnapshotCount,
            benign.Overall.FalsePositives,
            benign.TrueNegatives,
            benignFalsePositiveRate,
            latency,
            detectionThroughput,
            detectionPhase.Elapsed.TotalSeconds,
            acceptedEvents,
            acceptedObservations,
            ingestThroughput,
            ingestSeconds,
            BytesToMegabytes(heapHighWater),
            GC.GetTotalAllocatedBytes(precise: false),
            BytesToMegabytes((long)workingSetHighWater),
            workingSetAvailable,
            _options.TestCount,
            _options.Notes);
    }

    private static RuleMetricsResult ToResult(RuleMetrics metrics)
        => new(
            metrics.RuleId,
            metrics.TruePositives,
            metrics.FalsePositives,
            metrics.FalseNegatives,
            metrics.Precision,
            metrics.Recall,
            metrics.F1);

    private static List<ProcessSnapshot> TelemetryJsonlRead(string path)
        => Core.Telemetry.TelemetryJsonl.ReadLines(path).ToList();

    private static LatencyResult Percentiles(List<double> samples)
    {
        if (samples.Count == 0)
        {
            return new LatencyResult(0, 0, 0, 0, 0, 0);
        }

        var sorted = samples.OrderBy(value => value).ToArray();

        return new LatencyResult(
            NearestRank(sorted, 50),
            NearestRank(sorted, 95),
            NearestRank(sorted, 99),
            sorted.Average(),
            sorted[^1],
            sorted.Length);
    }

    private static double NearestRank(double[] sorted, double percentile)
    {
        var rank = (int)Math.Ceiling(percentile / 100.0 * sorted.Length);
        return sorted[Math.Clamp(rank - 1, 0, sorted.Length - 1)];
    }

    private static double? TryGetWorkingSet()
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            var bytes = process.WorkingSet64;
            return bytes > 0 ? bytes : null;
        }
        catch (Exception ex) when (ex is PlatformNotSupportedException or InvalidOperationException or NotSupportedException)
        {
            return null;
        }
    }

    private static double BytesToMegabytes(long bytes) => Math.Round(bytes / (1024.0 * 1024.0), 3);

    private static string DetectedTelemetrySource
        => RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "Win32EtwTelemetrySource"
            : "ReplayTelemetrySource";
}

/// <summary>Benchmark inputs.</summary>
public sealed class BenchmarkOptions
{
    public string LabeledCorpusPath { get; init; } = string.Empty;

    public string BenignCorpusPath { get; init; } = string.Empty;

    public int IngestBatchSize { get; init; } = 100;

    /// <summary>
    /// Number of tests in the suite at the time of the run. The benchmark can be
    /// told this with <c>--test-count</c> so results/metrics.json is self-contained.
    /// </summary>
    public int TestCount { get; init; }

    public string Notes { get; init; } = string.Empty;
}
