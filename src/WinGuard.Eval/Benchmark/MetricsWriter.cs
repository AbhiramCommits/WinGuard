using System.Globalization;
using System.Text;
using System.Text.Json;
using WinGuard.Core.Serialization;

namespace WinGuard.Eval.Benchmark;

/// <summary>Writes the benchmark results as JSON (machine-readable) and Markdown (for the README).</summary>
public static class MetricsWriter
{
    public static async Task WriteAsync(BenchmarkResults results, string outputDirectory, CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);

        var jsonPath = Path.Combine(outputDirectory, "metrics.json");
        var markdownPath = Path.Combine(outputDirectory, "metrics.md");

        var json = JsonSerializer.Serialize(results, WinGuardJson.Indented);
        await File.WriteAllTextAsync(jsonPath, json + Environment.NewLine, ct).ConfigureAwait(false);

        await File.WriteAllTextAsync(markdownPath, RenderMarkdown(results), ct).ConfigureAwait(false);

        Console.WriteLine($"Wrote {jsonPath}");
        Console.WriteLine($"Wrote {markdownPath}");
    }

    public static string RenderMarkdown(BenchmarkResults results)
    {
        var invariant = CultureInfo.InvariantCulture;
        var builder = new StringBuilder();

        builder.AppendLine("# WinGuard benchmark results");
        builder.AppendLine();
        builder.AppendLine($"Run: **{results.Environment.RunTimestampUtc}**  ");
        builder.AppendLine($"Machine: `{results.Environment.MachineName}` — {results.Environment.OsDescription} "
            + $"({results.Environment.OsArchitecture}, {results.Environment.ProcessorCount} CPUs)  ");
        builder.AppendLine($"Runtime: {results.Environment.FrameworkDescription} (`{results.Environment.RuntimeIdentifier}`)  ");
        builder.AppendLine($"Telemetry source: `{results.Environment.TelemetrySource}` — {results.Environment.DetectorPlatformNote}");
        builder.AppendLine();

        builder.AppendLine("## Corpus");
        builder.AppendLine();
        builder.AppendLine("| Corpus | Snapshots | Tampered |");
        builder.AppendLine("| --- | ---: | ---: |");
        builder.AppendLine($"| `labeled.jsonl` | {results.LabeledCorpusSnapshots} | {results.LabeledCorpusTamperedSnapshots} |");
        builder.AppendLine($"| `benign.jsonl` | {results.BenignCorpusSnapshots} | 0 |");
        builder.AppendLine();

        builder.AppendLine("## Detection quality (per rule)");
        builder.AppendLine();
        builder.AppendLine("| Rule | TP | FP | FN | Precision | Recall | F1 |");
        builder.AppendLine("| --- | ---: | ---: | ---: | ---: | ---: | ---: |");

        foreach (var rule in results.PerRule)
        {
            builder.AppendLine($"| {rule.RuleId} | {rule.TruePositives} | {rule.FalsePositives} | {rule.FalseNegatives} "
                + $"| {F(rule.Precision)} | {F(rule.Recall)} | {F(rule.F1)} |");
        }

        var overall = results.Overall;
        builder.AppendLine($"| **overall (micro)** | **{overall.TruePositives}** | **{overall.FalsePositives}** "
            + $"| **{overall.FalseNegatives}** | **{F(overall.Precision)}** | **{F(overall.Recall)}** | **{F(overall.F1)}** |");
        builder.AppendLine();

        builder.AppendLine("## False positives on the benign corpus");
        builder.AppendLine();
        builder.AppendLine($"- benign snapshots: **{results.BenignCorpusSnapshots}**");
        builder.AppendLine($"- false-positive findings: **{results.BenignFalsePositives}**");
        builder.AppendLine($"- false-positive rate (findings / (snapshots x rules)): **{results.BenignFalsePositiveRate.ToString("P4", invariant)}**");
        builder.AppendLine($"- true negatives: {results.BenignTrueNegatives}");
        builder.AppendLine();

        builder.AppendLine("## Performance");
        builder.AppendLine();
        builder.AppendLine("| Metric | Value |");
        builder.AppendLine("| --- | ---: |");
        builder.AppendLine($"| Detection latency p50 | {results.DetectionLatency.P50Ms.ToString("F3", invariant)} ms |");
        builder.AppendLine($"| Detection latency p95 | {results.DetectionLatency.P95Ms.ToString("F3", invariant)} ms |");
        builder.AppendLine($"| Detection latency p99 | {results.DetectionLatency.P99Ms.ToString("F3", invariant)} ms |");
        builder.AppendLine($"| Detection latency mean | {results.DetectionLatency.MeanMs.ToString("F3", invariant)} ms |");
        builder.AppendLine($"| Detection latency max | {results.DetectionLatency.MaxMs.ToString("F3", invariant)} ms |");
        builder.AppendLine($"| Detection throughput | {results.DetectionThroughputSnapshotsPerSecond.ToString("F0", invariant)} snapshots/s |");
        builder.AppendLine($"| Ingest throughput (events + observations) | {results.IngestThroughputEventsPerSecond.ToString("F0", invariant)} items/s |");
        builder.AppendLine($"| Ingested detection events | {results.IngestedDetectionEvents} |");
        builder.AppendLine($"| Ingested observations | {results.IngestedObservations} |");
        builder.AppendLine($"| Managed heap high-water mark | {results.ManagedHeapHighWaterMarkMb.ToString("F2", invariant)} MB |");
        builder.AppendLine($"| Process working set high-water mark | "
            + (results.ProcessWorkingSetAvailable ? results.ProcessWorkingSetHighWaterMarkMb.ToString("F2", invariant) + " MB" : "not available on this OS") + " |");
        builder.AppendLine($"| Total allocated (managed) | {(results.TotalAllocatedBytes / (1024.0 * 1024.0)).ToString("F1", invariant)} MB |");
        builder.AppendLine();

        builder.AppendLine("## Test suite");
        builder.AppendLine();
        builder.AppendLine(results.TestCount > 0
            ? $"- tests passing at the time of this run: **{results.TestCount}**"
            : "- test count: not recorded for this run (pass `--test-count N` to `benchmark`)");
        builder.AppendLine();

        if (!string.IsNullOrWhiteSpace(results.Notes))
        {
            builder.AppendLine("## Notes");
            builder.AppendLine();
            builder.AppendLine(results.Notes);
            builder.AppendLine();
        }

        return builder.ToString();
    }

    private static string F(double value) => value.ToString("F4", CultureInfo.InvariantCulture);
}
