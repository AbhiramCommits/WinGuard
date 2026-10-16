namespace WinGuard.Eval.Benchmark;

/// <summary>Implements <c>dotnet run --project src/WinGuard.Eval -- benchmark</c>.</summary>
public static class BenchmarkCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct = default)
    {
        var labeled = RepoPaths.CorpusFile("labeled.jsonl");
        var benign = RepoPaths.CorpusFile("benign.jsonl");
        var output = RepoPaths.ResultsDirectory;
        var testCount = 0;
        var ingestBatchSize = 100;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--labeled" when i + 1 < args.Length:
                    labeled = Path.GetFullPath(args[++i]);
                    break;
                case "--benign" when i + 1 < args.Length:
                    benign = Path.GetFullPath(args[++i]);
                    break;
                case "--out" when i + 1 < args.Length:
                    output = Path.GetFullPath(args[++i]);
                    break;
                case "--test-count" when i + 1 < args.Length:
                    _ = int.TryParse(args[++i], out testCount);
                    break;
                case "--batch-size" when i + 1 < args.Length:
                    _ = int.TryParse(args[++i], out ingestBatchSize);
                    break;
            }
        }

        if (!File.Exists(labeled))
        {
            Console.Error.WriteLine($"Labeled corpus not found: {labeled}");
            Console.Error.WriteLine("Run: dotnet run --project src/WinGuard.Eval -- gen-corpus");
            return 1;
        }

        if (!File.Exists(benign))
        {
            Console.Error.WriteLine($"Benign corpus not found: {benign}");
            return 1;
        }

        Console.WriteLine("WinGuard detection benchmark");
        Console.WriteLine(new string('-', 60));

        var runner = new BenchmarkRunner(new BenchmarkOptions
        {
            LabeledCorpusPath = labeled,
            BenignCorpusPath = benign,
            IngestBatchSize = ingestBatchSize <= 0 ? 100 : ingestBatchSize,
            TestCount = testCount,
            Notes = "Accuracy is measured against the ground-truth `labels` array on every corpus line. "
                + "Ingest throughput is measured by posting engine output through the real HTTP pipeline "
                + "(HMAC verification, validation, rate limiting, EF Core persistence) hosted in-process.",
        });

        var results = await runner.RunAsync(ct).ConfigureAwait(false);

        Console.WriteLine(new string('-', 60));
        await MetricsWriter.WriteAsync(results, output, ct).ConfigureAwait(false);

        Console.WriteLine();
        Console.WriteLine($"Overall  precision={results.Overall.Precision:F4}  recall={results.Overall.Recall:F4}  F1={results.Overall.F1:F4}");
        Console.WriteLine($"Benign false-positive rate: {results.BenignFalsePositiveRate:P4}");
        Console.WriteLine($"Latency  p50={results.DetectionLatency.P50Ms:F3}ms  p95={results.DetectionLatency.P95Ms:F3}ms  p99={results.DetectionLatency.P99Ms:F3}ms");
        Console.WriteLine($"Ingest   {results.IngestThroughputEventsPerSecond:F0} items/s");

        return 0;
    }
}
