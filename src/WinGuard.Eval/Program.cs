using System.Text.Json;
using WinGuard.Core.Serialization;
using WinGuard.Eval.Corpus;

namespace WinGuard.Eval;

/// <summary>
/// WinGuard evaluation harness entry point.
///
/// Commands:
///   gen-corpus   Regenerate the deterministic synthetic telemetry corpus.
///   benchmark    Run the detection benchmark (Step 6) and write results/.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var command = args.Length > 0 ? args[0] : "help";

        try
        {
            switch (command)
            {
                case "gen-corpus":
                    return await GenerateCorpusAsync(args).ConfigureAwait(false);
                case "help":
                case "--help":
                case "-h":
                    PrintUsage();
                    return 0;
                default:
                    Console.Error.WriteLine($"Unknown command: {command}");
                    PrintUsage();
                    return 2;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> GenerateCorpusAsync(string[] args)
    {
        var outputDirectory = RepoPaths.CorpusDirectory;
        for (var i = 1; i < args.Length - 1; i++)
        {
            if (args[i] == "--out")
            {
                outputDirectory = Path.GetFullPath(args[i + 1]);
            }
        }

        var options = new CorpusOptions();
        var generator = new CorpusGenerator(options);
        var result = await generator.GenerateAsync(outputDirectory).ConfigureAwait(false);

        Console.WriteLine("WinGuard corpus generation complete");
        Console.WriteLine($"  seed                : {options.Seed}");
        Console.WriteLine($"  hosts               : {result.HostCount}");
        Console.WriteLine($"  benign snapshots    : {result.BenignCount} -> {result.BenignPath}");
        Console.WriteLine($"  labeled snapshots   : {result.LabeledCount} ({result.TamperedCount} tampered) -> {result.LabeledPath}");
        Console.WriteLine($"  tampered fraction   : {(double)result.TamperedCount / result.LabeledCount:P1}");
        Console.WriteLine();
        Console.WriteLine(JsonSerializer.Serialize(result, WinGuardJson.Indented));

        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("WinGuard.Eval — corpus generator and detection benchmark");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run --project src/WinGuard.Eval -- gen-corpus [--out <dir>]");
        Console.WriteLine("  dotnet run -c Release --project src/WinGuard.Eval -- benchmark");
    }
}
