namespace WinGuard.Eval.Corpus;

/// <summary>
/// Deterministic corpus generation settings. Everything is derived from
/// <see cref="Seed"/>, so re-running the generator reproduces byte-identical
/// files.
/// </summary>
public sealed class CorpusOptions
{
    public int Seed { get; init; } = 20260115;

    /// <summary>Number of simulated endpoints.</summary>
    public int HostCount { get; init; } = 42;

    /// <summary>Snapshots written to <c>labeled.jsonl</c> (mixed benign + tampered).</summary>
    public int LabeledSnapshotCount { get; init; } = 2000;

    /// <summary>Snapshots written to <c>benign.jsonl</c> (all benign).</summary>
    public int BenignSnapshotCount { get; init; } = 500;

    /// <summary>Fraction of labeled snapshots that carry injected tamper indicators (~15%).</summary>
    public double TamperedFraction { get; init; } = 0.15;

    /// <summary>Simulated wall-clock spacing between consecutive snapshots.</summary>
    public TimeSpan SnapshotInterval { get; init; } = TimeSpan.FromSeconds(1.5);
}
