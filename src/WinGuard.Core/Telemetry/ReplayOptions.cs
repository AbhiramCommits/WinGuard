namespace WinGuard.Core.Telemetry;

/// <summary>
/// Controls how <see cref="ReplayTelemetrySource"/> paces playback.
/// </summary>
public sealed class ReplayOptions
{
    public const string SectionName = "Replay";

    /// <summary>Path to the JSONL corpus. Relative paths resolve against the current directory.</summary>
    public string CorpusPath { get; set; } = "data/corpus/labeled.jsonl";

    /// <summary>
    /// Snapshots per second. <c>0</c> (the default) replays as fast as the file
    /// can be read, which is what the benchmark harness uses. A positive value
    /// paces playback so it resembles live telemetry.
    /// </summary>
    public double RatePerSecond { get; set; }

    /// <summary>Restart from the top of the file when the corpus is exhausted.</summary>
    public bool Loop { get; set; }

    /// <summary>
    /// Overrides the host id stamped on the synthetic host description. The
    /// snapshots themselves keep whatever host id the corpus recorded.
    /// </summary>
    public string? HostIdOverride { get; set; }
}
