namespace WinGuard.Core.Models;

/// <summary>
/// A tamper indicator produced by the detection engine. Severity is a 0-100
/// score (not the raw rule weight) after trust/criticality modifiers and the
/// same-PID correlation bonus have been applied.
/// </summary>
public sealed record DetectionEvent
{
    /// <summary>Server-friendly unique id, generated when the event is emitted.</summary>
    public string EventId { get; init; } = Guid.NewGuid().ToString("N");

    /// <summary>Rule that fired, e.g. <c>R002</c>.</summary>
    public required string RuleId { get; init; }

    /// <summary>Final 0-100 severity after scoring.</summary>
    public required int Severity { get; init; }

    public required string HostId { get; init; }

    public int Pid { get; init; }

    public string ProcessName { get; init; } = string.Empty;

    public string ImagePath { get; init; } = string.Empty;

    /// <summary>Human-readable short description of the finding.</summary>
    public string Title { get; init; } = string.Empty;

    /// <summary>Structured evidence backing the finding (string key/value pairs).</summary>
    public IReadOnlyDictionary<string, string> Evidence { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public DateTimeOffset ObservedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Derived bucket: Low / Medium / High / Critical.</summary>
    public string SeverityBucket { get; init; } = string.Empty;
}
