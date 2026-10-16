using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Models;
using WinGuard.Core.Detection.Rules;

namespace WinGuard.Core.Detection;

/// <summary>
/// Runs every enabled rule over a snapshot, scores the findings, and suppresses
/// repeats of the same finding within a configurable window.
/// </summary>
public sealed class DetectionEngine
{
    private readonly IReadOnlyList<IDetectionRule> _rules;
    private readonly DetectionOptions _options;
    private readonly SeverityScorer _scorer;
    private readonly ILogger<DetectionEngine>? _logger;
    private readonly Func<DateTimeOffset> _clock;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _dedupeCache = new(StringComparer.Ordinal);

    public DetectionEngine(
        IEnumerable<IDetectionRule> rules,
        DetectionOptions options,
        ILogger<DetectionEngine>? logger = null,
        Func<DateTimeOffset>? clock = null)
    {
        _rules = rules.ToList();
        _options = options;
        _logger = logger;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _scorer = new SeverityScorer(options);
    }

    /// <summary>All rules known to the engine.</summary>
    public IReadOnlyList<IDetectionRule> Rules => _rules;

    /// <summary>Builds an engine with the built-in rule set and default options.</summary>
    public static DetectionEngine CreateDefault(
        DetectionOptions? options = null,
        ILogger<DetectionEngine>? logger = null,
        Func<DateTimeOffset>? clock = null)
        => new(DetectionRuleCatalog.DefaultRules(), options ?? new DetectionOptions(), logger, clock);

    /// <summary>
    /// Evaluates a snapshot. Emits only findings that are not duplicates of a
    /// recent (host, pid, rule, evidence) tuple.
    /// </summary>
    public IReadOnlyList<DetectionEvent> Evaluate(ProcessSnapshot snapshot)
    {
        var context = new DetectionRuleContext(snapshot, _options);
        var raw = new List<DetectionEvent>();

        foreach (var rule in _rules)
        {
            if (!_options.IsRuleEnabled(rule.RuleId))
            {
                continue;
            }

            raw.AddRange(rule.Evaluate(context));
        }

        if (raw.Count == 0)
        {
            return [];
        }

        var scored = _scorer.Score(raw, context);
        var emitted = new List<DetectionEvent>(scored.Count);

        foreach (var detectionEvent in scored)
        {
            if (TryRecord(detectionEvent))
            {
                emitted.Add(detectionEvent);
            }
            else
            {
                _logger?.LogDebug(
                    "Suppressed duplicate finding {RuleId} for {HostId}/{Pid} within {Window}s.",
                    detectionEvent.RuleId,
                    detectionEvent.HostId,
                    detectionEvent.Pid,
                    _options.DedupeWindowSeconds);
            }
        }

        return emitted;
    }

    /// <summary>Evaluates a stream of snapshots, preserving order.</summary>
    public IEnumerable<(ProcessSnapshot Snapshot, IReadOnlyList<DetectionEvent> Events)> EvaluateStream(
        IEnumerable<ProcessSnapshot> snapshots)
    {
        foreach (var snapshot in snapshots)
        {
            yield return (snapshot, Evaluate(snapshot));
        }
    }

    private bool TryRecord(DetectionEvent detectionEvent)
    {
        var now = _clock();
        Prune(now);

        var key = EvidenceHasher.Fingerprint(detectionEvent);
        var window = TimeSpan.FromSeconds(_options.DedupeWindowSeconds);

        if (_dedupeCache.TryGetValue(key, out var seenAt) && now - seenAt < window)
        {
            return false;
        }

        _dedupeCache[key] = now;
        return true;
    }

    private void Prune(DateTimeOffset now)
    {
        // Bounded, cheap pruning: drop expired entries when the cache grows.
        if (_dedupeCache.Count < 4096)
        {
            return;
        }

        var window = TimeSpan.FromSeconds(_options.DedupeWindowSeconds);
        foreach (var pair in _dedupeCache)
        {
            if (now - pair.Value >= window)
            {
                _dedupeCache.TryRemove(pair.Key, out _);
            }
        }
    }
}

/// <summary>The built-in rule set.</summary>
public static class DetectionRuleCatalog
{
    public static IReadOnlyList<IDetectionRule> DefaultRules() =>
    [
        new UnsignedModuleLoadedRule(),
        new InjectedModulePathRule(),
        new UnbackedExecutableMemoryRule(),
        new PatchedCodeSectionRule(),
        new RwxPrivateRegionRule(),
        new ProcessHollowingRule(),
    ];
}
