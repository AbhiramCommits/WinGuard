using WinGuard.Core.Models;

namespace WinGuard.Core.Detection;

/// <summary>
/// Turns raw rule output (base weights) into final 0-100 severities.
/// </summary>
/// <remarks>
/// Three modifiers are applied on top of the rule's base weight:
/// <list type="number">
///   <item><description>
///     signer trust — findings about untrusted/unsigned modules are pushed up,
///     findings about verified modules are relieved slightly;
///   </description></item>
///   <item><description>
///     process criticality — protected / high-value processes carry a bonus;
///   </description></item>
///   <item><description>
///     correlation — each additional rule firing on the same PID adds a bonus,
///     because independent indicators reinforce each other.
///   </description></item>
/// </list>
/// The result is clamped to 0-100 and bucketed Low/Medium/High/Critical.
/// </remarks>
public sealed class SeverityScorer
{
    private readonly DetectionOptions _options;

    public SeverityScorer(DetectionOptions options) => _options = options;

    /// <summary>Scores every event produced for a single snapshot.</summary>
    public IReadOnlyList<DetectionEvent> Score(IReadOnlyList<DetectionEvent> events, DetectionRuleContext context)
    {
        if (events.Count == 0)
        {
            return events;
        }

        var correlationBonus = CorrelationBonus(events.Select(e => e.RuleId));
        var result = new List<DetectionEvent>(events.Count);

        foreach (var detectionEvent in events)
        {
            var score = detectionEvent.Severity;

            if (context.IsProtected)
            {
                score += _options.ProtectedProcessBonus;
            }

            score += SignerModifier(detectionEvent);
            score += correlationBonus;

            result.Add(Finalise(detectionEvent, score));
        }

        return result;
    }

    /// <summary>
    /// Scores a batch spanning multiple processes, applying the correlation bonus
    /// per (host, pid) rather than per snapshot.
    /// </summary>
    public IReadOnlyList<DetectionEvent> ScoreBatch(IEnumerable<(DetectionEvent Event, bool IsProtected)> events)
    {
        var list = events.ToList();
        if (list.Count == 0)
        {
            return [];
        }

        var correlationByPid = list
            .GroupBy(x => (x.Event.HostId, x.Event.Pid))
            .ToDictionary(g => g.Key, g => CorrelationBonus(g.Select(x => x.Event.RuleId)));

        var result = new List<DetectionEvent>(list.Count);

        foreach (var (detectionEvent, isProtected) in list)
        {
            var score = detectionEvent.Severity;

            if (isProtected)
            {
                score += _options.ProtectedProcessBonus;
            }

            score += SignerModifier(detectionEvent);
            score += correlationByPid[(detectionEvent.HostId, detectionEvent.Pid)];

            result.Add(Finalise(detectionEvent, score));
        }

        return result;
    }

    private int CorrelationBonus(IEnumerable<string> ruleIds)
    {
        var distinct = ruleIds.Distinct(StringComparer.Ordinal).Count();
        return Math.Min(_options.MaxCorrelationBonus, Math.Max(0, distinct - 1) * _options.CorrelationBonusPerExtraRule);
    }

    private int SignerModifier(DetectionEvent detectionEvent)
    {
        if (!detectionEvent.Evidence.TryGetValue("signerTrust", out var trust))
        {
            return 0;
        }

        return trust switch
        {
            "untrusted" => _options.UntrustedSignerSurcharge,
            "trusted" => -_options.TrustedSignerRelief,
            _ => 0,
        };
    }

    private DetectionEvent Finalise(DetectionEvent detectionEvent, int score)
    {
        var clamped = Math.Clamp(score, 0, 100);
        return detectionEvent with
        {
            Severity = clamped,
            SeverityBucket = SeverityBuckets.Name(SeverityBuckets.FromScore(clamped, _options)),
        };
    }
}
