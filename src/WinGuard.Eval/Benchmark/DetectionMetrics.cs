namespace WinGuard.Eval.Benchmark;

/// <summary>Per-rule confusion counts and derived precision/recall/F1.</summary>
public sealed record RuleMetrics(string RuleId, int TruePositives, int FalsePositives, int FalseNegatives)
{
    public double Precision => TruePositives + FalsePositives == 0
        ? 1.0
        : (double)TruePositives / (TruePositives + FalsePositives);

    public double Recall => TruePositives + FalseNegatives == 0
        ? 1.0
        : (double)TruePositives / (TruePositives + FalseNegatives);

    public double F1 => Precision + Recall == 0
        ? 0.0
        : 2 * Precision * Recall / (Precision + Recall);
}

/// <summary>
/// Detection-quality metrics for one snapshot on a per-rule basis, aggregated
/// across the six rule ids rather than per emitted event. Counting per
/// (snapshot, rule) is the correct unit for rule-based detection: a rule that
/// fires three times on one process is one detection decision, not three.
/// </summary>
public static class DetectionMetrics
{
    public static RuleMetrics Sum(string ruleId, IEnumerable<RuleMetrics> perRule)
    {
        var tp = 0;
        var fp = 0;
        var fn = 0;

        foreach (var metrics in perRule)
        {
            tp += metrics.TruePositives;
            fp += metrics.FalsePositives;
            fn += metrics.FalseNegatives;
        }

        return new RuleMetrics(ruleId, tp, fp, fn);
    }
}

/// <summary>Result of evaluating a whole corpus.</summary>
public sealed record CorpusEvaluation(
    int SnapshotCount,
    int TamperedSnapshotCount,
    int LabeledRuleInstances,
    int TrueNegatives,
    IReadOnlyList<RuleMetrics> PerRule,
    RuleMetrics Overall);
