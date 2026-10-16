using WinGuard.Core.Detection;
using WinGuard.Core.Models;
using WinGuard.Core.Telemetry;

namespace WinGuard.Eval.Benchmark;

/// <summary>
/// Runs the real <see cref="DetectionEngine"/> over a labeled corpus and
/// compares the predicted rule set with the ground-truth labels.
/// </summary>
public sealed class CorpusEvaluator
{
    private readonly DetectionEngine _engine;
    private readonly string[] _ruleUniverse;

    public CorpusEvaluator(DetectionEngine engine, IEnumerable<string>? ruleUniverse = null)
    {
        _engine = engine;
        _ruleUniverse = (ruleUniverse ?? RuleIds.All).Distinct(StringComparer.Ordinal).ToArray();
    }

    public CorpusEvaluation Evaluate(IEnumerable<ProcessSnapshot> snapshots)
    {
        var counts = _ruleUniverse.ToDictionary(id => id, _ => (Tp: 0, Fp: 0, Fn: 0), StringComparer.Ordinal);
        var extra = new Dictionary<string, (int Tp, int Fp, int Fn)>(StringComparer.Ordinal);

        var snapshotCount = 0;
        var tampered = 0;
        var labeledInstances = 0;
        var trueNegatives = 0;

        foreach (var snapshot in snapshots)
        {
            snapshotCount++;

            var expected = new HashSet<string>(snapshot.Labels, StringComparer.Ordinal);
            var predicted = new HashSet<string>(
                _engine.Evaluate(snapshot).Select(e => e.RuleId),
                StringComparer.Ordinal);

            if (expected.Count > 0)
            {
                tampered++;
            }

            labeledInstances += expected.Count;

            foreach (var ruleId in _ruleUniverse)
            {
                var inExpected = expected.Contains(ruleId);
                var inPredicted = predicted.Contains(ruleId);

                var current = counts[ruleId];
                if (inExpected && inPredicted)
                {
                    current.Tp++;
                }
                else if (!inExpected && inPredicted)
                {
                    current.Fp++;
                }
                else if (inExpected && !inPredicted)
                {
                    current.Fn++;
                }
                else
                {
                    trueNegatives++;
                }

                counts[ruleId] = current;
            }

            // Rules outside the declared universe should not exist; record them so
            // a typo in a rule id surfaces as a metric rather than silently.
            foreach (var ruleId in predicted.Where(r => !counts.ContainsKey(r)))
            {
                counts[ruleId] = (0, 0, 0);
            }
        }

        var perRule = counts
            .Select(kvp => new RuleMetrics(kvp.Key, kvp.Value.Tp, kvp.Value.Fp, kvp.Value.Fn))
            .OrderBy(m => m.RuleId, StringComparer.Ordinal)
            .ToList();

        var overall = DetectionMetrics.Sum("ALL", perRule);

        return new CorpusEvaluation(snapshotCount, tampered, labeledInstances, trueNegatives, perRule, overall);
    }

    /// <summary>
    /// Convenience helper: evaluates a JSONL corpus file with a freshly built
    /// engine. Dedupe is disabled because the corpus is replayed as a whole and
    /// a suppression cache is a live-stream concern.
    /// </summary>
    public static CorpusEvaluation EvaluateFile(string corpusPath, DetectionOptions? options = null)
    {
        var effective = options ?? new DetectionOptions();

        // Dedupe is a live-stream concern: when replaying a whole corpus the
        // suppression cache would hide genuine repeats, so it is switched off.
        effective.DedupeWindowSeconds = 0;

        var engine = DetectionEngine.CreateDefault(effective);
        var evaluator = new CorpusEvaluator(engine);
        var snapshots = TelemetryJsonl.ReadLines(corpusPath);
        return evaluator.Evaluate(snapshots);
    }
}
