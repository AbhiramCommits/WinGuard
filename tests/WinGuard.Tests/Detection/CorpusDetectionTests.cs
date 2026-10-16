using WinGuard.Core.Detection;
using WinGuard.Eval.Benchmark;

namespace WinGuard.Tests.Detection;

/// <summary>
/// Corpus-level checks: the rules must reproduce the ground truth baked into
/// <c>data/corpus/labeled.jsonl</c> and must stay silent on
/// <c>data/corpus/benign.jsonl</c>. These are the assertions that make the
/// benchmark numbers meaningful.
/// </summary>
public sealed class CorpusDetectionTests
{
    private static CorpusEvaluation Labeled => CorpusEvaluator.EvaluateFile(TestPaths.CorpusFile("labeled.jsonl"));

    [Fact]
    public void EveryRuleHasPerfectRecallOnTheLabeledCorpus()
    {
        var evaluation = Labeled;

        foreach (var rule in evaluation.PerRule)
        {
            Assert.Equal(0, rule.FalseNegatives);
        }
    }

    [Fact]
    public void OverlappingClassificationIsPerfectOnTheLabeledCorpus()
    {
        var evaluation = Labeled;

        Assert.Equal(1.0, evaluation.Overall.Precision, 6);
        Assert.Equal(1.0, evaluation.Overall.Recall, 6);
        Assert.Equal(1.0, evaluation.Overall.F1, 6);
        Assert.Equal(0, evaluation.Overall.FalsePositives);
    }

    [Fact]
    public void BenignCorpusProducesNoFindings()
    {
        var evaluation = CorpusEvaluator.EvaluateFile(TestPaths.CorpusFile("benign.jsonl"));

        Assert.Equal(0, evaluation.Overall.FalsePositives);
        Assert.Equal(0, evaluation.TamperedSnapshotCount);
        Assert.All(evaluation.PerRule, rule => Assert.Equal(0, rule.FalsePositives));
    }

    [Fact]
    public void LabeledCorpusContainsEveryRuleAtLeastOnce()
    {
        var evaluation = Labeled;

        Assert.All(
            RuleIds.All,
            ruleId => Assert.True(
                evaluation.PerRule.Single(r => r.RuleId == ruleId).TruePositives > 0,
                $"{ruleId} never fired as a true positive."));
    }
}
