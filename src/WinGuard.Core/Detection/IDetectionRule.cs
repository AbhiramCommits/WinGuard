using WinGuard.Core.Models;

namespace WinGuard.Core.Detection;

/// <summary>A single tamper-detection rule.</summary>
public interface IDetectionRule
{
    /// <summary>Stable rule id, e.g. <c>R002</c>.</summary>
    string RuleId { get; }

    /// <summary>Short description used in events and documentation.</summary>
    string Title { get; }

    /// <summary>Base severity applied before modifiers and correlation.</summary>
    int DefaultBaseWeight { get; }

    /// <summary>
    /// Evaluates the rule against one snapshot. Returns zero or more events —
    /// each event carries structured evidence and the rule's base weight; the
    /// severity scorer finalises the score.
    /// </summary>
    IReadOnlyList<DetectionEvent> Evaluate(DetectionRuleContext context);
}
