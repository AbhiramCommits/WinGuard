namespace WinGuard.Core.Detection;

/// <summary>Per-rule configuration: enable/disable and the base severity weight.</summary>
public sealed class RuleSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>Base severity (0-100) before modifiers and correlation are applied.</summary>
    public int BaseWeight { get; set; }
}

/// <summary>
/// Strongly-typed configuration bound from the <c>Detection</c> section of
/// <c>appsettings.json</c>.
/// </summary>
public sealed class DetectionOptions
{
    public const string SectionName = "Detection";

    /// <summary>
    /// Roots a legitimately loaded module may live under. The directory of the
    /// process's own image is always added at evaluation time (the "game dir").
    /// </summary>
    public List<string> AllowedModuleRoots { get; set; } =
    [
        @"C:\Windows\System32",
        @"C:\Windows\SysWOW64",
        @"C:\Windows\WinSxS",
        @"C:\Windows\Microsoft.NET",
        @"C:\Program Files",
        @"C:\Program Files (x86)",
    ];

    /// <summary>Processes considered high-value; rules R001 and R005 only apply to these.</summary>
    public List<string> ProtectedProcessNames { get; set; } =
    [
        "cs2.exe",
        "csgo.exe",
        "r5apex.exe",
        "valorant-win64-shipping.exe",
        "fortniteclient-win64-shipping.exe",
        "game.exe",
    ];

    /// <summary>Rule id -&gt; settings. Missing rules default to enabled with their built-in weight.</summary>
    public Dictionary<string, RuleSettings> Rules { get; set; } = CreateDefaultRules();

    /// <summary>Window within which an identical (host, pid, rule, evidence) finding is suppressed.</summary>
    public int DedupeWindowSeconds { get; set; } = 60;

    /// <summary>Severity added for each additional rule that fires on the same PID.</summary>
    public int CorrelationBonusPerExtraRule { get; set; } = 8;

    /// <summary>Upper bound on the same-PID correlation bonus.</summary>
    public int MaxCorrelationBonus { get; set; } = 25;

    /// <summary>Severity added when the affected process is protected / high value.</summary>
    public int ProtectedProcessBonus { get; set; } = 10;

    /// <summary>Severity removed when a finding concerns a trusted, signed module.</summary>
    public int TrustedSignerRelief { get; set; } = 5;

    /// <summary>Severity added when a finding concerns an untrusted / unsigned module.</summary>
    public int UntrustedSignerSurcharge { get; set; } = 5;

    /// <summary>Lower bound (inclusive) of the Medium bucket.</summary>
    public int MediumThreshold { get; set; } = 25;

    /// <summary>Lower bound (inclusive) of the High bucket.</summary>
    public int HighThreshold { get; set; } = 50;

    /// <summary>Lower bound (inclusive) of the Critical bucket.</summary>
    public int CriticalThreshold { get; set; } = 75;

    public bool IsRuleEnabled(string ruleId)
        => !Rules.TryGetValue(ruleId, out var settings) || settings.Enabled;

    public int BaseWeightFor(string ruleId, int fallback)
        => Rules.TryGetValue(ruleId, out var settings) && settings.BaseWeight > 0 ? settings.BaseWeight : fallback;

    public static Dictionary<string, RuleSettings> CreateDefaultRules() => new(StringComparer.Ordinal)
    {
        [RuleIds.UnsignedModuleLoaded] = new() { Enabled = true, BaseWeight = 45 },
        [RuleIds.InjectedModulePath] = new() { Enabled = true, BaseWeight = 60 },
        [RuleIds.UnbackedExecutableMemory] = new() { Enabled = true, BaseWeight = 65 },
        [RuleIds.PatchedCodeSection] = new() { Enabled = true, BaseWeight = 75 },
        [RuleIds.RwxPrivateRegion] = new() { Enabled = true, BaseWeight = 55 },
        [RuleIds.ProcessHollowing] = new() { Enabled = true, BaseWeight = 70 },
    };
}
