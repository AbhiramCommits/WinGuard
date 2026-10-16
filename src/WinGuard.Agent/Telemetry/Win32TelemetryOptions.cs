namespace WinGuard.Agent.Telemetry;

/// <summary>Configuration for the real Win32/ETW collector.</summary>
public sealed class Win32TelemetryOptions
{
    public const string SectionName = "Win32Telemetry";

    /// <summary>Name of the real-time ETW session used for image-load events.</summary>
    public string EtwSessionName { get; set; } = "WinGuardKernelProcess";

    /// <summary>How often the full process/module/memory sweep runs.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Start the kernel-process ETW session for event-driven image loads.</summary>
    public bool EnableEtw { get; set; } = true;

    /// <summary>Upper bound on the number of modules hashed per process per sweep.</summary>
    public int MaxHashedModulesPerProcess { get; set; } = 32;

    /// <summary>Upper bound on the number of bytes read for the in-memory .text hash.</summary>
    public int MaxTextSectionBytes { get; set; } = 8 * 1024 * 1024;

    /// <summary>When non-empty, only these process names are collected.</summary>
    public string[] TargetProcessNames { get; set; } = [];
}
