namespace WinGuard.Core;

/// <summary>Build/identity constants shared by the agent, API and eval harness.</summary>
public static class CoreInfo
{
    /// <summary>Agent version reported in registration, heartbeats and the corpus.</summary>
    public const string AgentVersion = "1.0.0";

    /// <summary>Product name used in headers, evidence and logs.</summary>
    public const string ProductName = "WinGuard";

    /// <summary>Native collector ABI version the managed agent expects.</summary>
    public const int NativeAbiVersion = 1;
}
