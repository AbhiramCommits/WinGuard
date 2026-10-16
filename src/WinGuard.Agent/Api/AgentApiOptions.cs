namespace WinGuard.Agent.Api;

/// <summary>Configuration for the agent's connection back to the WinGuard API.</summary>
public sealed class AgentApiOptions
{
    public const string SectionName = "Api";

    /// <summary>Base address of the WinGuard API.</summary>
    public string BaseUrl { get; set; } = "https://localhost:7199";

    /// <summary>When false the agent collects and scores telemetry but does not transmit.</summary>
    public bool Enabled { get; set; }

    public int HeartbeatIntervalSeconds { get; set; } = 30;

    /// <summary>Detection events buffered before a batch is transmitted.</summary>
    public int BatchSize { get; set; } = 100;

    public int MaxRetries { get; set; } = 5;

    public double InitialBackoffSeconds { get; set; } = 1;

    /// <summary>Directory used to spool batches while the API is unreachable.</summary>
    public string SpoolDirectory { get; set; } = "data/spool";

    /// <summary>Per-host HMAC key (base64). Filled in from the registration response.</summary>
    public string? SigningKey { get; set; }

    /// <summary>Development only: accept the API's self-signed certificate.</summary>
    public bool AcceptAnyServerCertificate { get; set; }
}
