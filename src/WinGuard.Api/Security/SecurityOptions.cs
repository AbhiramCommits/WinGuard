namespace WinGuard.Api.Security;

/// <summary>Configuration for HMAC request signing and payload limits.</summary>
public sealed class SignedPayloadOptions
{
    public const string SectionName = "Security:Signing";

    /// <summary>When false, signature verification is skipped (local development only).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Maximum accepted difference between request and server time, in seconds.</summary>
    public int MaxClockSkewSeconds { get; set; } = 300;

    /// <summary>How long a nonce is remembered for replay rejection.</summary>
    public int NonceCacheSeconds { get; set; } = 600;

    /// <summary>
    /// Server master secret. Per-host keys are derived as
    /// HMAC-SHA256(master, hostId) so the API never stores agent secrets.
    /// </summary>
    public string MasterSecret { get; set; } = string.Empty;

    /// <summary>Pre-provisioned per-host keys (base64), used for tests and bootstrap.</summary>
    public Dictionary<string, string> HostKeys { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Path prefixes that require a valid HMAC signature: the agent ingest
    /// endpoints. Analyst/dashboard read endpoints are not signature-protected
    /// (in a real deployment the dashboard sits behind the analyst's own auth).
    /// </summary>
    public string[] ProtectedPaths { get; set; } = ["/api/v1/heartbeat", "/api/v1/events"];

    /// <summary>Paths that never require a signature (health probe, host enrollment).</summary>
    public string[] ExemptPaths { get; set; } = ["/healthz", "/api/v1/hosts/register"];

    /// <summary>
    /// Optional shared secret that <c>POST /api/v1/hosts/register</c> must present
    /// in <c>X-WinGuard-Enrollment</c>. Empty disables the check.
    /// </summary>
    public string EnrollmentSecret { get; set; } = string.Empty;

    /// <summary>Hard cap on request body size (default 1 MiB).</summary>
    public long MaxRequestBodyBytes { get; set; } = 1_048_576;
}

/// <summary>Configuration for the mTLS client-certificate scheme.</summary>
public sealed class MtlsOptions
{
    public const string SectionName = "Security:Mtls";

    /// <summary>When true, Kestrel requires a client certificate on the HTTPS endpoint.</summary>
    public bool Enabled { get; set; }

    /// <summary>When true, agent endpoints accept either an HMAC signature or a client certificate.</summary>
    public bool AllowCertificateAuthentication { get; set; } = true;
}
