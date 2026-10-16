using System.ComponentModel.DataAnnotations;

namespace WinGuard.Api.Data.Entities;

/// <summary>A registered endpoint running the WinGuard agent.</summary>
public class Host
{
    /// <summary>Stable host id (Windows MachineGuid on real endpoints).</summary>
    [MaxLength(128)]
    public string Id { get; set; } = string.Empty;

    [MaxLength(256)]
    public string Hostname { get; set; } = string.Empty;

    [MaxLength(128)]
    public string OsVersion { get; set; } = string.Empty;

    [MaxLength(32)]
    public string Architecture { get; set; } = string.Empty;

    [MaxLength(32)]
    public string AgentVersion { get; set; } = string.Empty;

    [MaxLength(128)]
    public string Domain { get; set; } = string.Empty;

    [MaxLength(128)]
    public string UserName { get; set; } = string.Empty;

    public DateTimeOffset RegisteredAtUtc { get; set; }

    /// <summary>Timestamp of the most recent heartbeat; drives Online/Stale/Offline.</summary>
    public DateTimeOffset? LastHeartbeatUtc { get; set; }

    /// <summary>Client-certificate thumbprint bound to this host by the mTLS scheme.</summary>
    [MaxLength(128)]
    public string? CertificateThumbprint { get; set; }

    public bool Active { get; set; } = true;

    public ICollection<HeartbeatRecord> Heartbeats { get; set; } = new List<HeartbeatRecord>();

    public ICollection<DetectionRecord> Detections { get; set; } = new List<DetectionRecord>();

    public ICollection<ProcessObservation> ProcessObservations { get; set; } = new List<ProcessObservation>();
}
