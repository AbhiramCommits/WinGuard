namespace WinGuard.Api.Services;

/// <summary>Derives a host's fleet status from the age of its last heartbeat.</summary>
public static class HostStatusCalculator
{
    public const string Online = "Online";
    public const string Stale = "Stale";
    public const string Offline = "Offline";

    public static readonly TimeSpan OnlineWindow = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan StaleWindow = TimeSpan.FromMinutes(30);

    public static string Status(DateTimeOffset? lastHeartbeatUtc, DateTimeOffset now)
    {
        if (lastHeartbeatUtc is null)
        {
            return Offline;
        }

        var age = now - lastHeartbeatUtc.Value;

        if (age <= OnlineWindow)
        {
            return Online;
        }

        return age <= StaleWindow ? Stale : Offline;
    }
}
