using System.Security.Cryptography;
using System.Text;
using WinGuard.Core.Models;

namespace WinGuard.Core.Detection;

/// <summary>
/// Stable fingerprint of a detection finding, used by the engine's dedupe cache.
/// </summary>
public static class EvidenceHasher
{
    /// <summary>
    /// Hashes (host, pid, rule, evidence) into a stable key. Evidence keys are
    /// sorted so dictionary ordering never changes the fingerprint.
    /// </summary>
    public static string Fingerprint(DetectionEvent detectionEvent)
    {
        var builder = new StringBuilder();
        builder.Append(detectionEvent.HostId).Append('\u001f')
            .Append(detectionEvent.Pid).Append('\u001f')
            .Append(detectionEvent.RuleId).Append('\u001f');

        foreach (var pair in detectionEvent.Evidence.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            builder.Append(pair.Key).Append('=').Append(pair.Value).Append('\u001e');
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString()));
        return Convert.ToHexString(hash);
    }
}
