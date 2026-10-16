using Microsoft.Extensions.Options;
using WinGuard.Core.Security;

namespace WinGuard.Api.Security;

/// <summary>Resolves the per-host HMAC key used to verify agent requests.</summary>
public interface IHostKeyStore
{
    bool TryGetKey(string hostId, out byte[] key);

    /// <summary>Returns the key handed to a host at registration time.</summary>
    byte[] GetOrCreateKey(string hostId);
}

/// <inheritdoc />
public sealed class HostKeyStore : IHostKeyStore
{
    private readonly SignedPayloadOptions _options;

    public HostKeyStore(IOptions<SignedPayloadOptions> options) => _options = options.Value;

    public bool TryGetKey(string hostId, out byte[] key)
    {
        if (string.IsNullOrWhiteSpace(hostId))
        {
            key = [];
            return false;
        }

        if (_options.HostKeys.TryGetValue(hostId, out var base64) && !string.IsNullOrWhiteSpace(base64))
        {
            try
            {
                key = Convert.FromBase64String(base64);
                return true;
            }
            catch (FormatException)
            {
                key = [];
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.MasterSecret))
        {
            key = RequestSigning.DeriveHostKey(_options.MasterSecret, hostId);
            return true;
        }

        key = [];
        return false;
    }

    public byte[] GetOrCreateKey(string hostId)
        => TryGetKey(hostId, out var key)
            ? key
            : throw new InvalidOperationException(
                "No host key available: configure Security:Signing:MasterSecret or a per-host entry in Security:Signing:HostKeys.");
}
