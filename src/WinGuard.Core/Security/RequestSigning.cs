using System.Security.Cryptography;
using System.Text;

namespace WinGuard.Core.Security;

/// <summary>
/// HMAC-SHA256 request signing shared by the agent (signer) and the API
/// (verifier). Both sides build the same canonical string, so the scheme is
/// defined in exactly one place.
/// </summary>
/// <remarks>
/// Canonical form:
/// <code>
/// METHOD \n path-and-query \n unix-timestamp-seconds \n nonce \n lowercase-hex(sha256(body))
/// </code>
/// The body hash binds the payload; the timestamp bounds the validity window;
/// the nonce makes each request single-use.
/// </remarks>
public static class RequestSigning
{
    public const string HostIdHeader = "X-WinGuard-HostId";
    public const string TimestampHeader = "X-WinGuard-Timestamp";
    public const string NonceHeader = "X-WinGuard-Nonce";
    public const string SignatureHeader = "X-WinGuard-Signature";
    public const string AgentVersionHeader = "X-WinGuard-AgentVersion";

    /// <summary>Builds the canonical string that is signed.</summary>
    public static string BuildCanonicalString(
        string method,
        string pathAndQuery,
        long unixTimestampSeconds,
        string nonce,
        ReadOnlySpan<byte> body)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);

        var bodyHash = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

        return string.Concat(
            method.ToUpperInvariant(), "\n",
            pathAndQuery, "\n",
            unixTimestampSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture), "\n",
            nonce, "\n",
            bodyHash);
    }

    /// <summary>Computes the HMAC-SHA256 signature over the canonical string.</summary>
    public static byte[] ComputeSignature(byte[] key, string canonical)
        => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(canonical));

    public static string Sign(byte[] key, string canonical)
        => Convert.ToBase64String(ComputeSignature(key, canonical));

    /// <summary>Fixed-time verification of a base64 signature over the canonical string.</summary>
    public static bool Verify(byte[] key, string canonical, string signatureBase64)
    {
        if (string.IsNullOrWhiteSpace(signatureBase64))
        {
            return false;
        }

        byte[] provided;
        try
        {
            provided = Convert.FromBase64String(signatureBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        var expected = ComputeSignature(key, canonical);
        return CryptographicOperations.FixedTimeEquals(expected, provided);
    }

    /// <summary>
    /// Derives a per-host key from the server master secret so the API never has
    /// to store agent secrets: it recomputes the key from the host id.
    /// </summary>
    public static byte[] DeriveHostKey(string masterSecret, string hostId)
        => HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(masterSecret),
            Encoding.UTF8.GetBytes(hostId));

    public static string ToBase64(byte[] value) => Convert.ToBase64String(value);
}
