using System.Net.Http.Headers;
using System.Text.Json;
using WinGuard.Core.Security;
using WinGuard.Core.Serialization;

namespace WinGuard.Tests.Api;

/// <summary>Builds HMAC-signed requests the same way the agent does.</summary>
internal static class TestSigning
{
    public static HttpRequestMessage SignedPost<T>(
        string path,
        T payload,
        string hostId,
        byte[] key,
        long? unixTimestamp = null,
        string? nonce = null,
        byte[]? bodyOverride = null,
        string? signatureOverride = null)
    {
        var body = bodyOverride ?? JsonSerializer.SerializeToUtf8Bytes(payload, WinGuardJson.Compact);
        var timestamp = unixTimestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var requestNonce = nonce ?? Guid.NewGuid().ToString("N");

        var canonical = RequestSigning.BuildCanonicalString("POST", path, timestamp, requestNonce, body);
        var signature = signatureOverride ?? RequestSigning.Sign(key, canonical);

        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new ByteArrayContent(body),
        };

        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation(RequestSigning.HostIdHeader, hostId);
        request.Headers.TryAddWithoutValidation(RequestSigning.TimestampHeader, timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(RequestSigning.NonceHeader, requestNonce);
        request.Headers.TryAddWithoutValidation(RequestSigning.SignatureHeader, signature);

        return request;
    }

    public static async Task<T?> ReadJsonAsync<T>(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<T>(json, WinGuardJson.Compact);
    }

    public static async Task<JsonDocument> ReadDocumentAsync(HttpResponseMessage response)
        => JsonDocument.Parse(await response.Content.ReadAsStringAsync());
}
