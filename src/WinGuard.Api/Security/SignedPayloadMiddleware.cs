using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using WinGuard.Core.Security;

namespace WinGuard.Api.Security;

/// <summary>
/// Verifies the HMAC-SHA256 signature on agent requests.
/// </summary>
/// <remarks>
/// Rejects: missing/!malformed signature headers, clock skew beyond
/// <see cref="SignedPayloadOptions.MaxClockSkewSeconds"/>, replayed nonces, an
/// unknown host key, a body larger than
/// <see cref="SignedPayloadOptions.MaxRequestBodyBytes"/>, and any body that does
/// not match the signature. Every rejection is a bare 401/413 with no detail
/// about which check failed, so the endpoint cannot be used as an oracle.
/// </remarks>
public sealed class SignedPayloadMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SignedPayloadOptions _options;
    private readonly IHostKeyStore _keys;
    private readonly NonceCache _nonces;
    private readonly ILogger<SignedPayloadMiddleware> _logger;

    public SignedPayloadMiddleware(
        RequestDelegate next,
        IOptions<SignedPayloadOptions> options,
        IHostKeyStore keys,
        NonceCache nonces,
        ILogger<SignedPayloadMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _keys = keys;
        _nonces = nonces;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_options.Enabled || IsExempt(context.Request.Path) || !IsProtected(context.Request.Path))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (context.Request.ContentLength is { } declared && declared > _options.MaxRequestBodyBytes)
        {
            await RejectAsync(context, StatusCodes.Status413PayloadTooLarge).ConfigureAwait(false);
            return;
        }

        var hostId = context.Request.Headers[RequestSigning.HostIdHeader].ToString();
        var timestampRaw = context.Request.Headers[RequestSigning.TimestampHeader].ToString();
        var nonce = context.Request.Headers[RequestSigning.NonceHeader].ToString();
        var signature = context.Request.Headers[RequestSigning.SignatureHeader].ToString();

        if (string.IsNullOrWhiteSpace(hostId)
            || string.IsNullOrWhiteSpace(timestampRaw)
            || string.IsNullOrWhiteSpace(nonce)
            || string.IsNullOrWhiteSpace(signature))
        {
            await RejectAsync(context, StatusCodes.Status401Unauthorized).ConfigureAwait(false);
            return;
        }

        if (!long.TryParse(timestampRaw, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var unixSeconds))
        {
            await RejectAsync(context, StatusCodes.Status401Unauthorized).ConfigureAwait(false);
            return;
        }

        var requestTime = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        var skew = (DateTimeOffset.UtcNow - requestTime).Duration();
        if (skew > TimeSpan.FromSeconds(_options.MaxClockSkewSeconds))
        {
            _logger.LogWarning("Rejected request from {HostId}: clock skew {Skew}s exceeds the allowed window.", hostId, skew.TotalSeconds);
            await RejectAsync(context, StatusCodes.Status401Unauthorized).ConfigureAwait(false);
            return;
        }

        if (!_keys.TryGetKey(hostId, out var key))
        {
            _logger.LogWarning("Rejected request from unknown or unprovisioned host {HostId}.", hostId);
            await RejectAsync(context, StatusCodes.Status401Unauthorized).ConfigureAwait(false);
            return;
        }

        var body = await ReadBodyAsync(context).ConfigureAwait(false);

        if (body.Length > _options.MaxRequestBodyBytes)
        {
            await RejectAsync(context, StatusCodes.Status413PayloadTooLarge).ConfigureAwait(false);
            return;
        }

        var canonical = RequestSigning.BuildCanonicalString(
            context.Request.Method,
            context.Request.Path + context.Request.QueryString,
            unixSeconds,
            nonce,
            body);

        if (!RequestSigning.Verify(key, canonical, signature))
        {
            _logger.LogWarning("Rejected request from {HostId}: signature mismatch.", hostId);
            await RejectAsync(context, StatusCodes.Status401Unauthorized).ConfigureAwait(false);
            return;
        }

        if (!_nonces.TryAdd(hostId, nonce, TimeSpan.FromSeconds(_options.NonceCacheSeconds)))
        {
            _logger.LogWarning("Rejected replayed request from {HostId}.", hostId);
            await RejectAsync(context, StatusCodes.Status401Unauthorized).ConfigureAwait(false);
            return;
        }

        // The verified host id is authoritative for the request; downstream code
        // must not trust a host id supplied in the payload.
        context.Items[HostIdItemKey] = hostId;
        context.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim("host_id", hostId)],
                authenticationType: "HmacRequestSignature"));

        await _next(context).ConfigureAwait(false);
    }

    /// <summary>Key under which the verified host id is stored in <see cref="HttpContext.Items"/>.</summary>
    public const string HostIdItemKey = "WinGuard.HostId";

    private bool IsExempt(PathString path)
        => _options.ExemptPaths.Any(exempt => path.StartsWithSegments(exempt, StringComparison.OrdinalIgnoreCase));

    private bool IsProtected(PathString path)
        => _options.ProtectedPaths.Any(prefix => path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase));

    private static async Task<byte[]> ReadBodyAsync(HttpContext context)
    {
        if (context.Request.ContentLength is 0)
        {
            return [];
        }

        context.Request.EnableBuffering();

        using var buffer = new MemoryStream();
        await context.Request.Body.CopyToAsync(buffer).ConfigureAwait(false);
        context.Request.Body.Position = 0;

        return buffer.ToArray();
    }

    private static Task RejectAsync(HttpContext context, int statusCode)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        context.Response.Headers[HeaderNames.CacheControl] = "no-store";
        return context.Response.WriteAsync("""{"error":"unauthorized"}""");
    }
}
