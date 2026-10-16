using Microsoft.AspNetCore.Http;

namespace WinGuard.Api.Security;

/// <summary>Helpers for reading the identity established by the signature middleware.</summary>
public static class HttpContextSecurityExtensions
{
    /// <summary>
    /// Returns the host id proven by the request's HMAC signature (or client
    /// certificate), or <see langword="null"/> when the request was not
    /// authenticated (for example when signing is disabled locally).
    /// </summary>
    public static string? GetVerifiedHostId(this HttpContext context)
        => context.Items.TryGetValue(SignedPayloadMiddleware.HostIdItemKey, out var value)
            ? value as string
            : null;
}
