namespace WinGuard.Api.Security;

/// <summary>
/// Adds the browser-facing hardening headers to every response.
/// </summary>
/// <remarks>
/// The dashboard is vanilla JS/CSS served from <c>wwwroot</c> with no inline
/// script or style, so a strict Content-Security-Policy without
/// <c>'unsafe-inline'</c> is achievable. <c>frame-ancestors 'none'</c> plus
/// <c>X-Frame-Options: DENY</c> block click-jacking of the analyst console, and
/// <c>nosniff</c> prevents MIME confusion attacks on uploaded/served content.
/// </remarks>
public sealed class SecurityHeadersMiddleware
{
    public const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'none'; " +
        "frame-ancestors 'none'; " +
        "form-action 'none'";

    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        // Swagger UI (development only) relies on inline script and would be
        // broken by a strict CSP; the console itself never is.
        if (context.Request.Path.StartsWithSegments("/swagger"))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        context.Response.OnStarting(static state =>
        {
            var response = (HttpResponse)state;
            var headers = response.Headers;

            headers["Content-Security-Policy"] = ContentSecurityPolicy;
            headers["X-Content-Type-Options"] = "nosniff";
            headers["X-Frame-Options"] = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers["Cross-Origin-Opener-Policy"] = "same-origin";
            headers["Cross-Origin-Resource-Policy"] = "same-origin";
            headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";

            return Task.CompletedTask;
        }, context.Response);

        await _next(context).ConfigureAwait(false);
    }
}
