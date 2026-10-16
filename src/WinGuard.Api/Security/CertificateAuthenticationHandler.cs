using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using WinGuard.Api.Services;

namespace WinGuard.Api.Security;

/// <summary>Options for the client-certificate authentication scheme.</summary>
public sealed class CertificateAuthenticationOptions : AuthenticationSchemeOptions
{
}

/// <summary>
/// Authenticates an agent by its mTLS client certificate: the certificate
/// thumbprint is mapped to a <c>HostId</c> that the host registered with. A
/// certificate that is not bound to a host is rejected — presenting *any*
/// trusted client certificate is not enough.
/// </summary>
public sealed class CertificateAuthenticationHandler : AuthenticationHandler<CertificateAuthenticationOptions>
{
    public const string SchemeName = "WinGuardCertificate";
    public const string HostIdClaimType = "host_id";

    private readonly IClientCertificateDirectory _directory;

    public CertificateAuthenticationHandler(
        IOptionsMonitor<CertificateAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IClientCertificateDirectory directory)
        : base(options, logger, encoder)
    {
        _directory = directory;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var certificate = await Context.Connection.GetClientCertificateAsync(Context.RequestAborted).ConfigureAwait(false);
        if (certificate is null)
        {
            return AuthenticateResult.NoResult();
        }

        var thumbprint = certificate.Thumbprint;
        if (string.IsNullOrWhiteSpace(thumbprint))
        {
            return AuthenticateResult.Fail("Client certificate has no thumbprint.");
        }

        var hostId = await _directory.ResolveHostIdAsync(thumbprint, Context.RequestAborted).ConfigureAwait(false);
        if (hostId is null)
        {
            Logger.LogWarning("Client certificate {Thumbprint} is not bound to any registered host.", thumbprint);
            return AuthenticateResult.Fail("Client certificate is not bound to a host.");
        }

        var identity = new ClaimsIdentity(
            [
                new Claim(HostIdClaimType, hostId),
                new Claim("cert_thumbprint", thumbprint),
            ],
            SchemeName);

        Context.Items[SignedPayloadMiddleware.HostIdItemKey] = hostId;

        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }
}
