using Microsoft.EntityFrameworkCore;
using WinGuard.Api.Data;

namespace WinGuard.Api.Services;

/// <summary>Maps an mTLS client-certificate thumbprint to a registered host id.</summary>
public interface IClientCertificateDirectory
{
    Task<string?> ResolveHostIdAsync(string thumbprint, CancellationToken ct);

    Task BindAsync(string hostId, string thumbprint, CancellationToken ct);
}

/// <inheritdoc />
public sealed class DbClientCertificateDirectory : IClientCertificateDirectory
{
    private readonly WinGuardDbContext _db;

    public DbClientCertificateDirectory(WinGuardDbContext db) => _db = db;

    public async Task<string?> ResolveHostIdAsync(string thumbprint, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(thumbprint))
        {
            return null;
        }

        return await _db.Hosts
            .AsNoTracking()
            .Where(h => h.CertificateThumbprint == thumbprint && h.Active)
            .Select(h => h.Id)
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task BindAsync(string hostId, string thumbprint, CancellationToken ct)
    {
        var host = await _db.Hosts.FirstOrDefaultAsync(h => h.Id == hostId, ct).ConfigureAwait(false);
        if (host is null)
        {
            return;
        }

        host.CertificateThumbprint = thumbprint;
        await _db.SaveChangesAsync(ct).ConfigureAwait(false);
    }
}
