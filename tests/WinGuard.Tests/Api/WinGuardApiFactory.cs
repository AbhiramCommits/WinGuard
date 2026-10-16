using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using WinGuard.Core.Security;
using WinGuard.Core.Serialization;

namespace WinGuard.Tests.Api;

/// <summary>
/// Boots the real API in-process against a throwaway SQLite database, with HMAC
/// signing enabled and a known master secret so tests can sign requests.
/// </summary>
public sealed class WinGuardApiFactory : WebApplicationFactory<Program>
{
    public const string MasterSecret = "test-master-secret-0000000000000000";
    public const string EnrollmentSecret = "test-enrollment-secret";

    private readonly string _databasePath =
        Path.Combine(Path.GetTempPath(), $"winguard-test-{Guid.NewGuid():N}.db");

    /// <summary>Per-host signing key derived the same way the API derives it.</summary>
    public byte[] KeyFor(string hostId) => RequestSigning.DeriveHostKey(MasterSecret, hostId);

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Database:Provider", "Sqlite");
        builder.UseSetting("ConnectionStrings:Sqlite", $"Data Source={_databasePath}");
        builder.UseSetting("Database:MigrateOnStartup", "true");
        builder.UseSetting("Security:Signing:Enabled", "true");
        builder.UseSetting("Security:Signing:MasterSecret", MasterSecret);
        builder.UseSetting("Security:Signing:MaxClockSkewSeconds", "300");
        builder.UseSetting("Security:Signing:EnrollmentSecret", EnrollmentSecret);
        builder.UseSetting("Security:Signing:MaxRequestBodyBytes", "1048576");
        builder.UseSetting("Security:Mtls:Enabled", "false");
    }

    /// <summary>Registers a host through the real endpoint and returns its signing key.</summary>
    public async Task<byte[]> RegisterHostAsync(HttpClient client, string hostId, string hostname = "WGTEST-001")
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(new
        {
            hostId,
            hostname,
            osVersion = "Microsoft Windows 11 Pro",
            architecture = "X64",
            agentVersion = "1.0.0",
            domain = "TESTOFFICE",
            userName = "analyst",
        }, WinGuardJson.Compact);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/hosts/register")
        {
            Content = new ByteArrayContent(body),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation("X-WinGuard-Enrollment", EnrollmentSecret);

        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var key = document.RootElement.GetProperty("signingKey").GetString()!;

        return Convert.FromBase64String(key);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        foreach (var suffix in new[] { string.Empty, "-shm", "-wal" })
        {
            try
            {
                File.Delete(_databasePath + suffix);
            }
            catch (IOException)
            {
                // Best-effort cleanup of the throwaway database.
            }
        }
    }
}
