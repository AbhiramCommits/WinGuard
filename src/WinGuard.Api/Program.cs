using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;
using WinGuard.Api.Data;
using WinGuard.Api.Security;
using WinGuard.Api.Services;
using WinGuard.Core;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
builder.Services.Configure<SignedPayloadOptions>(builder.Configuration.GetSection(SignedPayloadOptions.SectionName));
builder.Services.Configure<MtlsOptions>(builder.Configuration.GetSection(MtlsOptions.SectionName));

var provider = builder.Configuration["Database:Provider"] ?? "Sqlite";
var mtlsEnabled = builder.Configuration.GetValue<bool>("Security:Mtls:Enabled");
var allowUntrustedClientCerts = builder.Configuration.GetValue<bool>("Security:Mtls:AllowUntrustedCertificates");
var maxRequestBodyBytes = builder.Configuration.GetValue<long?>("Security:Signing:MaxRequestBodyBytes") ?? 1_048_576;

// ---------------------------------------------------------------------------
// Kestrel: 1 MiB request cap + optional mutual TLS
// ---------------------------------------------------------------------------
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.Limits.MaxRequestBodySize = maxRequestBodyBytes;

    if (mtlsEnabled)
    {
        kestrel.ConfigureHttpsDefaults(https =>
        {
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;

            if (allowUntrustedClientCerts)
            {
                // Development only: the dev CA is not in the machine trust store.
                https.ClientCertificateValidation = (_, _, _) => true;
            }
        });
    }
});

// ---------------------------------------------------------------------------
// Persistence: SQL Server in production, SQLite locally / in tests and CI
// ---------------------------------------------------------------------------
if (provider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
{
    var connectionString = builder.Configuration.GetConnectionString("SqlServer")
        ?? throw new InvalidOperationException("ConnectionStrings:SqlServer is required when Database:Provider is SqlServer.");

    builder.Services.AddDbContext<WinGuardDbContext, SqlServerWinGuardDbContext>(options =>
        options.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(typeof(SqlServerWinGuardDbContext).Assembly.GetName().Name)));
}
else
{
    var rawConnectionString = builder.Configuration.GetConnectionString("Sqlite") ?? "Data Source=winguard.db";
    var connectionString = ResolveSqliteConnectionString(rawConnectionString, builder.Environment.ContentRootPath);

    builder.Services.AddDbContext<WinGuardDbContext, SqliteWinGuardDbContext>(options =>
        options.UseSqlite(connectionString, sql => sql.MigrationsAssembly(typeof(SqliteWinGuardDbContext).Assembly.GetName().Name)));
}

// ---------------------------------------------------------------------------
// Application services
// ---------------------------------------------------------------------------
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<NonceCache>();
builder.Services.AddSingleton<IHostKeyStore, HostKeyStore>();
builder.Services.AddScoped<IClientCertificateDirectory, DbClientCertificateDirectory>();
builder.Services.AddScoped<IHostRepository, HostRepository>();

builder.Services
    .AddAuthentication(CertificateAuthenticationHandler.SchemeName)
    .AddScheme<CertificateAuthenticationOptions, CertificateAuthenticationHandler>(
        CertificateAuthenticationHandler.SchemeName,
        _ => { });

builder.Services.AddAuthorization();

// ---------------------------------------------------------------------------
// Rate limiting (per host when a signed host id is present, else per client IP)
// ---------------------------------------------------------------------------
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy("ingest", context =>
    {
        var hostId = context.Request.Headers[WinGuard.Core.Security.RequestSigning.HostIdHeader].ToString();
        var partitionKey = string.IsNullOrWhiteSpace(hostId)
            ? context.Connection.RemoteIpAddress?.ToString() ?? "unknown"
            : hostId;

        return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 600,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        });
    });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------
if (builder.Configuration.GetValue("Database:MigrateOnStartup", true))
{
    using var scope = app.Services.CreateScope();
    var database = scope.ServiceProvider.GetRequiredService<WinGuardDbContext>();
    database.Database.Migrate();
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRateLimiter();
app.UseAuthentication();
app.UseMiddleware<SignedPayloadMiddleware>();
app.UseAuthorization();
app.MapControllers();

app.Logger.LogInformation(
    "WinGuard API starting: provider={Provider}, mTLS={Mtls}, signing={Signing}, version={Version}.",
    provider,
    mtlsEnabled,
    builder.Configuration.GetValue("Security:Signing:Enabled", true),
    CoreInfo.AgentVersion);

app.Run();

/// <summary>Exposed so integration tests can boot the API with <c>WebApplicationFactory</c>.</summary>
public partial class Program
{
    /// <summary>
    /// Turns a relative SQLite data source into an absolute path anchored at the
    /// repository root (so <c>dotnet run</c>, which sets the working directory to
    /// the project folder, still writes to the repo's <c>data/</c> directory) and
    /// creates the containing directory, which SQLite will not do itself.
    /// </summary>
    private static string ResolveSqliteConnectionString(string connectionString, string contentRootPath)
    {
        var builder = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(connectionString);
        var dataSource = builder.DataSource;

        if (string.IsNullOrWhiteSpace(dataSource)
            || dataSource.Contains(":memory:", StringComparison.OrdinalIgnoreCase)
            || Path.IsPathRooted(dataSource))
        {
            return connectionString;
        }

        var basePath = FindRepositoryRoot(contentRootPath) ?? contentRootPath;
        var absolute = Path.GetFullPath(Path.Combine(basePath, dataSource));

        var directory = Path.GetDirectoryName(absolute);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        builder.DataSource = absolute;
        return builder.ToString();
    }

    private static string? FindRepositoryRoot(string start)
    {
        var directory = new DirectoryInfo(start);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "WinGuard.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        return null;
    }
}
