using Microsoft.Extensions.Options;
using WinGuard.Agent;
using WinGuard.Agent.Api;
using WinGuard.Agent.Telemetry;
using WinGuard.Core.Detection;
using WinGuard.Core.Telemetry;

var builder = Host.CreateApplicationBuilder(args);

if (OperatingSystem.IsWindows())
{
    // Windows Service hosting. Least privilege: the installer registers the
    // service as LocalService (see packaging/install-service.ps1) — it needs no
    // administrative rights beyond the process/ETW access the collector requests.
    builder.Services.AddWindowsService(options => options.ServiceName = "WinGuardAgent");
}

builder.Services
    .AddOptions<Win32TelemetryOptions>()
    .Bind(builder.Configuration.GetSection(Win32TelemetryOptions.SectionName));

builder.Services
    .AddOptions<ReplayOptions>()
    .Bind(builder.Configuration.GetSection(ReplayOptions.SectionName));

builder.Services
    .AddOptions<AgentApiOptions>()
    .Bind(builder.Configuration.GetSection(AgentApiOptions.SectionName));

builder.Services
    .AddOptions<DetectionOptions>()
    .Bind(builder.Configuration.GetSection(DetectionOptions.SectionName));

if (OperatingSystem.IsWindows())
{
    // Real Win32/ETW collector. Only registered on Windows; the type itself
    // throws PlatformNotSupportedException anywhere else.
    builder.Services.AddSingleton<ITelemetrySource, Win32EtwTelemetrySource>();
}
else
{
    // Replay source: lets the agent run against the JSONL corpus on macOS/Linux.
    builder.Services.AddSingleton<ITelemetrySource>(sp =>
    {
        var options = sp.GetRequiredService<IOptions<ReplayOptions>>().Value;
        var path = CorpusLocator.Resolve(options.CorpusPath);
        return new ReplayTelemetrySource(path, options);
    });
}

builder.Services.AddSingleton(sp => DetectionEngine.CreateDefault(
    sp.GetRequiredService<IOptions<DetectionOptions>>().Value,
    sp.GetService<ILogger<DetectionEngine>>()));

builder.Services.AddSingleton(sp =>
{
    var options = sp.GetRequiredService<IOptions<AgentApiOptions>>().Value;
    var spoolDirectory = CorpusLocator.ResolveDirectory(options.SpoolDirectory);
    return new DetectionSpool(spoolDirectory, sp.GetRequiredService<ILogger<DetectionSpool>>());
});

builder.Services.AddHttpClient<AgentApiClient>()
    .ConfigurePrimaryHttpMessageHandler(sp =>
    {
        var options = sp.GetRequiredService<IOptions<AgentApiOptions>>().Value;
        var handler = new HttpClientHandler();

        if (options.AcceptAnyServerCertificate)
        {
            // Development only: accept the API's self-signed dev certificate.
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        return handler;
    });

builder.Services.AddHostedService<TelemetryWorker>();

var host = builder.Build();
host.Run();
