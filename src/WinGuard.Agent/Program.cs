using Microsoft.Extensions.Options;
using WinGuard.Agent;
using WinGuard.Agent.Telemetry;
using WinGuard.Core.Telemetry;

var builder = Host.CreateApplicationBuilder(args);

builder.Services
    .AddOptions<Win32TelemetryOptions>()
    .Bind(builder.Configuration.GetSection(Win32TelemetryOptions.SectionName));

builder.Services
    .AddOptions<ReplayOptions>()
    .Bind(builder.Configuration.GetSection(ReplayOptions.SectionName));

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

builder.Services.AddHostedService<TelemetryWorker>();

var host = builder.Build();
host.Run();
