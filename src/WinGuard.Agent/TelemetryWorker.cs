using WinGuard.Core.Telemetry;

namespace WinGuard.Agent;

/// <summary>
/// Long-running agent loop. Consumes snapshots from the configured
/// <see cref="ITelemetrySource"/> (real Win32/ETW on Windows, corpus replay
/// elsewhere) and — from Step 4 — forwards them to the WinGuard API.
/// </summary>
public sealed class TelemetryWorker : BackgroundService
{
    private readonly ITelemetrySource _source;
    private readonly ILogger<TelemetryWorker> _logger;
    private long _observed;

    public TelemetryWorker(ITelemetrySource source, ILogger<TelemetryWorker> logger)
    {
        _source = source;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var host = _source.DescribeHost();
        _logger.LogInformation(
            "WinGuard agent {AgentVersion} starting on host {HostId} ({Hostname}).",
            host.AgentVersion,
            host.HostId,
            host.Hostname);

        await foreach (var snapshot in _source.StreamAsync(stoppingToken).ConfigureAwait(false))
        {
            _observed++;

            if (_observed % 250 == 0)
            {
                _logger.LogInformation(
                    "Observed {Count} process snapshots (latest {Process} pid {Pid}).",
                    _observed,
                    snapshot.ProcessName,
                    snapshot.Pid);
            }
        }

        _logger.LogInformation("Telemetry stream ended after {Count} snapshots.", _observed);
    }
}
