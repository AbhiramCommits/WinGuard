using Microsoft.Extensions.Options;
using WinGuard.Agent.Api;
using WinGuard.Core.Contracts;
using WinGuard.Core.Detection;
using WinGuard.Core.Models;
using WinGuard.Core.Telemetry;

namespace WinGuard.Agent;

/// <summary>
/// Long-running agent loop: consumes snapshots from the configured
/// <see cref="ITelemetrySource"/> (real Win32/ETW on Windows, corpus replay
/// elsewhere), scores them with the real <see cref="DetectionEngine"/>, and
/// forwards detections and process observations to the WinGuard API with retry
/// and disk spooling.
/// </summary>
public sealed class TelemetryWorker : BackgroundService
{
    private readonly ITelemetrySource _source;
    private readonly DetectionEngine _engine;
    private readonly AgentApiClient _api;
    private readonly AgentApiOptions _apiOptions;
    private readonly ILogger<TelemetryWorker> _logger;

    private long _observed;
    private long _detections;
    private long _heartbeatSequence;

    public TelemetryWorker(
        ITelemetrySource source,
        DetectionEngine engine,
        AgentApiClient api,
        IOptions<AgentApiOptions> apiOptions,
        ILogger<TelemetryWorker> logger)
    {
        _source = source;
        _engine = engine;
        _api = api;
        _apiOptions = apiOptions.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var host = _source.DescribeHost();
        _logger.LogInformation(
            "WinGuard agent {AgentVersion} starting on host {HostId} ({Hostname}); API transmission {State}.",
            host.AgentVersion,
            host.HostId,
            host.Hostname,
            _apiOptions.Enabled ? "enabled" : "disabled");

        if (_apiOptions.Enabled)
        {
            await _api.RegisterAsync(host, stoppingToken).ConfigureAwait(false);
            await _api.FlushSpoolAsync(stoppingToken).ConfigureAwait(false);
        }

        var pendingEvents = new List<DetectionEventDto>();
        var pendingObservations = new List<ProcessObservationDto>();
        var lastHeartbeat = DateTimeOffset.UtcNow;
        var heartbeatInterval = TimeSpan.FromSeconds(_apiOptions.HeartbeatIntervalSeconds);

        await foreach (var snapshot in _source.StreamAsync(stoppingToken).ConfigureAwait(false))
        {
            _observed++;

            var events = _engine.Evaluate(snapshot);
            if (events.Count > 0)
            {
                _detections += events.Count;
                pendingEvents.AddRange(events.Select(e => e.ToDto()));

                // Observations only matter for processes that tripped a rule:
                // they are what the analyst drill-down renders.
                pendingObservations.Add(snapshot.ToObservationDto());
            }

            var dueForHeartbeat = DateTimeOffset.UtcNow - lastHeartbeat >= heartbeatInterval;

            if (_apiOptions.Enabled && (pendingEvents.Count >= _apiOptions.BatchSize || dueForHeartbeat))
            {
                await FlushAsync(host, pendingEvents, pendingObservations, stoppingToken).ConfigureAwait(false);
            }

            if (_apiOptions.Enabled && dueForHeartbeat)
            {
                await SendHeartbeatAsync(host, lastHeartbeat, pendingEvents.Count, stoppingToken).ConfigureAwait(false);
                await _api.FlushSpoolAsync(stoppingToken).ConfigureAwait(false);
                lastHeartbeat = DateTimeOffset.UtcNow;
            }

            if (_observed % 250 == 0)
            {
                _logger.LogInformation(
                    "Observed {Observed} snapshots, {Detections} detections, {Spooled} spooled batches.",
                    _observed,
                    _detections,
                    _api.SpooledBatches);
            }
        }

        if (_apiOptions.Enabled)
        {
            await FlushAsync(host, pendingEvents, pendingObservations, stoppingToken).ConfigureAwait(false);
        }

        _logger.LogInformation(
            "Telemetry stream ended after {Observed} snapshots and {Detections} detections.",
            _observed,
            _detections);
    }

    private async Task FlushAsync(
        HostInfo host,
        List<DetectionEventDto> events,
        List<ProcessObservationDto> observations,
        CancellationToken ct)
    {
        if (events.Count == 0 && observations.Count == 0)
        {
            return;
        }

        var batch = new EventsRequest
        {
            HostId = host.HostId,
            Events = [.. events],
            Observations = [.. observations],
        };

        await _api.SendEventsAsync(batch, ct).ConfigureAwait(false);

        events.Clear();
        observations.Clear();
    }

    private async Task SendHeartbeatAsync(HostInfo host, DateTimeOffset lastHeartbeat, int pendingCount, CancellationToken ct)
    {
        var heartbeat = new Heartbeat
        {
            HostId = host.HostId,
            AgentVersion = host.AgentVersion,
            Sequence = ++_heartbeatSequence,
            TimestampUtc = DateTimeOffset.UtcNow,
            ProcessCount = (int)Math.Min(_observed, int.MaxValue),
            PendingEventCount = pendingCount,
            Status = _api.SpooledBatches > 0 ? "SpoolingOffline" : "Healthy",
        };

        _logger.LogDebug("Heartbeat {Sequence} (last sent at {Last:O}).", heartbeat.Sequence, lastHeartbeat);
        await _api.SendHeartbeatAsync(heartbeat, ct).ConfigureAwait(false);
    }
}
