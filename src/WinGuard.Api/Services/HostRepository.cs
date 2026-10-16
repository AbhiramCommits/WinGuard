using Microsoft.EntityFrameworkCore;
using WinGuard.Api.Contracts;
using WinGuard.Api.Data;
using WinGuard.Api.Data.Entities;
using WinGuard.Api.Mapping;
using WinGuard.Core.Contracts;
using Host = WinGuard.Api.Data.Entities.Host;

namespace WinGuard.Api.Services;

/// <summary>Persistence operations used by the ingest and read APIs.</summary>
public interface IHostRepository
{
    Task<Host?> FindHostAsync(string hostId, CancellationToken ct);

    Task<Host> UpsertHostAsync(RegisterHostRequest request, string? certificateThumbprint, DateTimeOffset now, CancellationToken ct);

    Task<bool> RecordHeartbeatAsync(HeartbeatRequest request, DateTimeOffset now, CancellationToken ct);

    Task<(int Accepted, int Duplicates)> AddDetectionsAsync(string hostId, IReadOnlyList<DetectionEventDto> events, DateTimeOffset now, CancellationToken ct);

    Task<int> AddObservationsAsync(string hostId, IReadOnlyList<ProcessObservationDto> observations, DateTimeOffset now, CancellationToken ct);

    Task<IReadOnlyList<HostSummaryDto>> GetHostSummariesAsync(DateTimeOffset now, CancellationToken ct);

    Task<IReadOnlyList<DetectionDto>> GetHostDetectionsAsync(string hostId, DateTimeOffset? since, int minSeverity, int limit, CancellationToken ct);

    Task<IReadOnlyList<DetectionDto>> GetRecentDetectionsAsync(int limit, CancellationToken ct);

    Task<ProcessObservation?> GetLatestObservationAsync(string hostId, int pid, CancellationToken ct);

    Task<IReadOnlyList<DetectionDto>> GetProcessDetectionsAsync(string hostId, int pid, int limit, CancellationToken ct);
}

/// <inheritdoc />
public sealed class HostRepository : IHostRepository
{
    private readonly WinGuardDbContext _db;
    private readonly ILogger<HostRepository> _logger;

    public HostRepository(WinGuardDbContext db, ILogger<HostRepository> logger)
    {
        _db = db;
        _logger = logger;
    }

    public Task<Host?> FindHostAsync(string hostId, CancellationToken ct)
        => _db.Hosts.FirstOrDefaultAsync(h => h.Id == hostId, ct);

    public async Task<Host> UpsertHostAsync(
        RegisterHostRequest request,
        string? certificateThumbprint,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var host = await _db.Hosts.FirstOrDefaultAsync(h => h.Id == request.HostId, ct).ConfigureAwait(false);

        if (host is null)
        {
            host = new Host
            {
                Id = request.HostId,
                RegisteredAtUtc = now,
            };
            _db.Hosts.Add(host);
            _logger.LogInformation("Registered new host {HostId} ({Hostname}).", request.HostId, request.Hostname);
        }
        else
        {
            _logger.LogInformation("Re-registered host {HostId} ({Hostname}).", request.HostId, request.Hostname);
        }

        host.Hostname = request.Hostname;
        host.OsVersion = request.OsVersion;
        host.Architecture = request.Architecture;
        host.AgentVersion = request.AgentVersion;
        host.Domain = request.Domain;
        host.UserName = request.UserName;

        if (!string.IsNullOrWhiteSpace(certificateThumbprint))
        {
            host.CertificateThumbprint = certificateThumbprint;
        }

        await _db.SaveChangesAsync(ct).ConfigureAwait(false);
        return host;
    }

    public async Task<bool> RecordHeartbeatAsync(HeartbeatRequest request, DateTimeOffset now, CancellationToken ct)
    {
        var host = await _db.Hosts.FirstOrDefaultAsync(h => h.Id == request.HostId, ct).ConfigureAwait(false);
        if (host is null)
        {
            return false;
        }

        _db.Heartbeats.Add(new HeartbeatRecord
        {
            HostId = request.HostId,
            Sequence = request.Sequence,
            AgentVersion = request.AgentVersion,
            Status = request.Status,
            ProcessCount = request.ProcessCount,
            PendingEventCount = request.PendingEventCount,
            TimestampUtc = request.TimestampUtc,
            ReceivedAtUtc = now,
        });

        host.LastHeartbeatUtc = now;
        if (!string.IsNullOrWhiteSpace(request.AgentVersion))
        {
            host.AgentVersion = request.AgentVersion;
        }

        await _db.SaveChangesAsync(ct).ConfigureAwait(false);
        return true;
    }

    public async Task<(int Accepted, int Duplicates)> AddDetectionsAsync(
        string hostId,
        IReadOnlyList<DetectionEventDto> events,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (events.Count == 0)
        {
            return (0, 0);
        }

        var eventIds = events
            .Select(e => e.EventId)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => id!)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var existing = eventIds.Count == 0
            ? []
            : await _db.Detections
                .Where(d => d.HostId == hostId && eventIds.Contains(d.EventId))
                .Select(d => d.EventId)
                .ToListAsync(ct)
                .ConfigureAwait(false);

        var seen = new HashSet<string>(existing, StringComparer.Ordinal);
        var accepted = 0;
        var duplicates = 0;

        foreach (var detectionEventDto in events)
        {
            var record = detectionEventDto.ToRecord(hostId, now);

            if (!seen.Add(record.EventId))
            {
                duplicates++;
                continue;
            }

            _db.Detections.Add(record);
            accepted++;
        }

        await _db.SaveChangesAsync(ct).ConfigureAwait(false);
        return (accepted, duplicates);
    }

    public async Task<int> AddObservationsAsync(
        string hostId,
        IReadOnlyList<ProcessObservationDto> observations,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (observations.Count == 0)
        {
            return 0;
        }

        foreach (var observationDto in observations)
        {
            _db.ProcessObservations.Add(observationDto.ToObservation(hostId, now));
        }

        await _db.SaveChangesAsync(ct).ConfigureAwait(false);
        return observations.Count;
    }

    public async Task<IReadOnlyList<HostSummaryDto>> GetHostSummariesAsync(DateTimeOffset now, CancellationToken ct)
    {
        var hosts = await _db.Hosts.AsNoTracking().ToListAsync(ct).ConfigureAwait(false);

        var stats = await _db.Detections
            .AsNoTracking()
            .GroupBy(d => d.HostId)
            .Select(g => new
            {
                HostId = g.Key,
                Count = g.Count(),
                HighestSeverity = g.Max(d => d.Severity),
            })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var statsByHost = stats.ToDictionary(s => s.HostId, StringComparer.Ordinal);

        return hosts
            .OrderBy(h => h.Hostname, StringComparer.OrdinalIgnoreCase)
            .Select(host =>
            {
                statsByHost.TryGetValue(host.Id, out var stat);

                var highestSeverity = stat?.HighestSeverity ?? 0;

                return new HostSummaryDto(
                    host.Id,
                    host.Hostname,
                    host.Domain,
                    host.AgentVersion,
                    HostStatusCalculator.Status(host.LastHeartbeatUtc, now),
                    host.LastHeartbeatUtc,
                    stat?.Count ?? 0,
                    highestSeverity,
                    BucketName(highestSeverity));
            })
            .ToList();
    }

    public async Task<IReadOnlyList<DetectionDto>> GetHostDetectionsAsync(
        string hostId,
        DateTimeOffset? since,
        int minSeverity,
        int limit,
        CancellationToken ct)
    {
        var query = _db.Detections.AsNoTracking().Where(d => d.HostId == hostId);

        if (since is not null)
        {
            query = query.Where(d => d.ObservedAtUtc >= since);
        }

        if (minSeverity > 0)
        {
            query = query.Where(d => d.Severity >= minSeverity);
        }

        var records = await query
            .OrderByDescending(d => d.ObservedAtUtc)
            .ThenByDescending(d => d.Id)
            .Take(ClampLimit(limit))
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return records.Select(r => r.ToDto()).ToList();
    }

    public async Task<IReadOnlyList<DetectionDto>> GetRecentDetectionsAsync(int limit, CancellationToken ct)
    {
        var records = await _db.Detections
            .AsNoTracking()
            .OrderByDescending(d => d.ObservedAtUtc)
            .ThenByDescending(d => d.Id)
            .Take(ClampLimit(limit))
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return records.Select(r => r.ToDto()).ToList();
    }

    public Task<ProcessObservation?> GetLatestObservationAsync(string hostId, int pid, CancellationToken ct)
        => _db.ProcessObservations
            .AsNoTracking()
            .Where(o => o.HostId == hostId && o.Pid == pid)
            .OrderByDescending(o => o.ObservedAtUtc)
            .ThenByDescending(o => o.Id)
            .FirstOrDefaultAsync(ct);

    public async Task<IReadOnlyList<DetectionDto>> GetProcessDetectionsAsync(
        string hostId,
        int pid,
        int limit,
        CancellationToken ct)
    {
        var records = await _db.Detections
            .AsNoTracking()
            .Where(d => d.HostId == hostId && d.Pid == pid)
            .OrderByDescending(d => d.ObservedAtUtc)
            .ThenByDescending(d => d.Id)
            .Take(ClampLimit(limit))
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return records.Select(r => r.ToDto()).ToList();
    }

    private static int ClampLimit(int limit) => limit switch
    {
        <= 0 => 200,
        > 1000 => 1000,
        _ => limit,
    };

    private static string BucketName(int severity) => severity switch
    {
        >= 75 => "Critical",
        >= 50 => "High",
        >= 25 => "Medium",
        > 0 => "Low",
        _ => "None",
    };
}
