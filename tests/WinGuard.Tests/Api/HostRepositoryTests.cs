using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuard.Api.Data;
using WinGuard.Api.Services;
using WinGuard.Core.Contracts;
using Host = WinGuard.Api.Data.Entities.Host;

namespace WinGuard.Tests.Api;

/// <summary>
/// Direct EF Core query tests against a real SQLite database with the committed
/// migrations applied — the filter/order semantics the dashboard depends on.
/// </summary>
public sealed class HostRepositoryTests : IDisposable
{
    private readonly string _databasePath;
    private readonly SqliteWinGuardDbContext _db;
    private readonly HostRepository _repository;

    public HostRepositoryTests()
    {
        _databasePath = Path.Combine(Path.GetTempPath(), $"winguard-repo-{Guid.NewGuid():N}.db");

        var options = new DbContextOptionsBuilder<SqliteWinGuardDbContext>()
            .UseSqlite($"Data Source={_databasePath}")
            .Options;

        _db = new SqliteWinGuardDbContext(options);
        _db.Database.Migrate();
        _repository = new HostRepository(_db, NullLogger<HostRepository>.Instance);
    }

    [Fact]
    public async Task MigrationsCreateTheExpectedSchema()
    {
        var applied = await _db.Database.GetAppliedMigrationsAsync();

        Assert.NotEmpty(applied);
        Assert.True(await _db.Hosts.AnyAsync() == false);
    }

    [Fact]
    public async Task DetectionsAreDeduplicatedByEventId()
    {
        var hostId = await SeedHostAsync();

        var batch = new List<DetectionEventDto>
        {
            Detection(hostId, "evt-1", "R001", 45),
            Detection(hostId, "evt-2", "R002", 60),
        };

        var first = await _repository.AddDetectionsAsync(hostId, batch, DateTimeOffset.UtcNow, default);
        Assert.Equal((2, 0), first);

        var second = await _repository.AddDetectionsAsync(hostId, batch, DateTimeOffset.UtcNow, default);
        Assert.Equal((0, 2), second);

        Assert.Equal(2, await _repository.CountDetectionsAsync(default));
    }

    [Fact]
    public async Task HostDetectionsAreNewestFirstAndLimited()
    {
        var hostId = await SeedHostAsync();
        var baseTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var batch = Enumerable.Range(0, 10)
            .Select(i => Detection(hostId, $"evt-{i}", "R003", 50 + i, baseTime.AddMinutes(i)))
            .ToList();

        await _repository.AddDetectionsAsync(hostId, batch, DateTimeOffset.UtcNow, default);

        var newest = await _repository.GetHostDetectionsAsync(hostId, null, 0, 3, default);

        Assert.Equal(3, newest.Count);
        Assert.Equal(59, newest[0].Severity);
        Assert.True(newest[0].ObservedAtUtc > newest[1].ObservedAtUtc);
    }

    [Fact]
    public async Task HostDetectionsFilterBySeverityAndSince()
    {
        var hostId = await SeedHostAsync();
        var baseTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        await _repository.AddDetectionsAsync(
            hostId,
            [
                Detection(hostId, "old-low", "R001", 20, baseTime),
                Detection(hostId, "new-high", "R004", 90, baseTime.AddHours(3)),
            ],
            DateTimeOffset.UtcNow,
            default);

        var highOnly = await _repository.GetHostDetectionsAsync(hostId, null, 50, 100, default);
        Assert.Single(highOnly);
        Assert.Equal("R004", highOnly[0].RuleId);

        var recent = await _repository.GetHostDetectionsAsync(hostId, baseTime.AddHours(1), 0, 100, default);
        Assert.Single(recent);
        Assert.Equal("new-high", recent[0].EventId);
    }

    [Fact]
    public async Task HostSummariesDeriveStatusFromHeartbeatAge()
    {
        var onlineId = await SeedHostAsync("online-host");
        var staleId = await SeedHostAsync("stale-host");
        var offlineId = await SeedHostAsync("offline-host");

        var now = DateTimeOffset.UtcNow;

        await SetHeartbeatAsync(onlineId, now.AddMinutes(-1));
        await SetHeartbeatAsync(staleId, now.AddMinutes(-10));
        await SetHeartbeatAsync(offlineId, now.AddHours(-3));

        await _repository.AddDetectionsAsync(onlineId, [Detection(onlineId, "e1", "R004", 90)], now, default);
        await _repository.AddDetectionsAsync(onlineId, [Detection(onlineId, "e2", "R001", 30)], now, default);

        var summaries = await _repository.GetHostSummariesAsync(now, default);

        Assert.Equal("Online", summaries.Single(s => s.HostId == onlineId).Status);
        Assert.Equal("Stale", summaries.Single(s => s.HostId == staleId).Status);
        Assert.Equal("Offline", summaries.Single(s => s.HostId == offlineId).Status);

        var online = summaries.Single(s => s.HostId == onlineId);
        Assert.Equal(2, online.DetectionCount);
        Assert.Equal(90, online.HighestSeverity);
        Assert.Equal("Critical", online.HighestSeverityBucket);
    }

    [Fact]
    public async Task LatestObservationWinsForTheDrilldown()
    {
        var hostId = await SeedHostAsync();
        var baseTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        await _repository.AddObservationsAsync(hostId, [Observation(hostId, 10, baseTime)], DateTimeOffset.UtcNow, default);
        await _repository.AddObservationsAsync(hostId, [Observation(hostId, 10, baseTime.AddMinutes(5))], DateTimeOffset.UtcNow, default);

        var latest = await _repository.GetLatestObservationAsync(hostId, 10, default);

        Assert.NotNull(latest);
        Assert.Equal(baseTime.AddMinutes(5), latest!.ObservedAtUtc);
    }

    [Fact]
    public async Task HeartbeatUpdatesTheHostLastSeenTimestamp()
    {
        var hostId = await SeedHostAsync();
        var now = DateTimeOffset.UtcNow;

        var recorded = await _repository.RecordHeartbeatAsync(
            new HeartbeatRequest { HostId = hostId, Sequence = 7, TimestampUtc = now, ProcessCount = 3, Status = "Healthy" },
            now,
            default);

        Assert.True(recorded);

        var host = await _db.Hosts.AsNoTracking().SingleAsync(h => h.Id == hostId);
        Assert.Equal(now, host.LastHeartbeatUtc);

        var unknown = await _repository.RecordHeartbeatAsync(
            new HeartbeatRequest { HostId = "no-such-host", Sequence = 1 },
            now,
            default);

        Assert.False(unknown);
    }

    public void Dispose()
    {
        _db.Dispose();

        foreach (var suffix in new[] { string.Empty, "-shm", "-wal" })
        {
            try
            {
                File.Delete(_databasePath + suffix);
            }
            catch (IOException)
            {
                // Best-effort cleanup.
            }
        }
    }

    private async Task SetHeartbeatAsync(string hostId, DateTimeOffset timestamp)
    {
        var host = await _db.Hosts.SingleAsync(h => h.Id == hostId);
        host.LastHeartbeatUtc = timestamp;
        await _db.SaveChangesAsync();
    }

    private async Task<string> SeedHostAsync(string hostname = "WG-REPO-001")
    {
        var hostId = $"repo-{Guid.NewGuid():N}";

        await _repository.UpsertHostAsync(
            new RegisterHostRequest
            {
                HostId = hostId,
                Hostname = hostname,
                OsVersion = "Windows 11",
                Architecture = "X64",
                AgentVersion = "1.0.0",
                Domain = "TEST",
                UserName = "tester",
            },
            certificateThumbprint: null,
            DateTimeOffset.UtcNow,
            default);

        return hostId;
    }

    private static DetectionEventDto Detection(string hostId, string eventId, string ruleId, int severity, DateTimeOffset? at = null)
        => new()
        {
            EventId = eventId,
            RuleId = ruleId,
            Severity = severity,
            Pid = 100,
            ProcessName = "cs2.exe",
            ImagePath = @"C:\Games\CS2\cs2.exe",
            Title = ruleId,
            SeverityBucket = severity >= 75 ? "Critical" : severity >= 50 ? "High" : "Medium",
            ObservedAtUtc = at ?? DateTimeOffset.UtcNow,
            Evidence = new Dictionary<string, string> { ["host"] = hostId },
        };

    private static ProcessObservationDto Observation(string hostId, int pid, DateTimeOffset at)
        => new()
        {
            Pid = pid,
            ProcessName = "cs2.exe",
            ImagePath = @"C:\Games\CS2\cs2.exe",
            ObservedAtUtc = at,
            Modules =
            [
                new ModuleDto { Path = @"C:\Windows\System32\ntdll.dll", Name = "ntdll.dll", SignatureStatus = "Signed" },
            ],
        };
}
