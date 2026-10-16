using System.Net;
using WinGuard.Core.Contracts;

namespace WinGuard.Tests.Api;

/// <summary>Read-side API behaviour: host status, per-host history, drill-down.</summary>
public sealed class ApiQueryTests : IClassFixture<WinGuardApiFactory>
{
    private readonly WinGuardApiFactory _factory;
    private readonly HttpClient _client;

    public ApiQueryTests(WinGuardApiFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task HostDetectionsAreFilteredByMinSeverityAndSince()
    {
        var hostId = $"hist-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        var now = DateTimeOffset.UtcNow;
        var old = now.AddHours(-2);

        var batch = new EventsRequest
        {
            HostId = hostId,
            Events =
            [
                Event("R001", 45, old, "low-old"),
                Event("R002", 83, now, "high-new"),
                Event("R003", 65, now, "high-new"),
            ],
        };

        using (var ingest = await _client.SendAsync(TestSigning.SignedPost("/api/v1/events", batch, hostId, key)))
        {
            Assert.Equal(HttpStatusCode.Accepted, ingest.StatusCode);
        }

        using (var all = await TestSigning.ReadDocumentAsync(await _client.GetAsync($"/api/v1/hosts/{hostId}/detections")))
        {
            Assert.Equal(3, all.RootElement.GetArrayLength());
        }

        using (var severe = await TestSigning.ReadDocumentAsync(await _client.GetAsync($"/api/v1/hosts/{hostId}/detections?minSeverity=60")))
        {
            Assert.Equal(2, severe.RootElement.GetArrayLength());
            Assert.All(
                severe.RootElement.EnumerateArray(),
                e => Assert.True(e.GetProperty("severity").GetInt32() >= 60));
        }

        using (var recent = await TestSigning.ReadDocumentAsync(await _client.GetAsync(
            $"/api/v1/hosts/{hostId}/detections?since={Uri.EscapeDataString(now.AddMinutes(-5).ToString("O"))}")))
        {
            Assert.Equal(2, recent.RootElement.GetArrayLength());
        }

        // History is scoped per host.
        using var otherHost = await TestSigning.ReadDocumentAsync(await _client.GetAsync("/api/v1/hosts/some-other-host/detections"));
        Assert.Equal(0, otherHost.RootElement.GetArrayLength());
    }

    [Fact]
    public async Task RecentDetectionsAreReverseChronologicalAndLimited()
    {
        using var document = await TestSigning.ReadDocumentAsync(await _client.GetAsync("/api/v1/detections/recent?limit=5"));

        var items = document.RootElement.EnumerateArray().ToList();
        Assert.True(items.Count <= 5);

        var timestamps = items.Select(i => i.GetProperty("observedAtUtc").GetDateTimeOffset()).ToList();
        Assert.Equal(timestamps.OrderByDescending(t => t), timestamps);
    }

    [Fact]
    public async Task ProcessDrilldownReturnsModulesEvidenceAndTimeline()
    {
        var hostId = $"drill-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);
        const int pid = 9182;

        var observedAt = DateTimeOffset.UtcNow;

        var batch = new EventsRequest
        {
            HostId = hostId,
            Events =
            [
                Event("R002", 83, observedAt, "drill", pid),
                Event("R005", 73, observedAt.AddSeconds(1), "drill", pid),
            ],
            Observations =
            [
                new ProcessObservationDto
                {
                    Pid = pid,
                    ProcessName = "cs2.exe",
                    ImagePath = @"C:\Games\CS2\cs2.exe",
                    ParentPid = 42,
                    UserName = "gamer",
                    IsProtected = true,
                    ObservedAtUtc = observedAt,
                    Modules =
                    [
                        new ModuleDto
                        {
                            Path = @"C:\Users\Public\payload.dll",
                            Name = "payload.dll",
                            BaseAddress = "0x7FF601234000",
                            Size = 200704,
                            SignatureStatus = "Unsigned",
                            IsBackedByFile = true,
                            MemoryProtection = "PAGE_EXECUTE_READ",
                        },
                    ],
                    MemoryRegions =
                    [
                        new MemoryRegionDto
                        {
                            BaseAddress = "0x7FF602000000",
                            Size = 0x10000,
                            Protection = "PAGE_EXECUTE_READWRITE",
                            RegionType = "MEM_PRIVATE",
                            IsExecutable = true,
                            IsWritable = true,
                            IsBackedByFile = false,
                        },
                    ],
                },
            ],
        };

        using (var ingest = await _client.SendAsync(TestSigning.SignedPost("/api/v1/events", batch, hostId, key)))
        {
            Assert.Equal(HttpStatusCode.Accepted, ingest.StatusCode);
        }

        using var response = await _client.GetAsync($"/api/v1/processes/{hostId}/{pid}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = await TestSigning.ReadDocumentAsync(response);
        var root = document.RootElement;

        Assert.Equal("cs2.exe", root.GetProperty("processName").GetString());
        Assert.True(root.GetProperty("isProtected").GetBoolean());

        var modules = root.GetProperty("modules").EnumerateArray().ToList();
        Assert.Single(modules);
        Assert.Equal("Unsigned", modules[0].GetProperty("signatureStatus").GetString());

        var regions = root.GetProperty("memoryRegions").EnumerateArray().ToList();
        Assert.Single(regions);
        Assert.True(regions[0].GetProperty("isWritable").GetBoolean());

        var detections = root.GetProperty("detections").EnumerateArray().ToList();
        Assert.Equal(2, detections.Count);

        // Evidence round-trips through the JSON column.
        Assert.True(detections.All(d => d.GetProperty("evidence").EnumerateObject().Any()));

        var timeline = root.GetProperty("timeline").EnumerateArray().ToList();
        Assert.Equal(2, timeline.Count);
        Assert.True(
            timeline[0].GetProperty("observedAtUtc").GetDateTimeOffset()
            <= timeline[1].GetProperty("observedAtUtc").GetDateTimeOffset());
    }

    [Fact]
    public async Task UnknownProcessReturnsNotFound()
    {
        using var response = await _client.GetAsync("/api/v1/processes/no-such-host/1234");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task FleetViewIncludesHostnameAndAgentVersion()
    {
        var hostId = $"fleet-{Guid.NewGuid():N}";
        await _factory.RegisterHostAsync(_client, hostId, "WGFLEET-042");

        using var document = await TestSigning.ReadDocumentAsync(await _client.GetAsync("/api/v1/hosts"));

        var host = document.RootElement.EnumerateArray().Single(h => h.GetProperty("hostId").GetString() == hostId);
        Assert.Equal("WGFLEET-042", host.GetProperty("hostname").GetString());
        Assert.Equal("1.0.0", host.GetProperty("agentVersion").GetString());

        // Registered but never heart-beaten: the fleet view must say Offline.
        Assert.Equal("Offline", host.GetProperty("status").GetString());
    }

    private static DetectionEventDto Event(
        string ruleId,
        int severity,
        DateTimeOffset observedAt,
        string eventIdPrefix,
        int pid = 4242) => new()
        {
            EventId = $"{eventIdPrefix}-{ruleId}-{Guid.NewGuid():N}",
            RuleId = ruleId,
            Severity = severity,
            Pid = pid,
            ProcessName = "cs2.exe",
            ImagePath = @"C:\Games\CS2\cs2.exe",
            Title = ruleId,
            SeverityBucket = severity >= 75 ? "Critical" : "High",
            ObservedAtUtc = observedAt,
            Evidence = new Dictionary<string, string> { ["k"] = "v" },
        };
}
