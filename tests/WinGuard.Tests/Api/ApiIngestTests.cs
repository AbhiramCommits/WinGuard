using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using WinGuard.Core.Contracts;

namespace WinGuard.Tests.Api;

/// <summary>
/// End-to-end tests over the real API pipeline: routing, HMAC middleware,
/// validation, EF Core persistence and the query endpoints.
/// </summary>
public sealed class ApiIngestTests : IClassFixture<WinGuardApiFactory>
{
    private readonly WinGuardApiFactory _factory;
    private readonly HttpClient _client;

    public ApiIngestTests(WinGuardApiFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task HealthzIsAnonymousAndHealthy()
    {
        using var response = await _client.GetAsync("/healthz");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = await TestSigning.ReadDocumentAsync(response);
        Assert.Equal("healthy", document.RootElement.GetProperty("status").GetString());
        Assert.Equal("Sqlite", document.RootElement.GetProperty("databaseProvider").GetString());
    }

    [Fact]
    public async Task RegistrationReturnsAPerHostSigningKey()
    {
        var hostId = $"reg-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        Assert.NotEmpty(key);
        Assert.Equal(_factory.KeyFor(hostId), key);
    }

    [Fact]
    public async Task HappyPathHeartbeatAndEventsArePersisted()
    {
        var hostId = $"happy-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        using var heartbeat = await _client.SendAsync(TestSigning.SignedPost(
            "/api/v1/heartbeat",
            new HeartbeatRequest
            {
                HostId = hostId,
                AgentVersion = "1.0.0",
                Sequence = 1,
                TimestampUtc = DateTimeOffset.UtcNow,
                ProcessCount = 12,
                Status = "Healthy",
            },
            hostId,
            key));

        Assert.Equal(HttpStatusCode.Accepted, heartbeat.StatusCode);

        var observation = new ProcessObservationDto
        {
            Pid = 4242,
            ProcessName = "cs2.exe",
            ImagePath = @"C:\Games\CS2\cs2.exe",
            ParentPid = 100,
            UserName = "gamer",
            IsProtected = true,
            ObservedAtUtc = DateTimeOffset.UtcNow,
            Modules =
            [
                new ModuleDto
                {
                    Path = @"C:\Windows\System32\ntdll.dll",
                    Name = "ntdll.dll",
                    BaseAddress = "0x7FF600001000",
                    Size = 2142208,
                    SignatureStatus = "Signed",
                    SignerName = "Microsoft Windows",
                    IsBackedByFile = true,
                    MemoryProtection = "PAGE_EXECUTE_READ",
                },
            ],
        };

        using var events = await _client.SendAsync(TestSigning.SignedPost(
            "/api/v1/events",
            new EventsRequest
            {
                HostId = hostId,
                Events =
                [
                    new DetectionEventDto
                    {
                        EventId = $"evt-{Guid.NewGuid():N}",
                        RuleId = "R002",
                        Severity = 83,
                        Pid = 4242,
                        ProcessName = "cs2.exe",
                        ImagePath = @"C:\Games\CS2\cs2.exe",
                        Title = "InjectedModulePath",
                        SeverityBucket = "Critical",
                        ObservedAtUtc = DateTimeOffset.UtcNow,
                        Evidence = new Dictionary<string, string> { ["modulePath"] = @"C:\Users\Public\payload.dll" },
                    },
                ],
                Observations = [observation],
            },
            hostId,
            key));

        Assert.Equal(HttpStatusCode.Accepted, events.StatusCode);

        using var summaryDocument = await TestSigning.ReadDocumentAsync(await _client.GetAsync("/api/v1/hosts"));
        var host = summaryDocument.RootElement.EnumerateArray().Single(h => h.GetProperty("hostId").GetString() == hostId);

        Assert.Equal("Online", host.GetProperty("status").GetString());
        Assert.Equal(1, host.GetProperty("detectionCount").GetInt32());
        Assert.Equal(83, host.GetProperty("highestSeverity").GetInt32());
        Assert.Equal("Critical", host.GetProperty("highestSeverityBucket").GetString());
    }

    [Fact]
    public async Task BadSignatureIsRejected()
    {
        var hostId = $"badsig-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        using var response = await _client.SendAsync(TestSigning.SignedPost(
            "/api/v1/heartbeat",
            new HeartbeatRequest { HostId = hostId, Sequence = 1 },
            hostId,
            key,
            signatureOverride: Convert.ToBase64String(new byte[32])));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TamperedBodyIsRejected()
    {
        var hostId = $"tampered-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var nonce = $"nonce-{Guid.NewGuid():N}";

        // Sign the original body, then transmit a different one under the same
        // headers: the body hash must not match.
        var originalBody = JsonSerializer.SerializeToUtf8Bytes(new HeartbeatRequest { HostId = hostId, Sequence = 1 });
        var tamperedBody = JsonSerializer.SerializeToUtf8Bytes(new HeartbeatRequest { HostId = hostId, Sequence = 2 });

        var signature = WinGuard.Core.Security.RequestSigning.Sign(
            key,
            WinGuard.Core.Security.RequestSigning.BuildCanonicalString(
                "POST", "/api/v1/heartbeat", timestamp, nonce, originalBody));

        using var response = await _client.SendAsync(TestSigning.SignedPost(
            "/api/v1/heartbeat",
            new HeartbeatRequest { HostId = hostId },
            hostId,
            key,
            unixTimestamp: timestamp,
            nonce: nonce,
            bodyOverride: tamperedBody,
            signatureOverride: signature));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ReplayedNonceIsRejected()
    {
        var hostId = $"replay-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        var nonce = $"nonce-{Guid.NewGuid():N}";
        var payload = new HeartbeatRequest { HostId = hostId, Sequence = 1, TimestampUtc = DateTimeOffset.UtcNow };

        using var first = await _client.SendAsync(TestSigning.SignedPost("/api/v1/heartbeat", payload, hostId, key, nonce: nonce));
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);

        using var second = await _client.SendAsync(TestSigning.SignedPost("/api/v1/heartbeat", payload, hostId, key, nonce: nonce));
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
    }

    [Fact]
    public async Task ClockSkewBeyondTheWindowIsRejected()
    {
        var hostId = $"skew-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        var tenMinutesAgo = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds();

        using var response = await _client.SendAsync(TestSigning.SignedPost(
            "/api/v1/heartbeat",
            new HeartbeatRequest { HostId = hostId, Sequence = 1 },
            hostId,
            key,
            unixTimestamp: tenMinutesAgo));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RequestWithinTheSkewWindowIsAccepted()
    {
        var hostId = $"skew-ok-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        var twoMinutesAgo = DateTimeOffset.UtcNow.AddMinutes(-2).ToUnixTimeSeconds();

        using var response = await _client.SendAsync(TestSigning.SignedPost(
            "/api/v1/heartbeat",
            new HeartbeatRequest { HostId = hostId, Sequence = 1, TimestampUtc = DateTimeOffset.UtcNow },
            hostId,
            key,
            unixTimestamp: twoMinutesAgo));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
    }

    [Fact]
    public async Task OversizedPayloadIsRejectedWith413()
    {
        var hostId = $"big-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        // ~1.5 MiB of evidence pushes the batch past the 1 MiB cap.
        var huge = new string('x', 1_500_000);

        var batch = new EventsRequest
        {
            HostId = hostId,
            Events =
            [
                new DetectionEventDto
                {
                    RuleId = "R001",
                    Severity = 45,
                    Pid = 1,
                    ProcessName = "big.exe",
                    SeverityBucket = "Medium",
                    ObservedAtUtc = DateTimeOffset.UtcNow,
                    Evidence = new Dictionary<string, string> { ["blob"] = huge },
                },
            ],
        };

        using var response = await _client.SendAsync(TestSigning.SignedPost("/api/v1/events", batch, hostId, key));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task UnknownHostIsNotFound()
    {
        var hostId = $"ghost-{Guid.NewGuid():N}";
        var key = _factory.KeyFor(hostId);

        using var response = await _client.SendAsync(TestSigning.SignedPost(
            "/api/v1/heartbeat",
            new HeartbeatRequest { HostId = hostId, Sequence = 1, TimestampUtc = DateTimeOffset.UtcNow },
            hostId,
            key));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task DuplicateEventIdsAreIdempotent()
    {
        var hostId = $"dup-{Guid.NewGuid():N}";
        var key = await _factory.RegisterHostAsync(_client, hostId);

        var eventId = $"evt-{Guid.NewGuid():N}";

        EventsRequest Batch() => new()
        {
            HostId = hostId,
            Events =
            [
                new DetectionEventDto
                {
                    EventId = eventId,
                    RuleId = "R003",
                    Severity = 65,
                    Pid = 10,
                    ProcessName = "dup.exe",
                    SeverityBucket = "High",
                    ObservedAtUtc = DateTimeOffset.UtcNow,
                },
            ],
        };

        using (var first = await _client.SendAsync(TestSigning.SignedPost("/api/v1/events", Batch(), hostId, key)))
        {
            Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
            using var document = await TestSigning.ReadDocumentAsync(first);
            Assert.Equal(1, document.RootElement.GetProperty("acceptedDetectionCount").GetInt32());
        }

        using (var second = await _client.SendAsync(TestSigning.SignedPost("/api/v1/events", Batch(), hostId, key)))
        {
            Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
            using var document = await TestSigning.ReadDocumentAsync(second);
            Assert.Equal(0, document.RootElement.GetProperty("acceptedDetectionCount").GetInt32());
            Assert.Equal(1, document.RootElement.GetProperty("duplicateDetectionCount").GetInt32());
        }

        using var recent = await TestSigning.ReadDocumentAsync(await _client.GetAsync($"/api/v1/hosts/{hostId}/detections"));
        Assert.Equal(1, recent.RootElement.GetArrayLength());
    }

    [Fact]
    public async Task InvalidRegistrationIsRejectedByValidation()
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(new { hostname = "no-id" });

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/hosts/register")
        {
            Content = new ByteArrayContent(body),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation("X-WinGuard-Enrollment", WinGuardApiFactory.EnrollmentSecret);

        using var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RegistrationWithoutTheEnrollmentSecretIsRejected()
    {
        var body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { hostId = "nope", hostname = "nope" }));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/hosts/register")
        {
            Content = new ByteArrayContent(body),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        using var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
