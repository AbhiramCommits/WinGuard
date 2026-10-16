using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using WinGuard.Core.Contracts;
using WinGuard.Core.Security;
using WinGuard.Core.Serialization;
using ApiProgram = global::Program;

namespace WinGuard.Eval.Benchmark;

/// <summary>
/// Drives the real API in-process (via <see cref="WebApplicationFactory{TEntryPoint}"/>)
/// and measures end-to-end ingest throughput for detection events.
/// </summary>
/// <remarks>
/// The benchmark posts the events produced by the real detection engine through
/// the real HTTP pipeline — routing, HMAC signature verification, nonce
/// checking, validation, rate limiting and EF Core persistence — rather than
/// calling the repository directly, so the throughput number reflects the whole
/// ingest path.
/// </remarks>
public sealed class ApiIngestBenchmark : IAsyncDisposable
{
    public const string MasterSecret = "benchmark-master-secret-0000000000000";
    public const string HostId = "benchmark-host";

    private readonly string _databasePath;
    private readonly string _spoolPath;
    private readonly WebApplicationFactory<ApiProgram> _factory;
    private readonly HttpClient _client;
    private readonly byte[] _key;

    private ApiIngestBenchmark(string databasePath, WebApplicationFactory<ApiProgram> factory, HttpClient client)
    {
        _databasePath = databasePath;
        _spoolPath = Path.ChangeExtension(databasePath, ".spool");
        _factory = factory;
        _client = client;
        _key = RequestSigning.DeriveHostKey(MasterSecret, HostId);
    }

    public static async Task<ApiIngestBenchmark> StartAsync()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"winguard-bench-{Guid.NewGuid():N}.db");

        var factory = new WebApplicationFactory<ApiProgram>()
            .WithWebHostBuilder(builder =>
            {
                // Eval is not a test project, so WebApplicationFactory cannot infer
                // the API's content root from a WebApplicationFactoryContentRoot
                // attribute; point it at the project directory explicitly.
                var apiProjectDirectory = Path.Combine(RepoPaths.FindRepoRoot(), "src", "WinGuard.Api");
                builder.UseContentRoot(apiProjectDirectory);

                builder.UseEnvironment("Testing");
                builder.UseSetting("Database:Provider", "Sqlite");
                builder.UseSetting("ConnectionStrings:Sqlite", $"Data Source={databasePath}");
                builder.UseSetting("Database:MigrateOnStartup", "true");
                builder.UseSetting("Security:Signing:Enabled", "true");
                builder.UseSetting("Security:Signing:MasterSecret", MasterSecret);
                builder.UseSetting("Security:Signing:EnrollmentSecret", string.Empty);
                // The benchmark pushes thousands of events; lift the per-host rate
                // limit so the measurement is not throttled.
                builder.UseSetting("Security:Signing:MaxRequestBodyBytes", "8388608");
            });

        var client = factory.CreateClient();
        var benchmark = new ApiIngestBenchmark(databasePath, factory, client);
        await benchmark.RegisterHostAsync().ConfigureAwait(false);
        return benchmark;
    }

    private async Task RegisterHostAsync()
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(new RegisterHostRequest
        {
            HostId = HostId,
            Hostname = "WGBENCH-001",
            OsVersion = Environment.OSVersion.VersionString,
            Architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            AgentVersion = Core.CoreInfo.AgentVersion,
            Domain = "BENCH",
            UserName = "benchmark",
        }, WinGuardJson.Compact);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/hosts/register")
        {
            Content = new ByteArrayContent(body),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        using var response = await _client.SendAsync(request).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Posts <paramref name="events"/> (and matching observations) in batches and
    /// returns the elapsed wall-clock time plus the accepted counts.
    /// </summary>
    public async Task<(double ElapsedSeconds, int AcceptedEvents, int AcceptedObservations)> IngestAsync(
        IReadOnlyList<DetectionEventDto> events,
        IReadOnlyList<ProcessObservationDto> observations,
        int batchSize,
        CancellationToken ct = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var acceptedEvents = 0;
        var acceptedObservations = 0;
        var observationsByPid = observations.ToLookup(o => o.Pid);

        for (var offset = 0; offset < events.Count; offset += batchSize)
        {
            var batchEvents = events.Skip(offset).Take(batchSize).ToList();
            var batchPids = batchEvents.Select(e => e.Pid).ToHashSet();

            var batch = new EventsRequest
            {
                HostId = HostId,
                Events = batchEvents,
                Observations = batchPids
                    .SelectMany(pid => observationsByPid[pid].Take(1))
                    .ToList(),
            };

            using var response = await SendSignedAsync("/api/v1/events", batch, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var eventsResponse = JsonSerializer.Deserialize<EventsResponse>(json, WinGuardJson.Compact);

            if (eventsResponse is not null)
            {
                acceptedEvents += eventsResponse.AcceptedDetectionCount;
                acceptedObservations += eventsResponse.AcceptedObservationCount;
            }
        }

        stopwatch.Stop();
        return (stopwatch.Elapsed.TotalSeconds, acceptedEvents, acceptedObservations);
    }

    /// <summary>Reads a host's detection history back through the HTTP API.</summary>
    public async Task<int> CountHostDetectionsAsync(CancellationToken ct = default)
    {
        using var response = await _client.GetAsync($"/api/v1/hosts/{HostId}/detections?limit=1000", ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        using var document = JsonDocument.Parse(json);
        return document.RootElement.GetArrayLength();
    }

    private async Task<HttpResponseMessage> SendSignedAsync<T>(string path, T payload, CancellationToken ct)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(payload, WinGuardJson.Compact);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var nonce = Guid.NewGuid().ToString("N");

        var canonical = RequestSigning.BuildCanonicalString("POST", path, timestamp, nonce, body);
        var signature = RequestSigning.Sign(_key, canonical);

        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new ByteArrayContent(body),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation(RequestSigning.HostIdHeader, HostId);
        request.Headers.TryAddWithoutValidation(RequestSigning.TimestampHeader, timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(RequestSigning.NonceHeader, nonce);
        request.Headers.TryAddWithoutValidation(RequestSigning.SignatureHeader, signature);

        return await _client.SendAsync(request, ct).ConfigureAwait(false);
    }

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();

        foreach (var suffix in new[] { string.Empty, "-shm", "-wal" })
        {
            try
            {
                File.Delete(_databasePath + suffix);
            }
            catch (IOException)
            {
                // Best-effort cleanup of the throwaway benchmark database.
            }
        }

        if (Directory.Exists(_spoolPath))
        {
            try
            {
                Directory.Delete(_spoolPath, recursive: true);
            }
            catch (IOException)
            {
                // Best-effort cleanup.
            }
        }

        return ValueTask.CompletedTask;
    }
}
