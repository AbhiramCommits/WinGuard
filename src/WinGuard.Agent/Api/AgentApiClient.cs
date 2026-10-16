using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using WinGuard.Core;
using WinGuard.Core.Contracts;
using WinGuard.Core.Models;
using WinGuard.Core.Security;
using WinGuard.Core.Serialization;

namespace WinGuard.Agent.Api;

/// <summary>
/// Signed HTTP client for the WinGuard API.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>every request is HMAC-SHA256 signed over
///   method+path+timestamp+nonce+body;</description></item>
///   <item><description>transient failures are retried with exponential backoff
///   and jitter;</description></item>
///   <item><description>batches that still cannot be delivered are written to a
///   disk spool and replayed later.</description></item>
/// </list>
/// </remarks>
public sealed class AgentApiClient
{
    private readonly HttpClient _http;
    private readonly AgentApiOptions _options;
    private readonly DetectionSpool _spool;
    private readonly ILogger<AgentApiClient> _logger;
    private readonly SemaphoreSlim _flushLock = new(1, 1);
    private byte[]? _signingKey;

    public AgentApiClient(
        HttpClient http,
        IOptions<AgentApiOptions> options,
        DetectionSpool spool,
        ILogger<AgentApiClient> logger)
    {
        _http = http;
        _options = options.Value;
        _spool = spool;
        _logger = logger;
        _http.BaseAddress = new Uri(_options.BaseUrl);
        _http.Timeout = TimeSpan.FromSeconds(30);

        if (!string.IsNullOrWhiteSpace(_options.SigningKey))
        {
            _signingKey = Convert.FromBase64String(_options.SigningKey);
        }
    }

    /// <summary>True once a signing key is available (after registration).</summary>
    public bool IsRegistered => _signingKey is not null;

    /// <summary>Number of batches currently spooled on disk.</summary>
    public int SpooledBatches => _spool.Count;

    public async Task<bool> RegisterAsync(HostInfo host, CancellationToken ct)
    {
        var request = new RegisterHostRequest
        {
            HostId = host.HostId,
            Hostname = host.Hostname,
            OsVersion = host.OsVersion,
            Architecture = host.Architecture,
            AgentVersion = host.AgentVersion,
            Domain = host.Domain,
            UserName = host.UserName,
        };

        var response = await PostJsonAsync("/api/v1/hosts/register", request, host.HostId, sign: false, ct)
            .ConfigureAwait(false);

        if (response is null)
        {
            return false;
        }

        var registration = JsonSerializer.Deserialize<RegisterHostResponse>(response, WinGuardJson.Compact);
        if (registration is null || string.IsNullOrWhiteSpace(registration.SigningKey))
        {
            _logger.LogError("Registration response did not contain a signing key.");
            return false;
        }

        _signingKey = Convert.FromBase64String(registration.SigningKey);
        _logger.LogInformation("Registered with the API as {HostId}; heartbeat interval {Interval}s.",
            registration.HostId, registration.HeartbeatIntervalSeconds);

        return true;
    }

    public async Task<bool> SendHeartbeatAsync(Heartbeat heartbeat, CancellationToken ct)
    {
        var request = new HeartbeatRequest
        {
            HostId = heartbeat.HostId,
            AgentVersion = heartbeat.AgentVersion,
            Sequence = heartbeat.Sequence,
            TimestampUtc = heartbeat.TimestampUtc,
            ProcessCount = heartbeat.ProcessCount,
            PendingEventCount = heartbeat.PendingEventCount,
            Status = heartbeat.Status,
        };

        var response = await PostJsonAsync("/api/v1/heartbeat", request, heartbeat.HostId, sign: true, ct)
            .ConfigureAwait(false);

        return response is not null;
    }

    /// <summary>Sends a batch, spooling it to disk when the API cannot be reached.</summary>
    public async Task<bool> SendEventsAsync(EventsRequest batch, CancellationToken ct)
    {
        var response = await PostJsonAsync("/api/v1/events", batch, batch.HostId, sign: true, ct)
            .ConfigureAwait(false);

        if (response is not null)
        {
            return true;
        }

        await _spool.EnqueueAsync(batch, ct).ConfigureAwait(false);
        return false;
    }

    /// <summary>Replays spooled batches oldest-first. Stops at the first failure.</summary>
    public async Task<int> FlushSpoolAsync(CancellationToken ct)
    {
        if (!await _flushLock.WaitAsync(0, ct).ConfigureAwait(false))
        {
            return 0;
        }

        try
        {
            var sent = 0;

            foreach (var path in _spool.Pending())
            {
                var batch = await _spool.ReadAsync(path, ct).ConfigureAwait(false);
                if (batch is null)
                {
                    _spool.Complete(path);
                    continue;
                }

                var response = await PostJsonAsync("/api/v1/events", batch, batch.HostId, sign: true, ct)
                    .ConfigureAwait(false);

                if (response is null)
                {
                    break; // still offline; leave the rest of the spool in place
                }

                _spool.Complete(path);
                sent++;
            }

            if (sent > 0)
            {
                _logger.LogInformation("Replayed {Count} spooled detection batches.", sent);
            }

            return sent;
        }
        finally
        {
            _flushLock.Release();
        }
    }

    private async Task<string?> PostJsonAsync<T>(string path, T payload, string hostId, bool sign, CancellationToken ct)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(payload, WinGuardJson.Compact);

        for (var attempt = 0; attempt <= _options.MaxRetries; attempt++)
        {
            if (ct.IsCancellationRequested)
            {
                return null;
            }

            try
            {
                using var request = BuildRequest(path, body, hostId, sign);
                using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                }

                if (IsTransient(response.StatusCode) && attempt < _options.MaxRetries)
                {
                    await DelayAsync(attempt, ct).ConfigureAwait(false);
                    continue;
                }

                _logger.LogWarning(
                    "API rejected {Method} {Path} with {StatusCode} (host {HostId}).",
                    request.Method,
                    path,
                    (int)response.StatusCode,
                    hostId);

                return null;
            }
            catch (HttpRequestException ex) when (attempt < _options.MaxRetries)
            {
                _logger.LogDebug(ex, "Transient transport failure posting {Path} (attempt {Attempt}).", path, attempt + 1);
                await DelayAsync(attempt, ct).ConfigureAwait(false);
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested && attempt < _options.MaxRetries)
            {
                await DelayAsync(attempt, ct).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogWarning(ex, "Could not reach the API at {BaseUrl}.", _options.BaseUrl);
                return null;
            }
            catch (TaskCanceledException)
            {
                _logger.LogWarning("Request to {BaseUrl} timed out.", _options.BaseUrl);
                return null;
            }
        }

        return null;
    }

    private HttpRequestMessage BuildRequest(string path, byte[] body, string hostId, bool sign)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new ByteArrayContent(body),
        };

        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation(RequestSigning.AgentVersionHeader, CoreInfo.AgentVersion);

        if (sign)
        {
            if (_signingKey is null)
            {
                throw new InvalidOperationException("Cannot sign a request before the agent has registered.");
            }

            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

            var canonical = RequestSigning.BuildCanonicalString("POST", path, timestamp, nonce, body);
            var signature = RequestSigning.Sign(_signingKey, canonical);

            request.Headers.TryAddWithoutValidation(RequestSigning.HostIdHeader, hostId);
            request.Headers.TryAddWithoutValidation(RequestSigning.TimestampHeader, timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture));
            request.Headers.TryAddWithoutValidation(RequestSigning.NonceHeader, nonce);
            request.Headers.TryAddWithoutValidation(RequestSigning.SignatureHeader, signature);
        }

        return request;
    }

    private async Task DelayAsync(int attempt, CancellationToken ct)
    {
        var backoff = _options.InitialBackoffSeconds * Math.Pow(2, attempt);
        var jitter = Random.Shared.NextDouble() * 0.25 * backoff;
        var delay = TimeSpan.FromSeconds(Math.Min(backoff + jitter, 60));

        _logger.LogDebug("Backing off for {Delay:F1}s before retrying.", delay.TotalSeconds);
        await Task.Delay(delay, ct).ConfigureAwait(false);
    }

    private static bool IsTransient(HttpStatusCode statusCode)
        => statusCode is HttpStatusCode.RequestTimeout
            or HttpStatusCode.TooManyRequests
            or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;
}
