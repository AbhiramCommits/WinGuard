using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using WinGuard.Api.Contracts;
using WinGuard.Api.Security;
using WinGuard.Api.Services;
using WinGuard.Core.Contracts;
using WinGuard.Core.Security;

namespace WinGuard.Api.Controllers;

/// <summary>Host enrollment and fleet/status queries.</summary>
[ApiController]
[Route("api/v1/hosts")]
public sealed class HostsController : ControllerBase
{
    private readonly IHostRepository _repository;
    private readonly IHostKeyStore _keyStore;
    private readonly SignedPayloadOptions _signingOptions;
    private readonly ILogger<HostsController> _logger;

    public HostsController(
        IHostRepository repository,
        IHostKeyStore keyStore,
        IOptions<SignedPayloadOptions> signingOptions,
        ILogger<HostsController> logger)
    {
        _repository = repository;
        _keyStore = keyStore;
        _signingOptions = signingOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Registers (or re-registers) an agent and returns the per-host signing key.
    /// Exempt from HMAC signing because the host has no key yet; optionally
    /// gated by the enrollment secret.
    /// </summary>
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<RegisterHostResponse>> Register(
        [FromBody] RegisterHostRequest request,
        CancellationToken ct)
    {
        if (!string.IsNullOrEmpty(_signingOptions.EnrollmentSecret))
        {
            var provided = Request.Headers["X-WinGuard-Enrollment"].ToString();
            if (!string.Equals(provided, _signingOptions.EnrollmentSecret, StringComparison.Ordinal))
            {
                _logger.LogWarning("Rejected registration for {HostId}: invalid enrollment secret.", request.HostId);
                return Unauthorized();
            }
        }

        var thumbprint = HttpContext.Connection.ClientCertificate?.Thumbprint;
        var host = await _repository.UpsertHostAsync(request, thumbprint, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        var key = _keyStore.GetOrCreateKey(host.Id);

        _logger.LogInformation(
            "Host {HostId} registered (agent {AgentVersion}, os {OsVersion}).",
            host.Id,
            request.AgentVersion,
            request.OsVersion);

        return Ok(new RegisterHostResponse(
            host.Id,
            RequestSigning.ToBase64(key),
            "HMAC-SHA256",
            30,
            DateTimeOffset.UtcNow));
    }

    /// <summary>Fleet view: every host with derived status and worst open finding.</summary>
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<HostSummaryDto>>> List(CancellationToken ct)
        => Ok(await _repository.GetHostSummariesAsync(DateTimeOffset.UtcNow, ct).ConfigureAwait(false));

    /// <summary>Per-host detection history, newest first.</summary>
    [HttpGet("{id}/detections")]
    public async Task<ActionResult<IReadOnlyList<DetectionDto>>> Detections(
        string id,
        [FromQuery] DateTimeOffset? since,
        [FromQuery] int minSeverity = 0,
        [FromQuery] int limit = 200,
        CancellationToken ct = default)
        => Ok(await _repository.GetHostDetectionsAsync(id, since, minSeverity, limit, ct).ConfigureAwait(false));
}
