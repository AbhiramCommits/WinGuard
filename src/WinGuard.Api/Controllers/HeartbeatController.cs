using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using WinGuard.Api.Contracts;
using WinGuard.Core.Contracts;
using WinGuard.Api.Security;
using WinGuard.Api.Services;

namespace WinGuard.Api.Controllers;

/// <summary>Agent liveness ingest.</summary>
[ApiController]
[Route("api/v1/heartbeat")]
[AllowAnonymous]
[EnableRateLimiting("ingest")]
public sealed class HeartbeatController : ControllerBase
{
    private readonly IHostRepository _repository;
    private readonly ILogger<HeartbeatController> _logger;

    public HeartbeatController(IHostRepository repository, ILogger<HeartbeatController> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    [HttpPost]
    public async Task<ActionResult<HeartbeatResponse>> Post(
        [FromBody] HeartbeatRequest request,
        CancellationToken ct)
    {
        var verifiedHostId = HttpContext.GetVerifiedHostId();
        if (verifiedHostId is not null && !string.Equals(verifiedHostId, request.HostId, StringComparison.Ordinal))
        {
            _logger.LogWarning("Heartbeat host id {Verified} does not match payload host id {Claimed}.", verifiedHostId, request.HostId);
            return Forbid();
        }

        var accepted = await _repository.RecordHeartbeatAsync(request, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);

        if (!accepted)
        {
            // Unknown host: reject rather than silently creating one.
            return NotFound();
        }

        return Accepted(new HeartbeatResponse(request.HostId, DateTimeOffset.UtcNow, true));
    }
}
