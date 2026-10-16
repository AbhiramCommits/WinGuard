using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using WinGuard.Api.Security;
using WinGuard.Api.Services;
using WinGuard.Core.Contracts;

namespace WinGuard.Api.Controllers;

/// <summary>Batch ingest of detection events and process observations.</summary>
[ApiController]
[Route("api/v1/events")]
[AllowAnonymous]
[EnableRateLimiting("ingest")]
public sealed class EventsController : ControllerBase
{
    private readonly IHostRepository _repository;
    private readonly ILogger<EventsController> _logger;

    public EventsController(IHostRepository repository, ILogger<EventsController> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    [HttpPost]
    public async Task<ActionResult<EventsResponse>> Post([FromBody] EventsRequest request, CancellationToken ct)
    {
        var verifiedHostId = HttpContext.GetVerifiedHostId();
        if (verifiedHostId is not null && !string.Equals(verifiedHostId, request.HostId, StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "Event batch host id {Verified} does not match payload host id {Claimed}.",
                verifiedHostId,
                request.HostId);
            return Forbid();
        }

        var host = await _repository.FindHostAsync(request.HostId, ct).ConfigureAwait(false);
        if (host is null)
        {
            return NotFound();
        }

        var now = DateTimeOffset.UtcNow;
        var (accepted, duplicates) = await _repository
            .AddDetectionsAsync(request.HostId, request.Events, now, ct)
            .ConfigureAwait(false);

        var observations = await _repository
            .AddObservationsAsync(request.HostId, request.Observations, now, ct)
            .ConfigureAwait(false);

        // Structured log: counts and rule ids only — never the raw payload.
        _logger.LogInformation(
            "Ingested {Accepted} detections ({Duplicates} duplicates) and {Observations} observations from {HostId}; rules [{Rules}].",
            accepted,
            duplicates,
            observations,
            request.HostId,
            string.Join(',', request.Events.Select(e => e.RuleId).Distinct(StringComparer.Ordinal).OrderBy(r => r, StringComparer.Ordinal)));

        return Accepted(new EventsResponse(request.HostId, accepted, duplicates, observations, now));
    }
}
