using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WinGuard.Api.Contracts;
using WinGuard.Api.Services;

namespace WinGuard.Api.Controllers;

/// <summary>Cross-fleet detection queries.</summary>
[ApiController]
[Route("api/v1/detections")]
[AllowAnonymous]
public sealed class DetectionsController : ControllerBase
{
    private readonly IHostRepository _repository;

    public DetectionsController(IHostRepository repository) => _repository = repository;

    /// <summary>Reverse-chronological detection feed for the analyst timeline.</summary>
    [HttpGet("recent")]
    public async Task<ActionResult<IReadOnlyList<DetectionDto>>> Recent(
        [FromQuery] int limit = 100,
        CancellationToken ct = default)
        => Ok(await _repository.GetRecentDetectionsAsync(limit, ct).ConfigureAwait(false));
}
