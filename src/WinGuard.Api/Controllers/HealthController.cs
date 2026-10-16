using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WinGuard.Api.Contracts;
using WinGuard.Core;

namespace WinGuard.Api.Controllers;

/// <summary>Liveness probe used by scripts, load balancers and the e2e harness.</summary>
[ApiController]
[Route("healthz")]
[AllowAnonymous]
public sealed class HealthController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public HealthController(IConfiguration configuration) => _configuration = configuration;

    [HttpGet]
    public ActionResult<HealthResponse> Get()
        => Ok(new HealthResponse(
            "healthy",
            CoreInfo.AgentVersion,
            _configuration["Database:Provider"] ?? "Sqlite",
            DateTimeOffset.UtcNow));
}
