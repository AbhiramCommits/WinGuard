using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WinGuard.Api.Contracts;
using WinGuard.Api.Mapping;
using WinGuard.Api.Services;

namespace WinGuard.Api.Controllers;

/// <summary>Per-process drill-down for the analyst dashboard.</summary>
[ApiController]
[Route("api/v1/processes")]
[AllowAnonymous]
public sealed class ProcessesController : ControllerBase
{
    private readonly IHostRepository _repository;

    public ProcessesController(IHostRepository repository) => _repository = repository;

    /// <summary>
    /// Returns the latest observation of a PID together with every rule that
    /// fired on it: modules with signature status, memory regions, evidence and
    /// the PID's timeline.
    /// </summary>
    [HttpGet("{hostId}/{pid:int}")]
    public async Task<ActionResult<ProcessDrilldownDto>> Get(string hostId, int pid, CancellationToken ct)
    {
        var observation = await _repository.GetLatestObservationAsync(hostId, pid, ct).ConfigureAwait(false);
        var detections = await _repository.GetProcessDetectionsAsync(hostId, pid, 200, ct).ConfigureAwait(false);

        if (observation is null && detections.Count == 0)
        {
            return NotFound();
        }

        var timeline = detections
            .OrderBy(d => d.ObservedAtUtc)
            .Select(d => new ProcessTimelineEntryDto(d.RuleId, d.Title, d.Severity, d.SeverityBucket, d.ObservedAtUtc))
            .ToList();

        return Ok(new ProcessDrilldownDto(
            hostId,
            pid,
            observation?.ProcessName ?? detections[0].ProcessName,
            observation?.ImagePath ?? detections[0].ImagePath,
            observation?.ParentPid ?? 0,
            observation?.UserName ?? string.Empty,
            observation?.CommandLine ?? string.Empty,
            observation?.IsProtected ?? false,
            observation?.ObservedAtUtc,
            MappingExtensions.DeserializeModules(observation?.ModulesJson),
            MappingExtensions.DeserializeRegions(observation?.MemoryRegionsJson),
            detections,
            timeline));
    }
}
