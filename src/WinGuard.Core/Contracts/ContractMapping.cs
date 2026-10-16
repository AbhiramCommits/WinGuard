using WinGuard.Core.Models;

namespace WinGuard.Core.Contracts;

/// <summary>
/// Conversions from the collector's model types to the wire contracts. Shared by
/// the agent (producer) and the API (consumer) so both sides agree exactly on
/// how a snapshot becomes an observation payload.
/// </summary>
public static class ContractMapping
{
    public static DetectionEventDto ToDto(this DetectionEvent detectionEvent)
        => new()
        {
            EventId = detectionEvent.EventId,
            RuleId = detectionEvent.RuleId,
            Severity = detectionEvent.Severity,
            Pid = detectionEvent.Pid,
            ProcessName = detectionEvent.ProcessName,
            ImagePath = detectionEvent.ImagePath,
            Title = detectionEvent.Title,
            SeverityBucket = detectionEvent.SeverityBucket,
            ObservedAtUtc = detectionEvent.ObservedAtUtc,
            Evidence = new Dictionary<string, string>(detectionEvent.Evidence, StringComparer.Ordinal),
        };

    public static ProcessObservationDto ToObservationDto(this ProcessSnapshot snapshot)
        => new()
        {
            Pid = snapshot.Pid,
            ProcessName = snapshot.ProcessName,
            ImagePath = snapshot.ImagePath,
            ParentPid = snapshot.ParentPid,
            UserName = snapshot.UserName,
            CommandLine = snapshot.CommandLine,
            IsProtected = snapshot.IsProtected,
            ObservedAtUtc = snapshot.ObservedAtUtc,
            Modules = snapshot.Modules.Select(m => m.ToDto()).ToList(),
            MemoryRegions = snapshot.MemoryRegions.Select(r => r.ToDto()).ToList(),
        };

    public static ModuleDto ToDto(this ModuleRecord module)
        => new()
        {
            Path = module.Path,
            Name = module.Name,
            BaseAddress = $"0x{module.BaseAddress:X}",
            Size = module.Size,
            SignatureStatus = module.SignatureStatus.ToString(),
            SignerName = module.SignerName,
            OnDiskSha256 = module.OnDiskSha256,
            InMemoryTextSha256 = module.InMemoryTextSha256,
            IsBackedByFile = module.IsBackedByFile,
            MemoryProtection = module.MemoryProtection,
        };

    public static MemoryRegionDto ToDto(this MemoryRegionRecord region)
        => new()
        {
            BaseAddress = $"0x{region.BaseAddress:X}",
            Size = region.Size,
            Protection = region.Protection,
            RegionType = region.RegionType,
            IsExecutable = region.IsExecutable,
            IsWritable = region.IsWritable,
            IsBackedByFile = region.IsBackedByFile,
            BackingFile = region.BackingFile,
        };
}
