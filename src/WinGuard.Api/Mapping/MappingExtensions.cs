using System.Text.Json;
using WinGuard.Api.Contracts;
using WinGuard.Api.Data.Entities;
using WinGuard.Core.Contracts;
using WinGuard.Core.Serialization;

namespace WinGuard.Api.Mapping;

/// <summary>Conversions between wire contracts and persistence entities.</summary>
public static class MappingExtensions
{
    public static DetectionRecord ToRecord(this DetectionEventDto dto, string hostId, DateTimeOffset receivedAtUtc)
        => new()
        {
            EventId = string.IsNullOrWhiteSpace(dto.EventId) ? Guid.NewGuid().ToString("N") : dto.EventId!,
            HostId = hostId,
            Pid = dto.Pid,
            ProcessName = dto.ProcessName,
            ImagePath = dto.ImagePath,
            RuleId = dto.RuleId,
            Severity = Math.Clamp(dto.Severity, 0, 100),
            SeverityBucket = dto.SeverityBucket,
            Title = dto.Title,
            EvidenceJson = JsonSerializer.Serialize(dto.Evidence, WinGuardJson.Compact),
            ObservedAtUtc = dto.ObservedAtUtc,
            ReceivedAtUtc = receivedAtUtc,
        };

    public static ProcessObservation ToObservation(this ProcessObservationDto dto, string hostId, DateTimeOffset receivedAtUtc)
        => new()
        {
            HostId = hostId,
            Pid = dto.Pid,
            ProcessName = dto.ProcessName,
            ImagePath = dto.ImagePath,
            ParentPid = dto.ParentPid,
            UserName = dto.UserName,
            CommandLine = dto.CommandLine,
            IsProtected = dto.IsProtected,
            ModulesJson = JsonSerializer.Serialize(dto.Modules, WinGuardJson.Compact),
            MemoryRegionsJson = JsonSerializer.Serialize(dto.MemoryRegions, WinGuardJson.Compact),
            ObservedAtUtc = dto.ObservedAtUtc,
            ReceivedAtUtc = receivedAtUtc,
        };

    public static DetectionDto ToDto(this DetectionRecord record)
        => new(
            record.EventId,
            record.HostId,
            record.Pid,
            record.ProcessName,
            record.ImagePath,
            record.RuleId,
            record.Title,
            record.Severity,
            record.SeverityBucket,
            record.ObservedAtUtc,
            DeserializeEvidence(record.EvidenceJson));

    public static IReadOnlyDictionary<string, string> DeserializeEvidence(string? evidenceJson)
    {
        if (string.IsNullOrWhiteSpace(evidenceJson))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(evidenceJson, WinGuardJson.Compact)
                ?? new Dictionary<string, string>(StringComparer.Ordinal);
        }
        catch (JsonException)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }
    }

    public static IReadOnlyList<ModuleDto> DeserializeModules(string? json)
        => DeserializeList<ModuleDto>(json);

    public static IReadOnlyList<MemoryRegionDto> DeserializeRegions(string? json)
        => DeserializeList<MemoryRegionDto>(json);

    private static IReadOnlyList<TItem> DeserializeList<TItem>(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<TItem>>(json, WinGuardJson.Compact) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
