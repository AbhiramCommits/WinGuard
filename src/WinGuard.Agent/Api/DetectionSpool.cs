using System.Text;
using System.Text.Json;
using WinGuard.Core.Contracts;
using WinGuard.Core.Serialization;

namespace WinGuard.Agent.Api;

/// <summary>
/// Disk-backed spool for detection batches that could not be delivered. Each
/// batch is one JSON file named with a sortable timestamp prefix; files are
/// replayed oldest-first and deleted once accepted.
/// </summary>
public sealed class DetectionSpool
{
    private readonly string _directory;
    private readonly ILogger<DetectionSpool> _logger;

    public DetectionSpool(string directory, ILogger<DetectionSpool> logger)
    {
        _directory = Path.GetFullPath(directory);
        _logger = logger;
        System.IO.Directory.CreateDirectory(_directory);
    }

    public int Count => System.IO.Directory.Exists(_directory)
        ? System.IO.Directory.GetFiles(_directory, "*.json").Length
        : 0;

    public async Task<string> EnqueueAsync(EventsRequest batch, CancellationToken ct)
    {
        var name = $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.json";
        var path = Path.Combine(_directory, name);
        var json = JsonSerializer.Serialize(batch, WinGuardJson.Compact);

        await File.WriteAllTextAsync(path, json, Encoding.UTF8, ct).ConfigureAwait(false);
        _logger.LogWarning("Spooled a detection batch to {Path}; API is unreachable.", path);

        return path;
    }

    /// <summary>Enumerates spooled batches oldest-first.</summary>
    public IReadOnlyList<string> Pending()
    {
        if (!System.IO.Directory.Exists(_directory))
        {
            return [];
        }

        return System.IO.Directory
            .GetFiles(_directory, "*.json")
            .OrderBy(f => Path.GetFileName(f), StringComparer.Ordinal)
            .ToList();
    }

    public async Task<EventsRequest?> ReadAsync(string path, CancellationToken ct)
    {
        try
        {
            var json = await File.ReadAllTextAsync(path, ct).ConfigureAwait(false);
            return JsonSerializer.Deserialize<EventsRequest>(json, WinGuardJson.Compact);
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Discarding corrupt spool file {Path}.", path);
            return null;
        }
        catch (IOException ex)
        {
            _logger.LogWarning(ex, "Could not read spool file {Path}.", path);
            return null;
        }
    }

    public void Complete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException ex)
        {
            _logger.LogWarning(ex, "Could not delete spool file {Path}.", path);
        }
    }
}
