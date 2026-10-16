using System.Text;
using System.Text.Json;
using WinGuard.Core.Models;
using WinGuard.Core.Serialization;

namespace WinGuard.Core.Telemetry;

/// <summary>
/// Reads and writes the JSONL telemetry format: one serialized
/// <see cref="ProcessSnapshot"/> per line, in observation order. Blank lines
/// and lines beginning with <c>#</c> are ignored on read.
/// </summary>
public static class TelemetryJsonl
{
    public static string Serialize(ProcessSnapshot snapshot)
        => JsonSerializer.Serialize(snapshot, WinGuardJson.Compact);

    public static ProcessSnapshot Deserialize(string line)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(line);

        var snapshot = JsonSerializer.Deserialize<ProcessSnapshot>(line, WinGuardJson.Compact)
            ?? throw new InvalidDataException("JSONL line deserialized to null.");

        return snapshot;
    }

    public static async IAsyncEnumerable<ProcessSnapshot> ReadAsync(
        string path,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach (var line in File.ReadLinesAsync(path, ct).ConfigureAwait(false))
        {
            if (string.IsNullOrWhiteSpace(line) || line[0] == '#')
            {
                continue;
            }

            yield return Deserialize(line);
        }
    }

    public static async Task WriteAllAsync(
        string path,
        IEnumerable<ProcessSnapshot> snapshots,
        CancellationToken ct = default)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
        await using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        foreach (var snapshot in snapshots)
        {
            ct.ThrowIfCancellationRequested();
            await writer.WriteLineAsync(Serialize(snapshot)).ConfigureAwait(false);
        }

        await writer.FlushAsync(ct).ConfigureAwait(false);
    }
}
