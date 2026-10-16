using System.Diagnostics;
using System.Runtime.CompilerServices;
using WinGuard.Core.Models;

namespace WinGuard.Core.Telemetry;

/// <summary>
/// Replays a JSONL telemetry corpus from disk as if it were live telemetry.
/// </summary>
/// <remarks>
/// This is the source used on macOS/Linux and in CI. It preserves the exact
/// ordering and <see cref="ProcessSnapshot.ObservedAtUtc"/> timestamps recorded
/// in the file — it never rewrites timestamps — so the detection engine and the
/// benchmark harness see the same data the Win32 collector would have produced.
/// </remarks>
public sealed class ReplayTelemetrySource : ITelemetrySource
{
    private readonly string _corpusPath;
    private readonly ReplayOptions _options;
    private readonly HostInfo _host;

    public ReplayTelemetrySource(string corpusPath, ReplayOptions? options = null, HostInfo? host = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(corpusPath);

        _corpusPath = Path.GetFullPath(corpusPath);
        _options = options ?? new ReplayOptions { CorpusPath = corpusPath };

        if (!File.Exists(_corpusPath))
        {
            throw new FileNotFoundException(
                $"Replay corpus not found: {_corpusPath}. Run 'dotnet run --project src/WinGuard.Eval -- gen-corpus' first.",
                _corpusPath);
        }

        _host = host ?? BuildSyntheticHost(_corpusPath, _options.HostIdOverride);
    }

    /// <summary>Absolute path of the corpus being replayed.</summary>
    public string CorpusPath => _corpusPath;

    public HostInfo DescribeHost() => _host;

    public async IAsyncEnumerable<ProcessSnapshot> StreamAsync(
        [EnumeratorCancellation] CancellationToken ct)
    {
        do
        {
            var stopwatch = Stopwatch.StartNew();
            var index = 0L;

            await foreach (var snapshot in TelemetryJsonl.ReadAsync(_corpusPath, ct).ConfigureAwait(false))
            {
                ct.ThrowIfCancellationRequested();

                if (_options.RatePerSecond > 0)
                {
                    // Maintain the requested average rate without drifting: sleep
                    // until the scheduled time for the *next* snapshot.
                    index++;
                    var target = TimeSpan.FromSeconds(index / _options.RatePerSecond);
                    var delay = target - stopwatch.Elapsed;
                    if (delay > TimeSpan.Zero)
                    {
                        await Task.Delay(delay, ct).ConfigureAwait(false);
                    }
                }

                yield return snapshot;
            }
        }
        while (_options.Loop && !ct.IsCancellationRequested);
    }

    private static HostInfo BuildSyntheticHost(string corpusPath, string? hostIdOverride)
    {
        var fileName = Path.GetFileNameWithoutExtension(corpusPath);

        return new HostInfo
        {
            HostId = hostIdOverride ?? $"replay-{fileName}",
            Hostname = $"replay-{fileName}",
            OsVersion = Environment.OSVersion.VersionString,
            Architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            AgentVersion = CoreInfo.AgentVersion,
            Domain = "REPLAY",
            UserName = Environment.UserName,
            CollectedAtUtc = DateTimeOffset.UtcNow,
        };
    }
}
