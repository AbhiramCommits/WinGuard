using WinGuard.Core.Models;
using WinGuard.Core.Telemetry;

namespace WinGuard.Tests.Telemetry;

public sealed class ReplayTelemetrySourceTests
{
    private static readonly CancellationToken None = CancellationToken.None;

    [Fact]
    public async Task StreamsEverySnapshotInFileOrderWithoutLoss()
    {
        var path = TestPaths.CorpusFile("labeled.jsonl");

        var expected = new List<ProcessSnapshot>();
        await foreach (var snapshot in TelemetryJsonl.ReadAsync(path))
        {
            expected.Add(snapshot);
        }

        var source = new ReplayTelemetrySource(path, new ReplayOptions { CorpusPath = path });

        var actual = new List<ProcessSnapshot>();
        await foreach (var snapshot in source.StreamAsync(None))
        {
            actual.Add(snapshot);
        }

        Assert.Equal(expected.Count, actual.Count);

        for (var i = 0; i < expected.Count; i++)
        {
            // Byte-for-byte re-serialization equality proves nothing was lost or
            // reordered by the replay path.
            Assert.Equal(TelemetryJsonl.Serialize(expected[i]), TelemetryJsonl.Serialize(actual[i]));
            Assert.Equal(expected[i].ObservedAtUtc, actual[i].ObservedAtUtc);
            Assert.Equal(expected[i].HostId, actual[i].HostId);
            Assert.Equal(expected[i].Pid, actual[i].Pid);
            Assert.Equal(expected[i].Labels, actual[i].Labels);
        }
    }

    [Fact]
    public async Task PreservesTimestampsAndOrderingExactly()
    {
        var path = TestPaths.CorpusFile("benign.jsonl");
        var source = new ReplayTelemetrySource(path, new ReplayOptions { CorpusPath = path });

        var timestamps = new List<DateTimeOffset>();
        await foreach (var snapshot in source.StreamAsync(None))
        {
            timestamps.Add(snapshot.ObservedAtUtc);
        }

        Assert.NotEmpty(timestamps);
        Assert.Equal(timestamps.OrderBy(t => t), timestamps);
    }

    [Fact]
    public async Task DescribesAReplayHostWithoutTouchingTheCorpusIds()
    {
        var path = TestPaths.CorpusFile("benign.jsonl");
        var source = new ReplayTelemetrySource(path, new ReplayOptions { CorpusPath = path });

        var host = source.DescribeHost();

        Assert.Equal("replay-benign", host.HostId);
        Assert.Equal("replay-benign", host.Hostname);
        Assert.False(string.IsNullOrWhiteSpace(host.AgentVersion));

        await foreach (var snapshot in source.StreamAsync(None))
        {
            Assert.NotEqual(host.HostId, snapshot.HostId);
            Assert.NotEmpty(snapshot.HostId);
            break;
        }
    }

    [Fact]
    public void ThrowsWhenCorpusFileIsMissing()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"winguard-missing-{Guid.NewGuid():N}.jsonl");

        var ex = Assert.Throws<FileNotFoundException>(() => new ReplayTelemetrySource(missing));
        Assert.Contains("gen-corpus", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RateLimitingPacesPlayback()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winguard-replay-{Guid.NewGuid():N}.jsonl");

        var snapshots = Enumerable.Range(0, 4).Select(i => new ProcessSnapshot
        {
            HostId = "host-1",
            Pid = 100 + i,
            ProcessName = "test.exe",
            ObservedAtUtc = DateTimeOffset.UnixEpoch.AddSeconds(i),
        });

        await TelemetryJsonl.WriteAllAsync(path, snapshots);
        await using var temp = new TempFile(path);

        var source = new ReplayTelemetrySource(path, new ReplayOptions { CorpusPath = path, RatePerSecond = 50 });

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var count = 0;
        await foreach (var _ in source.StreamAsync(None))
        {
            count++;
        }

        stopwatch.Stop();

        Assert.Equal(4, count);
        Assert.True(stopwatch.ElapsedMilliseconds >= 40, $"Expected pacing to take >=40ms, took {stopwatch.ElapsedMilliseconds}ms.");
    }

    private sealed class TempFile : IAsyncDisposable
    {
        private readonly string _path;

        public TempFile(string path) => _path = path;

        public ValueTask DisposeAsync()
        {
            try
            {
                File.Delete(_path);
            }
            catch (IOException)
            {
                // Best effort cleanup.
            }

            return ValueTask.CompletedTask;
        }
    }
}
