using WinGuard.Api.Security;
using WinGuard.Api.Services;

namespace WinGuard.Tests.Security;

public sealed class NonceCacheTests
{
    [Fact]
    public void FirstUseIsAcceptedAndReplayIsRejected()
    {
        var cache = new NonceCache();

        Assert.True(cache.TryAdd("host-a", "nonce-1", TimeSpan.FromMinutes(10)));
        Assert.False(cache.TryAdd("host-a", "nonce-1", TimeSpan.FromMinutes(10)));
        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public void NoncesAreScopedPerHost()
    {
        var cache = new NonceCache();

        Assert.True(cache.TryAdd("host-a", "shared-nonce", TimeSpan.FromMinutes(10)));
        Assert.True(cache.TryAdd("host-b", "shared-nonce", TimeSpan.FromMinutes(10)));
    }

    [Fact]
    public void NonceBecomesReusableAfterTheRetentionWindow()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var cache = new NonceCache(clock);
        var retention = TimeSpan.FromMinutes(10);

        Assert.True(cache.TryAdd("host-a", "nonce-1", retention));

        clock.Now = clock.Now.AddMinutes(5);
        Assert.False(cache.TryAdd("host-a", "nonce-1", retention));

        clock.Now = clock.Now.AddMinutes(6);
        Assert.True(cache.TryAdd("host-a", "nonce-1", retention));
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        public FakeTimeProvider(DateTimeOffset now) => Now = now;

        public DateTimeOffset Now { get; set; }

        public override DateTimeOffset GetUtcNow() => Now;
    }
}

public sealed class HostStatusCalculatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(0, "Online")]
    [InlineData(4, "Online")]
    [InlineData(6, "Stale")]
    [InlineData(29, "Stale")]
    [InlineData(31, "Offline")]
    [InlineData(600, "Offline")]
    public void StatusIsDerivedFromHeartbeatAge(int minutesAgo, string expected)
    {
        Assert.Equal(expected, HostStatusCalculator.Status(Now.AddMinutes(-minutesAgo), Now));
    }

    [Fact]
    public void HostThatNeverCheckedInIsOffline()
    {
        Assert.Equal("Offline", HostStatusCalculator.Status(null, Now));
    }
}
