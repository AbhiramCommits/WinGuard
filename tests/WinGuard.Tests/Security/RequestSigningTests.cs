using System.Security.Cryptography;
using System.Text;
using WinGuard.Core.Security;

namespace WinGuard.Tests.Security;

public sealed class RequestSigningTests
{
    [Fact]
    public void CanonicalStringIsStableAndIncludesEveryComponent()
    {
        var body = Encoding.UTF8.GetBytes("""{"a":1}""");

        var canonical = RequestSigning.BuildCanonicalString("post", "/api/v1/events", 1_700_000_000, "nonce-1", body);

        var lines = canonical.Split('\n');
        Assert.Equal("POST", lines[0]);
        Assert.Equal("/api/v1/events", lines[1]);
        Assert.Equal("1700000000", lines[2]);
        Assert.Equal("nonce-1", lines[3]);
        Assert.Equal(64, lines[4].Length);
    }

    [Fact]
    public void CanonicalStringChangesWithEveryComponent()
    {
        var body = Encoding.UTF8.GetBytes("body");

        var baseline = RequestSigning.BuildCanonicalString("POST", "/p", 1, "n", body);

        Assert.NotEqual(baseline, RequestSigning.BuildCanonicalString("GET", "/p", 1, "n", body));
        Assert.NotEqual(baseline, RequestSigning.BuildCanonicalString("POST", "/q", 1, "n", body));
        Assert.NotEqual(baseline, RequestSigning.BuildCanonicalString("POST", "/p", 2, "n", body));
        Assert.NotEqual(baseline, RequestSigning.BuildCanonicalString("POST", "/p", 1, "m", body));
        Assert.NotEqual(baseline, RequestSigning.BuildCanonicalString("POST", "/p", 1, "n", Encoding.UTF8.GetBytes("other")));
    }

    [Fact]
    public void SignAndVerifyRoundTrip()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var canonical = RequestSigning.BuildCanonicalString("POST", "/api/v1/events", 1, "n", []);

        var signature = RequestSigning.Sign(key, canonical);

        Assert.True(RequestSigning.Verify(key, canonical, signature));
    }

    [Fact]
    public void VerifyRejectsATamperedCanonicalString()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var canonical = RequestSigning.BuildCanonicalString("POST", "/api/v1/events", 1, "n", []);
        var signature = RequestSigning.Sign(key, canonical);

        var tampered = RequestSigning.BuildCanonicalString("POST", "/api/v1/events", 2, "n", []);

        Assert.False(RequestSigning.Verify(key, tampered, signature));
    }

    [Fact]
    public void VerifyRejectsGarbageSignatures()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var canonical = RequestSigning.BuildCanonicalString("POST", "/p", 1, "n", []);

        Assert.False(RequestSigning.Verify(key, canonical, string.Empty));
        Assert.False(RequestSigning.Verify(key, canonical, "not-base64!!"));
        Assert.False(RequestSigning.Verify(key, canonical, Convert.ToBase64String(new byte[32])));
    }

    [Fact]
    public void DerivedHostKeysAreDeterministicAndHostSpecific()
    {
        var a = RequestSigning.DeriveHostKey("master", "host-a");
        var b = RequestSigning.DeriveHostKey("master", "host-a");
        var c = RequestSigning.DeriveHostKey("master", "host-b");
        var d = RequestSigning.DeriveHostKey("other-master", "host-a");

        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.NotEqual(a, d);
        Assert.Equal(32, a.Length);
    }
}
