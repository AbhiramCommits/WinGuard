using System.Net;
using WinGuard.Api.Security;

namespace WinGuard.Tests.Api;

/// <summary>Static dashboard serving and browser-facing security headers.</summary>
public sealed class ApiDashboardTests : IClassFixture<WinGuardApiFactory>
{
    private readonly HttpClient _client;

    public ApiDashboardTests(WinGuardApiFactory factory) => _client = factory.CreateClient();

    [Fact]
    public async Task IndexIsServedAtTheRoot()
    {
        using var response = await _client.GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("<title>WinGuard", html, StringComparison.Ordinal);
        Assert.Contains("app.js", html, StringComparison.Ordinal);
        Assert.Contains("styles.css", html, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/app.js")]
    [InlineData("/styles.css")]
    public async Task DashboardAssetsAreServed(string path)
    {
        using var response = await _client.GetAsync(path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task SecurityHeadersAreAppliedToTheDashboard()
    {
        using var response = await _client.GetAsync("/");

        Assert.Equal(SecurityHeadersMiddleware.ContentSecurityPolicy, response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());

        // The policy must not rely on unsafe-inline, which is what lets the
        // dashboard avoid inline script entirely.
        var csp = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.DoesNotContain("unsafe-inline", csp, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DashboardJavaScriptDoesNotBuildMarkupFromStrings()
    {
        // Regression guard: every API value must be written with textContent, so
        // the only mention of innerHTML in app.js is the comment saying so.
        var script = await _client.GetStringAsync("/app.js");

        var occurrences = script.Split("innerHTML").Length - 1;
        Assert.Equal(1, occurrences);
        Assert.DoesNotContain("document.write", script, StringComparison.Ordinal);
        Assert.DoesNotContain("insertAdjacentHTML", script, StringComparison.Ordinal);
    }
}
