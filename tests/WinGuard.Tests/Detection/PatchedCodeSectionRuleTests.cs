using WinGuard.Core.Detection;
using WinGuard.Core.Detection.Rules;

namespace WinGuard.Tests.Detection;

public sealed class PatchedCodeSectionRuleTests
{
    private readonly PatchedCodeSectionRule _rule = new();

    [Fact]
    public void FlagsSignedModuleWhoseInMemoryTextDiffersFromDisk()
    {
        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.PatchedModule(@"C:\Windows\System32\dxgi.dll")],
        };

        var events = _rule.Evaluate(DetectionTestData.Context(snapshot));

        var detection = Assert.Single(events);
        Assert.Equal(RuleIds.PatchedCodeSection, detection.RuleId);
        Assert.NotEqual(detection.Evidence["onDiskSha256"], detection.Evidence["inMemoryTextSha256"]);
        Assert.Equal("trusted", detection.Evidence["signerTrust"]);
    }

    [Fact]
    public void FlagsEveryPatchedSignedModule()
    {
        var snapshot = DetectionTestData.Game() with
        {
            Modules =
            [
                DetectionTestData.PatchedModule(@"C:\Windows\System32\dxgi.dll", 0xA000),
                DetectionTestData.PatchedModule(@"C:\Windows\System32\d3d11.dll", 0xB000),
            ],
        };

        Assert.Equal(2, _rule.Evaluate(DetectionTestData.Context(snapshot)).Count);
    }

    [Fact]
    public void IgnoresUnmodifiedModules()
    {
        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.SignedModule(@"C:\Windows\System32\dxgi.dll")],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }

    [Fact]
    public void IgnoresModulesThatWereNotHashed()
    {
        var unhashed = DetectionTestData.SignedModule(@"C:\Windows\System32\dxgi.dll") with
        {
            OnDiskSha256 = string.Empty,
            InMemoryTextSha256 = string.Empty,
        };

        var snapshot = DetectionTestData.Game() with { Modules = [unhashed] };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }
}
