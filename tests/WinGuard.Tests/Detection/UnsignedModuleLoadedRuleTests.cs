using WinGuard.Core.Detection;
using WinGuard.Core.Detection.Rules;
using WinGuard.Core.Models;

namespace WinGuard.Tests.Detection;

public sealed class UnsignedModuleLoadedRuleTests
{
    private readonly UnsignedModuleLoadedRule _rule = new();

    [Fact]
    public void FlagsUnsignedModuleInProtectedProcess()
    {
        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.SignedModule(), DetectionTestData.UnsignedModule(@"C:\Windows\System32\drivers\evil.sys")],
        };

        var events = _rule.Evaluate(DetectionTestData.Context(snapshot));

        var detection = Assert.Single(events);
        Assert.Equal(RuleIds.UnsignedModuleLoaded, detection.RuleId);
        Assert.Equal("untrusted", detection.Evidence["signerTrust"]);
        Assert.Equal("Unsigned", detection.Evidence["signatureStatus"]);
    }

    [Fact]
    public void FlagsSelfSignedModuleWhenProcessIsProtectedByName()
    {
        var snapshot = DetectionTestData.Base("cs2.exe", DetectionTestData.GamePath, isProtected: false) with
        {
            Modules = [DetectionTestData.UnsignedModule(@"C:\Windows\System32\wgsvc_abc.dll", status: SignatureStatus.SelfSigned)],
        };

        var events = _rule.Evaluate(DetectionTestData.Context(snapshot));

        var detection = Assert.Single(events);
        Assert.Equal("SelfSigned", detection.Evidence["signatureStatus"]);
        Assert.Equal("true", detection.Evidence["protectedProcess"]);
    }

    [Fact]
    public void IgnoresUnsignedModulesInUnprotectedProcesses()
    {
        var snapshot = DetectionTestData.NonGame() with
        {
            Modules = [DetectionTestData.UnsignedModule(@"C:\Windows\System32\drivers\evil.sys")],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }

    [Fact]
    public void IgnoresSignatureOfModulesWithNoFileBacking()
    {
        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.UnbackedModule()],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }

    [Fact]
    public void IgnoresProperlySignedModules()
    {
        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.SignedModule()],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }
}
