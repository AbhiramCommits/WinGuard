using WinGuard.Core.Detection;
using WinGuard.Core.Detection.Rules;

namespace WinGuard.Tests.Detection;

public sealed class InjectedModulePathRuleTests
{
    private readonly InjectedModulePathRule _rule = new();

    [Fact]
    public void FlagsModuleOutsideTheAllowedRoots()
    {
        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.SignedModule(), DetectionTestData.UnsignedModule(@"C:\Users\Public\Downloads\payload.dll")],
        };

        var events = _rule.Evaluate(DetectionTestData.Context(snapshot));

        var detection = Assert.Single(events);
        Assert.Equal(RuleIds.InjectedModulePath, detection.RuleId);
        Assert.Equal(@"C:\Users\Public\Downloads\payload.dll", detection.Evidence["modulePath"]);
    }

    [Fact]
    public void FlagsModuleInTempDirectory()
    {
        var snapshot = DetectionTestData.NonGame() with
        {
            Modules = [DetectionTestData.SignedModule(@"C:\Temp\d3d11.dll")],
        };

        var events = _rule.Evaluate(DetectionTestData.Context(snapshot));

        Assert.Single(events);
    }

    [Fact]
    public void AllowsSystemAndProgramFilesModules()
    {
        var snapshot = DetectionTestData.Game() with
        {
            Modules =
            [
                DetectionTestData.SignedModule(@"C:\Windows\System32\ntdll.dll"),
                DetectionTestData.SignedModule(@"C:\Program Files\Common Files\vendor\helper.dll"),
                DetectionTestData.SignedModule(@"C:\Windows\System32\DriverStore\FileRepository\nv\nvwgf2umx.dll"),
            ],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }

    [Fact]
    public void AllowsModulesAlongsideTheProcessImage()
    {
        // The process's own directory is an allowed root, so game-shipped DLLs
        // next to the executable are legitimate.
        var snapshot = DetectionTestData.Game() with
        {
            Modules =
            [
                DetectionTestData.SignedModule(
                    @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\steam_api64.dll"),
            ],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }

    [Fact]
    public void IgnoresModulesWithNoBackingFile()
    {
        var snapshot = DetectionTestData.Game() with
        {
            Modules = [DetectionTestData.UnbackedModule()],
        };

        Assert.Empty(_rule.Evaluate(DetectionTestData.Context(snapshot)));
    }
}
