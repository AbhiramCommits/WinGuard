using WinGuard.Core.Detection;

namespace WinGuard.Tests.Detection;

public sealed class ModulePathPolicyTests
{
    private static readonly string[] Roots =
    [
        @"C:\Windows\System32",
        @"C:\Program Files",
        @"C:\Program Files (x86)",
    ];

    [Theory]
    [InlineData(@"C:\Windows\System32\ntdll.dll")]
    [InlineData(@"c:\windows\system32\NTDLL.DLL")]
    [InlineData(@"C:\Windows\System32\drivers\vendor.sys")]
    [InlineData(@"C:\Program Files\Vendor\product\bin\helper.dll")]
    [InlineData(@"C:\Program Files (x86)\Steam\steamapps\common\Game\game.dll")]
    [InlineData(@"C:/Windows/System32/forward-slash.dll")]
    public void AllowsPathsInsideConfiguredRoots(string path)
    {
        Assert.True(ModulePathPolicy.IsAllowed(path, Roots));
    }

    [Theory]
    [InlineData(@"C:\Users\Public\Downloads\payload.dll")]
    [InlineData(@"C:\Windows\Temp\stage.dll")]
    [InlineData(@"C:\PerfLogs\a.dll")]
    [InlineData(@"D:\Games\cheat.dll")]
    [InlineData(@"C:\Program FilesEvil\a.dll")]
    [InlineData("")]
    [InlineData(null)]
    public void RejectsPathsOutsideConfiguredRoots(string? path)
    {
        Assert.False(ModulePathPolicy.IsAllowed(path, Roots));
    }

    [Fact]
    public void RootItselfIsAllowed()
    {
        Assert.True(ModulePathPolicy.IsAllowed(@"C:\Windows\System32", Roots));
    }

    [Fact]
    public void ProcessDirectoryBecomesAnAllowedRoot()
    {
        var snapshot = DetectionTestData.Game();
        var roots = ModulePathPolicy.AllowedRootsFor(snapshot, new DetectionOptions());

        Assert.True(ModulePathPolicy.IsAllowed(
            @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\steam_api64.dll",
            roots));

        Assert.False(ModulePathPolicy.IsAllowed(@"C:\Users\Public\payload.dll", roots));
    }

    [Theory]
    [InlineData(@"C:\Games\CS2\cs2.exe", @"C:\Games\CS2")]
    [InlineData(@"C:\Games\CS2\bin\x.dll", @"C:\Games\CS2\bin")]
    [InlineData("cs2.exe", null)]
    public void DirectoryOfHandlesWindowsPathsOnAnyPlatform(string path, string? expected)
    {
        Assert.Equal(expected, ModulePathPolicy.DirectoryOf(path));
    }
}
