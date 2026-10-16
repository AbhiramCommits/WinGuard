using WinGuard.Core.Models;

namespace WinGuard.Eval.Corpus;

/// <summary>
/// A canonical Windows module: name, install path, typical size and the
/// Authenticode facts the collector would report for it.
/// </summary>
internal sealed record ModuleTemplate(string Name, string Path, long Size, SignatureStatus Status, string Signer);

/// <summary>
/// Realistic module sets for the synthetic corpus. Paths mirror a real Windows
/// install so that the path-based detection rules (allowed roots, injected DLLs)
/// are exercised against believable data rather than toy strings.
/// </summary>
internal static class SystemModuleCatalog
{
    public const string System32 = @"C:\Windows\System32";
    public const string SysWow64 = @"C:\Windows\SysWOW64";
    public const string DriveStore = @"C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_9c1a24b3cbb2f3e5";
    public const string ProgramFiles = @"C:\Program Files";
    public const string ProgramFilesX86 = @"C:\Program Files (x86)";
    public const string DotNetShared = @"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.11";

    private const string Microsoft = "Microsoft Windows";
    private const string MicrosoftCorp = "Microsoft Corporation";
    private const string Nvidia = "NVIDIA Corporation";
    private const string Valve = "Valve Corporation";
    private const string Google = "Google LLC";
    private const string Mozilla = "Mozilla Corporation";

    /// <summary>Modules every Windows process maps (the "minimum working set").</summary>
    public static readonly ModuleTemplate[] AlwaysLoaded =
    [
        new("ntdll.dll", $@"{System32}\ntdll.dll", 2_142_208, SignatureStatus.Signed, Microsoft),
        new("kernel32.dll", $@"{System32}\kernel32.dll", 770_048, SignatureStatus.Signed, Microsoft),
        new("kernelbase.dll", $@"{System32}\kernelbase.dll", 3_116_544, SignatureStatus.Signed, Microsoft),
        new("ucrtbase.dll", $@"{System32}\ucrtbase.dll", 1_077_248, SignatureStatus.Signed, Microsoft),
        new("vcruntime140.dll", $@"{System32}\vcruntime140.dll", 98_304, SignatureStatus.Signed, MicrosoftCorp),
        new("combase.dll", $@"{System32}\combase.dll", 3_383_296, SignatureStatus.Signed, Microsoft),
        new("ole32.dll", $@"{System32}\ole32.dll", 1_290_240, SignatureStatus.Signed, Microsoft),
        new("user32.dll", $@"{System32}\user32.dll", 1_724_416, SignatureStatus.Signed, Microsoft),
    ];

    /// <summary>Extra DLLs a game client typically has mapped.</summary>
    public static readonly ModuleTemplate[] GameExtras =
    [
        new("gdi32.dll", $@"{System32}\gdi32.dll", 172_032, SignatureStatus.Signed, Microsoft),
        new("d3d11.dll", $@"{System32}\d3d11.dll", 2_527_232, SignatureStatus.Signed, Microsoft),
        new("dxgi.dll", $@"{System32}\dxgi.dll", 921_088, SignatureStatus.Signed, Microsoft),
        new("d3d9.dll", $@"{System32}\d3d9.dll", 1_867_264, SignatureStatus.Signed, Microsoft),
        new("xinput1_4.dll", $@"{System32}\xinput1_4.dll", 59_392, SignatureStatus.Signed, Microsoft),
        new("dinput8.dll", $@"{System32}\dinput8.dll", 224_256, SignatureStatus.Signed, Microsoft),
        new("winmm.dll", $@"{System32}\winmm.dll", 126_976, SignatureStatus.Signed, Microsoft),
        new("mswsock.dll", $@"{System32}\mswsock.dll", 409_600, SignatureStatus.Signed, Microsoft),
        new("nvwgf2umx.dll", $@"{DriveStore}\nvwgf2umx.dll", 36_175_872, SignatureStatus.Signed, Nvidia),
        new("nvapi64.dll", $@"{DriveStore}\nvapi64.dll", 7_004_160, SignatureStatus.Signed, Nvidia),
        new("d3dcompiler_47.dll", $@"{System32}\d3dcompiler_47.dll", 4_911_104, SignatureStatus.Signed, MicrosoftCorp),
        new("version.dll", $@"{System32}\version.dll", 33_280, SignatureStatus.Signed, Microsoft),
    ];

    /// <summary>Files shipped alongside a game executable (inside the game dir).</summary>
    public static readonly ModuleTemplate[] GameLocalExtras =
    [
        new("steam_api64.dll", "steam_api64.dll", 236_544, SignatureStatus.Signed, Valve),
        new("gameoverlayrenderer64.dll", "gameoverlayrenderer64.dll", 1_314_816, SignatureStatus.Signed, Valve),
        new("tier0_s64.dll", "tier0_s64.dll", 396_288, SignatureStatus.Signed, Valve),
        new("vstdlib_s64.dll", "vstdlib_s64.dll", 165_376, SignatureStatus.Signed, Valve),
        new("resources.pak.dll", "resources.pak.dll", 8_912, SignatureStatus.Signed, Valve),
    ];

    public static readonly ModuleTemplate[] BrowserExtras =
    [
        new("winhttp.dll", $@"{System32}\winhttp.dll", 921_600, SignatureStatus.Signed, Microsoft),
        new("crypt32.dll", $@"{System32}\crypt32.dll", 1_318_912, SignatureStatus.Signed, Microsoft),
        new("dnsapi.dll", $@"{System32}\dnsapi.dll", 780_288, SignatureStatus.Signed, Microsoft),
        new("iphlpapi.dll", $@"{System32}\iphlpapi.dll", 200_704, SignatureStatus.Signed, Microsoft),
        new("ncrypt.dll", $@"{System32}\ncrypt.dll", 448_512, SignatureStatus.Signed, Microsoft),
        new("chrome_elf.dll", "chrome_elf.dll", 1_056_768, SignatureStatus.Signed, Google),
        new("ffmpeg.dll", "ffmpeg.dll", 2_830_848, SignatureStatus.Signed, Google),
        new("libEGL.dll", "libEGL.dll", 456_192, SignatureStatus.Signed, Google),
    ];

    public static readonly ModuleTemplate[] MozillaExtras =
    [
        new("nss3.dll", "nss3.dll", 3_780_608, SignatureStatus.Signed, Mozilla),
        new("mozglue.dll", "mozglue.dll", 1_003_520, SignatureStatus.Signed, Mozilla),
        new("winhttp.dll", $@"{System32}\winhttp.dll", 921_600, SignatureStatus.Signed, Microsoft),
    ];

    public static readonly ModuleTemplate[] DevExtras =
    [
        new("clrjit.dll", $@"{DotNetShared}\clrjit.dll", 704_512, SignatureStatus.Signed, MicrosoftCorp),
        new("coreclr.dll", $@"{DotNetShared}\coreclr.dll", 5_312_512, SignatureStatus.Signed, MicrosoftCorp),
        new("hostfxr.dll", $@"{DotNetShared}\hostfxr.dll", 258_048, SignatureStatus.Signed, MicrosoftCorp),
        new("ws2_32.dll", $@"{System32}\ws2_32.dll", 421_888, SignatureStatus.Signed, Microsoft),
    ];

    public static readonly ModuleTemplate[] ServiceExtras =
    [
        new("sechost.dll", $@"{System32}\sechost.dll", 485_376, SignatureStatus.Signed, Microsoft),
        new("advapi32.dll", $@"{System32}\advapi32.dll", 677_888, SignatureStatus.Signed, Microsoft),
        new("rpcrt4.dll", $@"{System32}\rpcrt4.dll", 1_142_784, SignatureStatus.Signed, Microsoft),
        new("sspicli.dll", $@"{System32}\sspicli.dll", 185_344, SignatureStatus.Signed, Microsoft),
        new("ncryptsslp.dll", $@"{System32}\ncryptsslp.dll", 135_168, SignatureStatus.Signed, Microsoft),
    ];

    /// <summary>
    /// A self-signed module that lives inside System32. Loading it does not by
    /// itself imply a path violation — it is used to exercise the "unsigned /
    /// self-signed module in a protected process" rule in isolation.
    /// </summary>
    public static ModuleTemplate SelfSignedSystemModule(string name)
        => new(name, $@"{System32}\{name}", 147_456, SignatureStatus.SelfSigned, "Ephemeral Test Publisher");

    public static ModuleTemplate UnsignedDriver(string name)
        => new(name, $@"{System32}\drivers\{name}", 212_992, SignatureStatus.Unsigned, string.Empty);
}
