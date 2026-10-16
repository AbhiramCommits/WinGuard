using System.Security.Cryptography;
using System.Text;
using WinGuard.Core.Detection;
using WinGuard.Core.Models;

namespace WinGuard.Tests.Detection;

/// <summary>Builders for realistic snapshots, modules and regions used by the rule tests.</summary>
internal static class DetectionTestData
{
    public const string GamePath = @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe";
    public const string System32Path = @"C:\Windows\System32\ntdll.dll";

    public static DetectionOptions Options() => new();

    public static DetectionRuleContext Context(ProcessSnapshot snapshot, DetectionOptions? options = null)
        => new(snapshot, options ?? Options());

    public static string Hex(string seed)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(seed))).ToLowerInvariant();

    public static ProcessSnapshot Game(ulong imageBase = 0x00007FF6_00001000, bool isProtected = true, string? processName = null)
        => Base(
            processName ?? "cs2.exe",
            GamePath,
            isProtected,
            imageBase);

    public static ProcessSnapshot NonGame(string processName = "notepad.exe", string? imagePath = null)
        => Base(processName, imagePath ?? @"C:\Windows\System32\notepad.exe", isProtected: false, 0x00007FF6_00001000);

    public static ProcessSnapshot Base(
        string processName,
        string imagePath,
        bool isProtected,
        ulong imageBase = 0x00007FF6_00001000,
        ulong sizeOfImage = 0x00200000,
        ulong? pebImageBase = null,
        ulong? pebImageSize = null,
        ulong? onDiskImageBase = null,
        ulong? onDiskImageSize = null,
        IReadOnlyList<ModuleRecord>? modules = null,
        IReadOnlyList<MemoryRegionRecord>? regions = null,
        TimeSpan? observedOffset = null)
        => new()
        {
            HostId = "host-test",
            Pid = 4242,
            ProcessName = processName,
            ImagePath = imagePath,
            ParentPid = 1,
            ImageBaseAddress = pebImageBase ?? imageBase,
            PebImageSize = pebImageSize ?? sizeOfImage,
            OnDiskImageBase = onDiskImageBase ?? imageBase,
            OnDiskImageSize = onDiskImageSize ?? sizeOfImage,
            IsProtected = isProtected,
            StartedAtUtc = DateTimeOffset.UnixEpoch,
            ObservedAtUtc = DateTimeOffset.UnixEpoch.Add(observedOffset ?? TimeSpan.Zero),
            Modules = modules ?? [],
            MemoryRegions = regions ?? [],
        };

    public static ModuleRecord SignedModule(string path = System32Path, ulong baseAddress = 0x00007FF6_01000000, string hashSeed = "ntdll")
        => new()
        {
            Path = path,
            Name = System.IO.Path.GetFileName(path.Replace('\\', '/')),
            BaseAddress = baseAddress,
            Size = 0x200000,
            SignatureStatus = SignatureStatus.Signed,
            SignerName = "Microsoft Windows",
            OnDiskSha256 = Hex(hashSeed),
            InMemoryTextSha256 = Hex(hashSeed),
            IsBackedByFile = true,
            MemoryProtection = "PAGE_EXECUTE_READ",
        };

    public static ModuleRecord UnsignedModule(string path, ulong baseAddress = 0x00007FF6_02000000, SignatureStatus status = SignatureStatus.Unsigned)
        => new()
        {
            Path = path,
            Name = System.IO.Path.GetFileName(path.Replace('\\', '/')),
            BaseAddress = baseAddress,
            Size = 0x10000,
            SignatureStatus = status,
            SignerName = status == SignatureStatus.SelfSigned ? "Ephemeral Publisher" : string.Empty,
            OnDiskSha256 = Hex(path),
            InMemoryTextSha256 = Hex(path),
            IsBackedByFile = true,
            MemoryProtection = "PAGE_EXECUTE_READ",
        };

    public static ModuleRecord UnbackedModule(ulong baseAddress = 0x00007FF6_03000000)
        => new()
        {
            Path = string.Empty,
            Name = "unknown",
            BaseAddress = baseAddress,
            Size = 0x8000,
            SignatureStatus = SignatureStatus.Unknown,
            IsBackedByFile = false,
            MemoryProtection = "PAGE_EXECUTE_READ",
        };

    public static ModuleRecord PatchedModule(string path = System32Path, ulong baseAddress = 0x00007FF6_04000000)
        => SignedModule(path, baseAddress, "original") with { InMemoryTextSha256 = Hex("patched-" + path) };

    public static MemoryRegionRecord UnbackedExecutableRegion(ulong baseAddress = 0x00007FF6_05000000, string protection = "PAGE_EXECUTE_READ", bool writable = false)
        => new()
        {
            BaseAddress = baseAddress,
            Size = 0x10000,
            Protection = protection,
            RegionType = "MEM_PRIVATE",
            IsExecutable = true,
            IsWritable = writable,
            IsBackedByFile = false,
        };

    public static MemoryRegionRecord ImageRegion(ulong baseAddress = 0x00007FF6_06000000, string backingFile = System32Path)
        => new()
        {
            BaseAddress = baseAddress,
            Size = 0x200000,
            Protection = "PAGE_EXECUTE_READ",
            RegionType = "MEM_IMAGE",
            IsExecutable = true,
            IsWritable = false,
            IsBackedByFile = true,
            BackingFile = backingFile,
        };

    public static MemoryRegionRecord PrivateHeapRegion(ulong baseAddress = 0x00007FF6_07000000)
        => new()
        {
            BaseAddress = baseAddress,
            Size = 0x4000,
            Protection = "PAGE_READWRITE",
            RegionType = "MEM_PRIVATE",
            IsExecutable = false,
            IsWritable = true,
            IsBackedByFile = false,
        };
}
