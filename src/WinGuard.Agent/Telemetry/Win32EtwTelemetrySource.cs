using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using WinGuard.Core;
using WinGuard.Core.Models;
using WinGuard.Core.Telemetry;

namespace WinGuard.Agent.Telemetry;

/// <summary>
/// The real Win32/ETW telemetry source.
/// </summary>
/// <remarks>
/// <para>
/// Combines a periodic full sweep (Toolhelp process list, psapi module list,
/// <c>VirtualQueryEx</c> memory walk, Authenticode verification, in-memory .text
/// hashing) with an event-driven ETW subscription to
/// <c>Microsoft-Windows-Kernel-Process</c> image-load events so short-lived
/// injections are not missed between sweeps.
/// </para>
/// <para>
/// Constructible on Windows only. Off Windows the agent registers
/// <see cref="ReplayTelemetrySource"/> instead, which is what allows the rest of
/// the system to be built, tested and benchmarked on macOS and Linux.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class Win32EtwTelemetrySource : ITelemetrySource, IDisposable
{
    private readonly Win32TelemetryOptions _options;
    private readonly ILogger<Win32EtwTelemetrySource> _logger;
    private readonly ConcurrentQueue<NativeCollector.ImageLoadEvent> _imageLoads = new();
    private readonly NativeCollector.ImageLoadCallback _imageLoadCallback;
    private readonly EtwSessionHandle? _etwSession;
    private HostInfo? _host;
    private bool _disposed;

    public Win32EtwTelemetrySource(
        IOptions<Win32TelemetryOptions> options,
        ILogger<Win32EtwTelemetrySource> logger)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Win32EtwTelemetrySource requires Windows. Use ReplayTelemetrySource elsewhere.");
        }

        _options = options.Value;
        _logger = logger;
        _imageLoadCallback = OnImageLoad;

        var abi = NativeCollector.wg_native_abi_version();
        if (abi != CoreInfo.NativeAbiVersion)
        {
            throw new InvalidOperationException(
                $"winguard_native.dll reports ABI version {abi}; the agent expects {CoreInfo.NativeAbiVersion}.");
        }

        if (_options.EnableEtw)
        {
            var rc = NativeCollector.wg_etw_start(_options.EtwSessionName, _imageLoadCallback, out var handle);
            if (rc == NativeCollector.Ok)
            {
                _etwSession = new EtwSessionHandle(handle);
                _logger.LogInformation(
                    "Started ETW session {Session} for Microsoft-Windows-Kernel-Process image loads.",
                    _options.EtwSessionName);
            }
            else
            {
                _logger.LogWarning(
                    "Could not start ETW session {Session} (status {Status}); falling back to periodic sweeps only.",
                    _options.EtwSessionName,
                    rc);
            }
        }
    }

    public HostInfo DescribeHost()
    {
        return _host ??= new HostInfo
        {
            HostId = ReadMachineGuid() ?? Environment.MachineName,
            Hostname = Environment.MachineName,
            OsVersion = Environment.OSVersion.VersionString,
            Architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            AgentVersion = CoreInfo.AgentVersion,
            Domain = Environment.UserDomainName,
            UserName = Environment.UserName,
            CollectedAtUtc = DateTimeOffset.UtcNow,
        };
    }

    public async IAsyncEnumerable<ProcessSnapshot> StreamAsync(
        [EnumeratorCancellation] CancellationToken ct)
    {
        var hostId = DescribeHost().HostId;

        while (!ct.IsCancellationRequested)
        {
            var seen = new HashSet<int>();

            foreach (var process in TryEnumerateProcesses())
            {
                if (!ShouldCollect(process.ProcessName))
                {
                    continue;
                }

                var snapshot = CollectSnapshot(hostId, process);
                if (snapshot is not null)
                {
                    seen.Add((int)process.Pid);
                    yield return snapshot;
                }
            }

            // Drain image-load events raised since the last sweep (event-driven
            // enrichment: catches modules loaded and unloaded between sweeps).
            while (_imageLoads.TryDequeue(out var imageLoad))
            {
                if (imageLoad.Pid == 0 || !seen.Add((int)imageLoad.Pid))
                {
                    continue;
                }

                var process = new NativeCollector.ProcessInfo
                {
                    Pid = imageLoad.Pid,
                    ImagePath = imageLoad.ImagePath,
                    ProcessName = Path.GetFileName(imageLoad.ImagePath),
                };

                var snapshot = CollectSnapshot(hostId, process);
                if (snapshot is not null)
                {
                    yield return snapshot;
                }
            }

            await Task.Delay(_options.PollInterval, ct).ConfigureAwait(false);
        }
    }

    private ProcessSnapshot? CollectSnapshot(string hostId, NativeCollector.ProcessInfo process)
    {
        try
        {
            var pid = (int)process.Pid;
            var modules = NativeCollector.EnumerateModules(pid);
            if (modules.Length == 0)
            {
                return null;
            }

            var records = new List<ModuleRecord>(modules.Length);
            var hashed = 0;
            ulong imageBase = 0;
            ulong pebSize = 0;

            for (var i = 0; i < modules.Length; i++)
            {
                var module = modules[i];

                string? onDiskHash = null;
                string? inMemoryHash = null;

                if (hashed < _options.MaxHashedModulesPerProcess && !string.IsNullOrEmpty(module.Path))
                {
                    onDiskHash = PeImageReader.HashOnDiskTextSection(module.Path);
                    var textBytes = NativeCollector.ReadTextSection(pid, module.BaseAddress, _options.MaxTextSectionBytes);
                    if (textBytes.Length > 0)
                    {
                        inMemoryHash = PeImageReader.Sha256Hex(textBytes);
                    }

                    hashed++;
                }

                if (i == 0)
                {
                    imageBase = module.BaseAddress;
                    pebSize = module.Size;
                }

                records.Add(new ModuleRecord
                {
                    Path = module.Path,
                    Name = module.ModuleName,
                    BaseAddress = module.BaseAddress,
                    Size = (long)module.Size,
                    SignatureStatus = (SignatureStatus)module.SignatureStatus,
                    SignerName = module.SignerName,
                    OnDiskSha256 = onDiskHash ?? string.Empty,
                    InMemoryTextSha256 = inMemoryHash ?? string.Empty,
                    IsBackedByFile = (module.Flags & 1) != 0,
                    MemoryProtection = "PAGE_EXECUTE_READ",
                });
            }

            var regions = new List<MemoryRegionRecord>();
            foreach (var region in NativeCollector.EnumerateRegions(pid))
            {
                regions.Add(new MemoryRegionRecord
                {
                    BaseAddress = region.BaseAddress,
                    Size = (long)region.Size,
                    Protection = ProtectionName(region.Protection),
                    RegionType = RegionTypeName(region.RegionType),
                    IsExecutable = IsExecutable(region.Protection),
                    IsWritable = IsWritable(region.Protection),
                    IsBackedByFile = region.HasBackingFile,
                    BackingFile = string.IsNullOrEmpty(region.BackingFile) ? null : region.BackingFile,
                });
            }

            // PEB image base/size vs on-disk PE headers (hollowing detection).
            var onDiskImageBase = imageBase;
            var onDiskImageSize = pebSize;
            var primaryPath = records[0].Path;
            if (!string.IsNullOrEmpty(primaryPath))
            {
                var onDisk = PeImageReader.TryParse(
                    ReadHeaderProbe(primaryPath),
                    out var headers);

                if (onDisk && headers is not null)
                {
                    onDiskImageBase = headers.ImageBase;
                    onDiskImageSize = headers.SizeOfImage;
                }
            }

            return new ProcessSnapshot
            {
                HostId = hostId,
                Pid = pid,
                ProcessName = string.IsNullOrEmpty(process.ProcessName)
                    ? Path.GetFileName(process.ImagePath)
                    : process.ProcessName,
                ImagePath = process.ImagePath,
                ParentPid = (int)process.ParentPid,
                CommandLine = string.Empty,
                UserName = Environment.UserName,
                ImageBaseAddress = imageBase,
                PebImageSize = pebSize,
                OnDiskImageBase = onDiskImageBase,
                OnDiskImageSize = onDiskImageSize,
                IsProtected = false,
                IsWow64 = false,
                StartedAtUtc = DateTimeOffset.UtcNow,
                ObservedAtUtc = DateTimeOffset.UtcNow,
                Modules = records,
                MemoryRegions = regions,
            };
        }
        catch (Win32Exception ex)
        {
            _logger.LogDebug(ex, "Skipped process {Pid}: {Message}", process.Pid, ex.Message);
            return null;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogDebug(ex, "Skipped protected process {Pid}.", process.Pid);
            return null;
        }
    }

    private NativeCollector.ProcessInfo[] TryEnumerateProcesses()
    {
        try
        {
            return NativeCollector.EnumerateProcesses();
        }
        catch (Win32Exception ex)
        {
            _logger.LogWarning(ex, "Process enumeration failed: {Message}", ex.Message);
            return [];
        }
    }

    private bool ShouldCollect(string processName)
    {
        if (_options.TargetProcessNames.Length == 0 || string.IsNullOrEmpty(processName))
        {
            return true;
        }

        return _options.TargetProcessNames.Contains(processName, StringComparer.OrdinalIgnoreCase);
    }

    private void OnImageLoad(IntPtr imageLoadEvent)
    {
        try
        {
            var managed = Marshal.PtrToStructure<NativeCollector.ImageLoadEvent>(imageLoadEvent);
            if (managed.Pid != 0)
            {
                _imageLoads.Enqueue(managed);
            }
        }
        catch (ArgumentException)
        {
            // Struct could not be decoded; ignore the event rather than fault the session.
        }
    }

    private static byte[] ReadHeaderProbe(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[PeImageReader.HeaderProbeSize];
            var read = stream.Read(buffer, 0, buffer.Length);
            return read == buffer.Length ? buffer : buffer[..read];
        }
        catch (IOException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static string? ReadMachineGuid()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
        return key?.GetValue("MachineGuid") as string;
    }

    private static bool IsExecutable(uint protection)
        => (protection & 0xFF) is 0x10 or 0x20 or 0x40 or 0x80;

    private static bool IsWritable(uint protection)
        => (protection & 0xFF) is 0x04 or 0x08 or 0x40 or 0x80;

    private static string ProtectionName(uint protection) => (protection & 0xFF) switch
    {
        0x01 => "PAGE_NOACCESS",
        0x02 => "PAGE_READONLY",
        0x04 => "PAGE_READWRITE",
        0x08 => "PAGE_WRITECOPY",
        0x10 => "PAGE_EXECUTE",
        0x20 => "PAGE_EXECUTE_READ",
        0x40 => "PAGE_EXECUTE_READWRITE",
        0x80 => "PAGE_EXECUTE_WRITECOPY",
        _ => "PAGE_UNKNOWN",
    };

    private static string RegionTypeName(uint regionType) => regionType switch
    {
        0x1000000 => "MEM_IMAGE",
        0x40000 => "MEM_MAPPED",
        0x20000 => "MEM_PRIVATE",
        0x1000 => "MEM_COMMIT",
        _ => "MEM_UNKNOWN",
    };

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _etwSession?.Dispose();
    }
}

/// <summary>Owns the native ETW session handle and stops/cleans it up on release.</summary>
[SupportedOSPlatform("windows")]
internal sealed class EtwSessionHandle : SafeHandle
{
    public EtwSessionHandle()
        : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    public EtwSessionHandle(ulong handle)
        : base(unchecked((IntPtr)(long)handle), ownsHandle: true)
    {
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
        => NativeCollector.wg_etw_stop(unchecked((ulong)handle.ToInt64())) == NativeCollector.Ok;
}
