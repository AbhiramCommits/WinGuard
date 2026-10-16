using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace WinGuard.Agent.Telemetry;

/// <summary>
/// P/Invoke binding for <c>winguard_native.dll</c> — the real Win32/ETW
/// collector. Every exported function is declared here; the managed callers
/// marshal into the model types in <c>WinGuard.Core.Models</c>.
/// </summary>
/// <remarks>
/// The native library only exists on Windows. This type is annotated
/// <see cref="SupportedOSPlatformAttribute"/> so the compiler forces every
/// caller to guard with <see cref="OperatingSystem.IsWindows"/>; the DI
/// registration in <c>Program.cs</c> does exactly that.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class NativeCollector
{
    internal const string LibraryName = "winguard_native";

    private const int PathChars = 520;
    private const int NameChars = 260;

    // Return codes mirrored from winguard_native.h.
    internal const int Ok = 0;
    internal const int ErrorFailure = -1;
    internal const int ErrorBuffer = -2;
    internal const int ErrorAccess = -3;
    internal const int ErrorNotFound = -4;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
    internal struct ProcessInfo
    {
        public uint Pid;
        public uint ParentPid;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathChars)]
        public string ImagePath;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = NameChars)]
        public string ProcessName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
    internal struct ModuleInfo
    {
        public ulong BaseAddress;
        public ulong Size;
        public int SignatureStatus;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathChars)]
        public string Path;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = NameChars)]
        public string ModuleName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = NameChars)]
        public string SignerName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
    internal struct RegionInfo
    {
        public ulong BaseAddress;
        public ulong Size;
        public uint Protection;
        public uint RegionType;

        [MarshalAs(UnmanagedType.I1)]
        public bool HasBackingFile;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathChars)]
        public string BackingFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
    internal struct ImageLoadEvent
    {
        public uint Pid;
        public uint Tid;
        public ulong ImageBase;
        public ulong ImageSize;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathChars)]
        public string ImagePath;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void ImageLoadCallback(IntPtr imageLoadEvent);

    // ---- Exports ----------------------------------------------------------

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    internal static extern int wg_native_abi_version();

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    internal static extern int wg_native_last_error();

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    internal static extern int wg_enumerate_processes(
        [Out] ProcessInfo[] buffer, int capacity, out int count);

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    internal static extern int wg_enumerate_modules(
        uint pid, [Out] ModuleInfo[] buffer, int capacity, out int count);

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    internal static extern int wg_enumerate_regions(
        uint pid, [Out] RegionInfo[] buffer, int capacity, out int count);

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    internal static extern int wg_read_text_section(
        uint pid, ulong imageBase, [Out] byte[] buffer, uint capacity, out uint written);

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true)]
    internal static extern int wg_etw_start(
        [MarshalAs(UnmanagedType.LPWStr)] string sessionName,
        ImageLoadCallback callback,
        out ulong sessionHandle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    internal static extern int wg_etw_stop(ulong sessionHandle);

    // ---- Managed wrappers -------------------------------------------------

    internal static ProcessInfo[] EnumerateProcesses()
    {
        var capacity = 512;

        while (true)
        {
            var buffer = new ProcessInfo[capacity];
            var rc = wg_enumerate_processes(buffer, capacity, out var count);

            if (rc == Ok)
            {
                return buffer[..count];
            }

            if (rc == ErrorBuffer)
            {
                capacity = Math.Max(count, capacity + 256);
                continue;
            }

            throw NativeFailure("wg_enumerate_processes", rc);
        }
    }

    internal static ModuleInfo[] EnumerateModules(int pid)
    {
        var capacity = 256;

        while (true)
        {
            var buffer = new ModuleInfo[capacity];
            var rc = wg_enumerate_modules((uint)pid, buffer, capacity, out var count);

            if (rc == Ok)
            {
                return buffer[..count];
            }

            if (rc == ErrorBuffer)
            {
                capacity = Math.Max(count, capacity + 128);
                continue;
            }

            if (rc is ErrorAccess or ErrorNotFound)
            {
                return [];
            }

            throw NativeFailure("wg_enumerate_modules", rc);
        }
    }

    internal static RegionInfo[] EnumerateRegions(int pid)
    {
        var capacity = 2048;

        while (true)
        {
            var buffer = new RegionInfo[capacity];
            var rc = wg_enumerate_regions((uint)pid, buffer, capacity, out var count);

            if (rc == Ok)
            {
                return buffer[..count];
            }

            if (rc == ErrorBuffer)
            {
                capacity = Math.Max(count, capacity + 1024);
                continue;
            }

            if (rc is ErrorAccess or ErrorNotFound)
            {
                return [];
            }

            throw NativeFailure("wg_enumerate_regions", rc);
        }
    }

    internal static byte[] ReadTextSection(int pid, ulong imageBase, int maxBytes)
    {
        var buffer = new byte[maxBytes];
        var rc = wg_read_text_section((uint)pid, imageBase, buffer, (uint)maxBytes, out var written);

        if (rc != Ok)
        {
            return [];
        }

        return buffer[..(int)written];
    }

    private static Exception NativeFailure(string operation, int rc)
        => new Win32Exception(rc, $"{operation} failed in {LibraryName}.dll (status {rc}).");
}
