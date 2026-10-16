using WinGuard.Core.Detection;
using WinGuard.Core.Models;
using WinGuard.Core.Telemetry;

namespace WinGuard.Eval.Corpus;

/// <summary>Summary of a completed corpus generation run.</summary>
public sealed record CorpusResult(
    int HostCount,
    int BenignCount,
    int LabeledCount,
    int TamperedCount,
    string BenignPath,
    string LabeledPath);

/// <summary>
/// Deterministic, seeded generator for the synthetic telemetry corpus.
/// </summary>
/// <remarks>
/// The generator models ~40 endpoints running realistic Windows process/module
/// sets and injects the six tamper categories WinGuard detects. Every snapshot
/// carries a ground-truth <c>labels</c> array naming the rule ids that *must*
/// fire (empty for benign). The rules in <c>WinGuard.Core.Detection</c> are
/// written against exactly these semantics, so the benchmark measures the real
/// engine rather than a lookup table.
/// </remarks>
public sealed class CorpusGenerator
{
    private static readonly string[] Sites = ["SEA", "NYC", "LON", "TOK", "FRA", "SYD", "BLR", "SFO", "AMS", "SIN"];
    private static readonly string[] Domains = ["CORP", "LAB", "HQ", "EDGE", "RND"];
    private static readonly string[] TamperKinds =
    [
        "injected-dll",
        "manual-map",
        "patched-code",
        "unsigned-module",
        "rwx-region",
        "process-hollowing",
    ];

    private readonly CorpusOptions _options;
    private readonly Random _rng;
    private readonly List<SimHost> _hosts;

    public CorpusGenerator(CorpusOptions options)
    {
        _options = options;
        _rng = new Random(options.Seed);
        _hosts = BuildHosts(_rng, options.HostCount);
    }

    public async Task<CorpusResult> GenerateAsync(string outputDirectory, CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);

        var benignPath = Path.Combine(outputDirectory, "benign.jsonl");
        var labeledPath = Path.Combine(outputDirectory, "labeled.jsonl");

        var benignStart = new DateTimeOffset(2026, 1, 12, 8, 0, 0, TimeSpan.Zero);
        var benign = BuildBenign(_options.BenignSnapshotCount, benignStart);
        await TelemetryJsonl.WriteAllAsync(benignPath, benign, ct).ConfigureAwait(false);

        var labeledStart = benignStart.AddDays(3);
        var (labeled, tampered) = BuildLabeled(_options.LabeledSnapshotCount, labeledStart);
        await TelemetryJsonl.WriteAllAsync(labeledPath, labeled, ct).ConfigureAwait(false);

        return new CorpusResult(_hosts.Count, benign.Count, labeled.Count, tampered, benignPath, labeledPath);
    }

    // -----------------------------------------------------------------------
    // Corpus assembly
    // -----------------------------------------------------------------------

    private List<ProcessSnapshot> BuildBenign(int count, DateTimeOffset start)
    {
        var snapshots = new List<ProcessSnapshot>(count);

        for (var i = 0; i < count; i++)
        {
            var host = _hosts[_rng.Next(_hosts.Count)];
            var arch = PickArchetype(requireProtected: false);
            var observed = start.AddSeconds(i * _options.SnapshotInterval.TotalSeconds);

            var draft = CreateDraft(host, arch, observed);

            // Hard negatives: legitimate self-signed / unsigned modules in
            // *non-protected* processes must not be reported as tamper.
            if (!arch.IsProtected && _rng.NextDouble() < 0.35)
            {
                ApplyHardNegatives(draft);
            }

            snapshots.Add(draft.ToSnapshot());
        }

        return snapshots;
    }

    private (List<ProcessSnapshot> Snapshots, int Tampered) BuildLabeled(int count, DateTimeOffset start)
    {
        var tamperedTarget = (int)Math.Round(count * _options.TamperedFraction);

        var indices = Enumerable.Range(0, count).ToList();
        Shuffle(indices);
        var tamperedIndices = indices.Take(tamperedTarget).ToList();

        var snapshots = new List<ProcessSnapshot>(count);
        var order = 0;

        for (var i = 0; i < count; i++)
        {
            var host = _hosts[_rng.Next(_hosts.Count)];
            var observed = start.AddSeconds(i * _options.SnapshotInterval.TotalSeconds);
            var isTampered = tamperedIndices.Contains(i);

            Archetype arch;
            if (isTampered)
            {
                var kind = TamperKinds[order % TamperKinds.Length];
                order++;

                arch = PickArchetype(RequiresProtectedProcess(kind));

                var draft = CreateDraft(host, arch, observed);
                ApplyTamper(draft, kind);

                // Occasionally combine two indicators so severity correlation is exercised.
                if (order % 7 == 0)
                {
                    ApplyTamper(draft, TamperKinds[_rng.Next(TamperKinds.Length)]);
                }

                snapshots.Add(draft.ToSnapshot());
            }
            else
            {
                arch = PickArchetype(requireProtected: false);
                var draft = CreateDraft(host, arch, observed);

                if (!arch.IsProtected && _rng.NextDouble() < 0.35)
                {
                    ApplyHardNegatives(draft);
                }

                snapshots.Add(draft.ToSnapshot());
            }
        }

        return (snapshots, tamperedTarget);
    }

    private static bool RequiresProtectedProcess(string kind)
        => kind is "injected-dll" or "unsigned-module" or "rwx-region";

    // -----------------------------------------------------------------------
    // Snapshot construction
    // -----------------------------------------------------------------------

    private SnapshotDraft CreateDraft(SimHost host, Archetype arch, DateTimeOffset observed)
    {
        var uptimeSeconds = _rng.Next(30, 60 * 60 * 12);
        var imageBase = 0x00007FF6_00000000UL + (ulong)(_rng.Next(0, 0x400) * 0x10000);
        var sizeOfImage = Align((ulong)_rng.Next(0x40000, 0x1C00000), 0x1000);
        var mainHash = Hex(64);

        var draft = new SnapshotDraft
        {
            HostId = host.HostId,
            Pid = _rng.Next(1000, 60000),
            ProcessName = arch.Name,
            ImagePath = JoinPath(arch.Directory, arch.Name),
            ParentPid = _rng.Next(500, 4000),
            CommandLine = arch.BuildCommandLine(),
            UserName = arch.UserName,
            ImageBaseAddress = imageBase,
            PebImageSize = sizeOfImage,
            OnDiskImageBase = imageBase,
            OnDiskImageSize = sizeOfImage,
            IsProtected = arch.IsProtected,
            IsWow64 = false,
            StartedAtUtc = observed.AddSeconds(-uptimeSeconds),
            ObservedAtUtc = observed,
        };

        draft.Modules.Add(new ModuleRecord
        {
            Path = draft.ImagePath,
            Name = arch.Name,
            BaseAddress = imageBase,
            Size = (long)sizeOfImage,
            SignatureStatus = SignatureStatus.Signed,
            SignerName = arch.Publisher,
            OnDiskSha256 = mainHash,
            InMemoryTextSha256 = mainHash,
            IsBackedByFile = true,
            MemoryProtection = "PAGE_EXECUTE_READ",
        });

        foreach (var template in SystemModuleCatalog.AlwaysLoaded)
        {
            draft.Modules.Add(Materialize(template, draft.NextBase()));
        }

        foreach (var template in Pick(arch.Extras, 2, Math.Min(4, arch.Extras.Length)))
        {
            draft.Modules.Add(Materialize(template, draft.NextBase()));
        }

        foreach (var template in Pick(arch.LocalExtras, 1, Math.Min(2, arch.LocalExtras.Length)))
        {
            draft.Modules.Add(Materialize(
                template with { Path = JoinPath(arch.Directory, template.Name) },
                draft.NextBase()));
        }

        AddBaselineRegions(draft);
        return draft;
    }

    private void AddBaselineRegions(SnapshotDraft draft)
    {
        // Image-backed executable regions, one per loader-mapped module (capped).
        // The backing path is recorded only for the primary image: every other
        // region's path is implied by the module list, and omitting it keeps the
        // committed corpus compact.
        var backed = draft.Modules.Where(m => m.IsBackedByFile).Take(5).ToList();
        for (var i = 0; i < backed.Count; i++)
        {
            var module = backed[i];
            draft.Regions.Add(new MemoryRegionRecord
            {
                BaseAddress = module.BaseAddress,
                Size = module.Size,
                Protection = "PAGE_EXECUTE_READ",
                RegionType = "MEM_IMAGE",
                IsExecutable = true,
                IsWritable = false,
                IsBackedByFile = true,
                BackingFile = i == 0 ? module.Path : null,
            });
        }

        // Private, writable, non-executable heaps/stacks — the normal case.
        var heapCount = _rng.Next(2, 4);
        for (var i = 0; i < heapCount; i++)
        {
            draft.Regions.Add(new MemoryRegionRecord
            {
                BaseAddress = draft.NextBase(),
                Size = _rng.Next(0x1000, 0x400000),
                Protection = "PAGE_READWRITE",
                RegionType = "MEM_PRIVATE",
                IsExecutable = false,
                IsWritable = true,
                IsBackedByFile = false,
            });
        }
    }

    private void ApplyHardNegatives(SnapshotDraft draft)
    {
        // Signed-elsewhere modules that are legitimately present but neither
        // Microsoft-signed nor in a protected process.
        var indices = Enumerable.Range(0, draft.Modules.Count)
            .Where(i => draft.Modules[i].SignatureStatus == SignatureStatus.Signed && draft.Modules[i].IsBackedByFile)
            .OrderBy(_ => _rng.Next())
            .Take(_rng.Next(1, 3))
            .ToList();

        foreach (var index in indices)
        {
            draft.Modules[index] = draft.Modules[index] with
            {
                SignatureStatus = _rng.Next(2) == 0 ? SignatureStatus.SelfSigned : SignatureStatus.Unsigned,
                SignerName = "In-house Development Team",
            };
        }

        // A read-only private region is perfectly normal and must not be flagged.
        draft.Regions.Add(new MemoryRegionRecord
        {
            BaseAddress = draft.NextBase(),
            Size = _rng.Next(0x1000, 0x20000),
            Protection = "PAGE_READONLY",
            RegionType = "MEM_PRIVATE",
            IsExecutable = false,
            IsWritable = false,
            IsBackedByFile = false,
        });
    }

    private void ApplyTamper(SnapshotDraft draft, string kind)
    {
        switch (kind)
        {
            case "injected-dll":
                ApplyInjectedDll(draft);
                break;
            case "manual-map":
                ApplyManualMap(draft);
                break;
            case "patched-code":
                ApplyPatchedCode(draft);
                break;
            case "unsigned-module":
                ApplyUnsignedModule(draft);
                break;
            case "rwx-region":
                ApplyRwxRegion(draft);
                break;
            case "process-hollowing":
                ApplyProcessHollowing(draft);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown tamper kind.");
        }
    }

    private void ApplyInjectedDll(SnapshotDraft draft)
    {
        var fileName = $"payload_{Hex(8)}.dll";
        var hash = Hex(64);

        draft.Modules.Add(new ModuleRecord
        {
            Path = $@"C:\Users\Public\Downloads\{fileName}",
            Name = fileName,
            BaseAddress = draft.NextBase(),
            Size = _rng.Next(0x8000, 0x400000),
            SignatureStatus = SignatureStatus.Unsigned,
            SignerName = string.Empty,
            OnDiskSha256 = hash,
            InMemoryTextSha256 = hash,
            IsBackedByFile = true,
            MemoryProtection = "PAGE_EXECUTE_READ",
        });

        draft.Labels.Add(RuleIds.InjectedModulePath);
        draft.Labels.Add(RuleIds.UnsignedModuleLoaded);
    }

    private void ApplyManualMap(SnapshotDraft draft)
    {
        var size = _rng.Next(0x4000, 0x80000);
        var baseAddress = draft.NextBase();

        draft.Modules.Add(new ModuleRecord
        {
            Path = string.Empty,
            Name = "unknown",
            BaseAddress = baseAddress,
            Size = size,
            SignatureStatus = SignatureStatus.Unknown,
            SignerName = string.Empty,
            OnDiskSha256 = string.Empty,
            InMemoryTextSha256 = string.Empty,
            IsBackedByFile = false,
            MemoryProtection = "PAGE_EXECUTE_READ",
        });

        draft.Regions.Add(new MemoryRegionRecord
        {
            BaseAddress = baseAddress,
            Size = size,
            Protection = "PAGE_EXECUTE_READ",
            RegionType = "MEM_PRIVATE",
            IsExecutable = true,
            IsWritable = false,
            IsBackedByFile = false,
        });

        draft.Labels.Add(RuleIds.UnbackedExecutableMemory);
    }

    private void ApplyPatchedCode(SnapshotDraft draft)
    {
        var candidates = Enumerable.Range(0, draft.Modules.Count)
            .Where(i => draft.Modules[i].SignatureStatus == SignatureStatus.Signed
                        && draft.Modules[i].IsBackedByFile
                        && draft.Modules[i].OnDiskSha256.Length == 64)
            .ToList();

        var index = candidates[_rng.Next(candidates.Count)];
        draft.Modules[index] = draft.Modules[index] with { InMemoryTextSha256 = Hex(64) };
        draft.Labels.Add(RuleIds.PatchedCodeSection);
    }

    private void ApplyUnsignedModule(SnapshotDraft draft)
    {
        var template = _rng.Next(2) == 0
            ? SystemModuleCatalog.SelfSignedSystemModule($"wgsvc_{Hex(6)}.dll")
            : SystemModuleCatalog.UnsignedDriver($"wg{Hex(6)}.sys");

        draft.Modules.Add(Materialize(template, draft.NextBase()));
        draft.Labels.Add(RuleIds.UnsignedModuleLoaded);
    }

    private void ApplyRwxRegion(SnapshotDraft draft)
    {
        draft.Regions.Add(new MemoryRegionRecord
        {
            BaseAddress = draft.NextBase(),
            Size = _rng.Next(0x1000, 0x200000),
            Protection = "PAGE_EXECUTE_READWRITE",
            RegionType = "MEM_PRIVATE",
            IsExecutable = true,
            IsWritable = true,
            IsBackedByFile = false,
        });

        // An RWX private region is also an unbacked executable region.
        draft.Labels.Add(RuleIds.RwxPrivateRegion);
        draft.Labels.Add(RuleIds.UnbackedExecutableMemory);
    }

    private void ApplyProcessHollowing(SnapshotDraft draft)
    {
        var newBase = draft.OnDiskImageBase + 0x10000UL;
        draft.ImageBaseAddress = newBase;
        draft.PebImageSize = draft.OnDiskImageSize + 0x2000UL;

        if (draft.Modules.Count > 0 && draft.Modules[0].BaseAddress == draft.OnDiskImageBase)
        {
            draft.Modules[0] = draft.Modules[0] with { BaseAddress = newBase };
        }

        draft.Labels.Add(RuleIds.ProcessHollowing);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private ModuleRecord Materialize(ModuleTemplate template, ulong baseAddress)
    {
        var hash = Hex(64);

        return new ModuleRecord
        {
            Path = template.Path,
            Name = template.Name,
            BaseAddress = baseAddress,
            Size = template.Size,
            SignatureStatus = template.Status,
            SignerName = template.Signer,
            OnDiskSha256 = hash,
            InMemoryTextSha256 = hash,
            IsBackedByFile = true,
            MemoryProtection = "PAGE_EXECUTE_READ",
        };
    }

    private Archetype PickArchetype(bool requireProtected)
    {
        var pool = requireProtected ? Archetypes.Games : Archetypes.All;
        return pool[_rng.Next(pool.Length)];
    }

    private ModuleTemplate[] Pick(ModuleTemplate[] source, int min, int max)
    {
        if (source.Length == 0)
        {
            return [];
        }

        var take = _rng.Next(min, Math.Max(min, max) + 1);
        return source.OrderBy(_ => _rng.Next()).Take(Math.Min(take, source.Length)).ToArray();
    }

    private void Shuffle<T>(IList<T> list)
    {
        for (var i = list.Count - 1; i > 0; i--)
        {
            var j = _rng.Next(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }

    private string Hex(int length)
    {
        const string alphabet = "0123456789abcdef";
        var buffer = new char[length];
        for (var i = 0; i < length; i++)
        {
            buffer[i] = alphabet[_rng.Next(alphabet.Length)];
        }

        return new string(buffer);
    }

    private static ulong Align(ulong value, ulong alignment) => (value + alignment - 1) & ~(alignment - 1);

    private static string JoinPath(string directory, string name) => $@"{directory}\{name}";

    private static List<SimHost> BuildHosts(Random rng, int count)
    {
        var hosts = new List<SimHost>(count);
        for (var i = 0; i < count; i++)
        {
            var id = new string(Enumerable.Range(0, 32)
                .Select(_ => "0123456789abcdef"[rng.Next(16)])
                .ToArray());

            hosts.Add(new SimHost(
                id,
                $"WG-{Sites[i % Sites.Length]}-{i + 1:D3}",
                Domains[i % Domains.Length]));
        }

        return hosts;
    }

    // -----------------------------------------------------------------------
    // Shape types
    // -----------------------------------------------------------------------

    private sealed record SimHost(string HostId, string Hostname, string Domain);

    private sealed record Archetype(
        string Name,
        string Directory,
        bool IsProtected,
        string Publisher,
        string UserName,
        string Arguments,
        ModuleTemplate[] Extras,
        ModuleTemplate[] LocalExtras)
    {
        public string BuildCommandLine() => $@"""{JoinPath(Directory, Name)}"" {Arguments}".TrimEnd();
    }

    private static class Archetypes
    {
        private const string SteamCs = @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64";
        private const string SteamApex = @"C:\Program Files (x86)\Steam\steamapps\common\Apex Legends";
        private const string Riot = @"C:\Riot Games\VALORANT\live";
        private const string Epic = @"C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64";

        public static readonly Archetype[] Games =
        [
            new("cs2.exe", SteamCs, true, "Valve Corporation", "CORP\\gamer01", "-steam -novid",
                SystemModuleCatalog.GameExtras, SystemModuleCatalog.GameLocalExtras),
            new("r5apex.exe", SteamApex, true, "Electronic Arts, Inc.", "CORP\\gamer02", "-novid",
                SystemModuleCatalog.GameExtras, SystemModuleCatalog.GameLocalExtras),
            new("VALORANT-Win64-Shipping.exe", Riot, true, "Riot Games, Inc.", "CORP\\gamer03", "-game",
                SystemModuleCatalog.GameExtras, SystemModuleCatalog.GameLocalExtras),
            new("FortniteClient-Win64-Shipping.exe", Epic, true, "Epic Games, Inc.", "CORP\\gamer04", "-EpicPortal",
                SystemModuleCatalog.GameExtras, SystemModuleCatalog.GameLocalExtras),
        ];

        public static readonly Archetype[] Others =
        [
            new("svchost.exe", SystemModuleCatalog.System32, false, "Microsoft Windows", "NT AUTHORITY\\SYSTEM", "-k netsvcs -p",
                SystemModuleCatalog.ServiceExtras, []),
            new("lsass.exe", SystemModuleCatalog.System32, false, "Microsoft Windows", "NT AUTHORITY\\SYSTEM", string.Empty,
                SystemModuleCatalog.ServiceExtras, []),
            new("services.exe", SystemModuleCatalog.System32, false, "Microsoft Windows", "NT AUTHORITY\\SYSTEM", string.Empty,
                SystemModuleCatalog.ServiceExtras, []),
            new("chrome.exe", @"C:\Program Files\Google\Chrome\Application", false, "Google LLC", "CORP\\analyst01", "--type=renderer",
                SystemModuleCatalog.BrowserExtras, SystemModuleCatalog.BrowserExtras),
            new("msedge.exe", @"C:\Program Files (x86)\Microsoft\Edge\Application", false, "Microsoft Corporation", "CORP\\analyst02", "--type=gpu-process",
                SystemModuleCatalog.BrowserExtras, SystemModuleCatalog.BrowserExtras),
            new("firefox.exe", @"C:\Program Files\Mozilla Firefox", false, "Mozilla Corporation", "CORP\\analyst03", "-contentproc",
                SystemModuleCatalog.MozillaExtras, SystemModuleCatalog.MozillaExtras),
            new("devenv.exe", @"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE", false, "Microsoft Corporation", "CORP\\dev01", "/Run",
                SystemModuleCatalog.DevExtras, []),
            new("node.exe", @"C:\Program Files\nodejs", false, "OpenJS Foundation", "CORP\\dev02", "server.js",
                SystemModuleCatalog.DevExtras, []),
        ];

        public static readonly Archetype[] All = [.. Games, .. Others];
    }

    private sealed class SnapshotDraft
    {
        private ulong _nextBase = 0x00007FF6_40000000UL;

        public required string HostId { get; init; }

        public required int Pid { get; init; }

        public required string ProcessName { get; init; }

        public required string ImagePath { get; init; }

        public int ParentPid { get; init; }

        public string CommandLine { get; init; } = string.Empty;

        public string UserName { get; init; } = string.Empty;

        public ulong ImageBaseAddress { get; set; }

        public ulong PebImageSize { get; set; }

        public ulong OnDiskImageBase { get; init; }

        public ulong OnDiskImageSize { get; init; }

        public bool IsProtected { get; init; }

        public bool IsWow64 { get; init; }

        public DateTimeOffset StartedAtUtc { get; init; }

        public DateTimeOffset ObservedAtUtc { get; init; }

        public List<ModuleRecord> Modules { get; } = [];

        public List<MemoryRegionRecord> Regions { get; } = [];

        public SortedSet<string> Labels { get; } = new(StringComparer.Ordinal);

        public ulong NextBase()
        {
            _nextBase += 0x00000000_00100000UL;
            return _nextBase;
        }

        public ProcessSnapshot ToSnapshot() => new()
        {
            HostId = HostId,
            Pid = Pid,
            ProcessName = ProcessName,
            ImagePath = ImagePath,
            ParentPid = ParentPid,
            CommandLine = CommandLine,
            UserName = UserName,
            ImageBaseAddress = ImageBaseAddress,
            PebImageSize = PebImageSize,
            OnDiskImageBase = OnDiskImageBase,
            OnDiskImageSize = OnDiskImageSize,
            IsProtected = IsProtected,
            IsWow64 = IsWow64,
            StartedAtUtc = StartedAtUtc,
            ObservedAtUtc = ObservedAtUtc,
            Modules = Modules.ToArray(),
            MemoryRegions = Regions.ToArray(),
            Labels = Labels.ToArray(),
        };
    }
}
