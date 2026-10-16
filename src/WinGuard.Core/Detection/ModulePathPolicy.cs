using WinGuard.Core.Models;

namespace WinGuard.Core.Detection;

/// <summary>
/// Decides whether a module path is a legitimate load location.
/// </summary>
/// <remarks>
/// Paths are Windows paths, and the agent may be evaluated on macOS/Linux, so
/// the comparison is done by hand rather than with <see cref="Path"/>: separators
/// are normalised to <c>\</c>, comparison is case-insensitive, and a root matches
/// only on a directory boundary (so <c>C:\Program Files</c> does not match
/// <c>C:\Program Files (x86)\...</c>).
/// </remarks>
public static class ModulePathPolicy
{
    public static IReadOnlyList<string> AllowedRootsFor(ProcessSnapshot snapshot, DetectionOptions options)
    {
        var roots = new List<string>(options.AllowedModuleRoots);

        var imageDirectory = DirectoryOf(snapshot.ImagePath);
        if (!string.IsNullOrWhiteSpace(imageDirectory))
        {
            roots.Add(imageDirectory);
        }

        return roots;
    }

    public static bool IsAllowed(string? modulePath, IReadOnlyList<string> allowedRoots)
    {
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return false;
        }

        var normalized = Normalize(modulePath);

        foreach (var root in allowedRoots)
        {
            if (string.IsNullOrWhiteSpace(root))
            {
                continue;
            }

            var normalizedRoot = Normalize(root);
            if (normalized.Equals(normalizedRoot, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (normalized.StartsWith(normalizedRoot + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Returns the directory portion of a Windows path, or null.</summary>
    public static string? DirectoryOf(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var index = path.LastIndexOfAny(['\\', '/']);
        return index > 0 ? path[..index] : null;
    }

    private static string Normalize(string path)
    {
        var normalized = path.Replace('/', '\\').Trim();
        return normalized.TrimEnd('\\');
    }
}
