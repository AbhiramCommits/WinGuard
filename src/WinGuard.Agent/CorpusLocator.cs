namespace WinGuard.Agent;

/// <summary>
/// Resolves corpus/spool paths relative to the repository when running from a
/// source checkout (for example <c>dotnet run</c> or the e2e script) and
/// relative to the binary directory otherwise.
/// </summary>
public static class CorpusLocator
{
    public static string Resolve(string configuredPath)
    {
        if (Path.IsPathRooted(configuredPath))
        {
            return configuredPath;
        }

        foreach (var root in CandidateRoots())
        {
            var candidate = Path.GetFullPath(Path.Combine(root, configuredPath));
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, configuredPath));
    }

    /// <summary>Resolves a directory path and ensures it exists.</summary>
    public static string ResolveDirectory(string configuredPath)
    {
        var resolved = Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(FindRepoRoot() ?? AppContext.BaseDirectory, configuredPath));

        Directory.CreateDirectory(resolved);
        return resolved;
    }

    private static string? FindRepoRoot()
    {
        foreach (var root in CandidateRoots())
        {
            if (File.Exists(Path.Combine(root, "WinGuard.sln")))
            {
                return root;
            }
        }

        return null;
    }

    private static IEnumerable<string> CandidateRoots()
    {
        yield return Directory.GetCurrentDirectory();

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            yield return dir.FullName;
            dir = dir.Parent;
        }
    }
}
