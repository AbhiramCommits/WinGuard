namespace WinGuard.Agent;

/// <summary>
/// Resolves corpus paths relative to the repository when running from a source
/// checkout (for example <c>dotnet run</c> or the e2e script) and relative to
/// the binary directory otherwise.
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
