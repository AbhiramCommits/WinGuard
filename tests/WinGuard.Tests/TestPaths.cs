namespace WinGuard.Tests;

/// <summary>Locates repository fixtures (the committed corpus) from the test bin directory.</summary>
public static class TestPaths
{
    public static string RepoRoot { get; } = FindRepoRoot();

    public static string CorpusFile(string name) => Path.Combine(RepoRoot, "data", "corpus", name);

    public static string ResultsDirectory => Path.Combine(RepoRoot, "results");

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "WinGuard.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not locate the repository root (WinGuard.sln).");
    }
}
