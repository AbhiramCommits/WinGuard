namespace WinGuard.Eval;

/// <summary>
/// Locates the repository root so the eval commands write to stable, committed
/// locations (<c>data/corpus</c>, <c>results/</c>) regardless of the working
/// directory the harness is invoked from.
/// </summary>
public static class RepoPaths
{
    public static string FindRepoRoot()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            var dir = new DirectoryInfo(start);
            while (dir is not null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "WinGuard.sln")))
                {
                    return dir.FullName;
                }

                dir = dir.Parent;
            }
        }

        return Directory.GetCurrentDirectory();
    }

    public static string CorpusDirectory => Path.Combine(FindRepoRoot(), "data", "corpus");

    public static string CorpusFile(string name) => Path.Combine(CorpusDirectory, name);

    public static string ResultsDirectory => Path.Combine(FindRepoRoot(), "results");
}
