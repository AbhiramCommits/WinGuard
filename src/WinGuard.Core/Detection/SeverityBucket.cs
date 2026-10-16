namespace WinGuard.Core.Detection;

/// <summary>Analyst-facing severity bucket derived from the 0-100 score.</summary>
public enum SeverityBucket
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// <summary>Maps a numeric severity onto a <see cref="SeverityBucket"/>.</summary>
public static class SeverityBuckets
{
    public static SeverityBucket FromScore(int score, DetectionOptions options)
    {
        if (score >= options.CriticalThreshold)
        {
            return SeverityBucket.Critical;
        }

        if (score >= options.HighThreshold)
        {
            return SeverityBucket.High;
        }

        return score >= options.MediumThreshold ? SeverityBucket.Medium : SeverityBucket.Low;
    }

    public static string Name(SeverityBucket bucket) => bucket.ToString();
}
