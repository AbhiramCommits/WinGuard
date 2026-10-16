using System.Collections.Concurrent;

namespace WinGuard.Api.Security;

/// <summary>
/// In-memory single-use nonce cache. A nonce seen within the retention window is
/// rejected, which makes a captured request unusable when replayed; once the
/// entry expires the nonce may be reused (by then the timestamp check in the
/// signature middleware will have rejected the old request anyway).
/// </summary>
public sealed class NonceCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    public NonceCache(TimeProvider? timeProvider = null) => _timeProvider = timeProvider ?? TimeProvider.System;

    public int Count => _entries.Count;

    /// <summary>
    /// Records a nonce. Returns false when it has already been seen inside the
    /// retention window (i.e. the request is a replay).
    /// </summary>
    public bool TryAdd(string hostId, string nonce, TimeSpan retention)
    {
        var now = _timeProvider.GetUtcNow();
        Prune(now, retention);

        var key = Key(hostId, nonce);

        while (true)
        {
            if (_entries.TryGetValue(key, out var seenAt))
            {
                if (now - seenAt < retention)
                {
                    return false;
                }

                // Expired entry: replace the timestamp so the nonce is reusable.
                if (_entries.TryUpdate(key, now, seenAt))
                {
                    return true;
                }

                continue;
            }

            if (_entries.TryAdd(key, now))
            {
                return true;
            }
        }
    }

    private void Prune(DateTimeOffset now, TimeSpan retention)
    {
        if (_entries.Count < 2048)
        {
            return;
        }

        foreach (var pair in _entries)
        {
            if (now - pair.Value >= retention)
            {
                _entries.TryRemove(pair.Key, out _);
            }
        }
    }

    private static string Key(string hostId, string nonce) => hostId + ":" + nonce;
}
