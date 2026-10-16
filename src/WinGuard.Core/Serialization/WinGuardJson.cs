using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinGuard.Core.Serialization;

/// <summary>
/// Single source of truth for the JSON contract used by the JSONL telemetry
/// corpus, the corpus generator, the replay source and the round-trip tests.
/// Sharing one options instance is what makes a serialized corpus byte-stable
/// and therefore reproducible.
/// </summary>
public static class WinGuardJson
{
    /// <summary>Compact options (no indentation) — used for one-snapshot-per-line JSONL.</summary>
    public static JsonSerializerOptions Compact { get; } = Create(writeIndented: false);

    /// <summary>Indented options — used for the human-readable results and API payloads.</summary>
    public static JsonSerializerOptions Indented { get; } = Create(writeIndented: true);

    private static JsonSerializerOptions Create(bool writeIndented)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DictionaryKeyPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = writeIndented,
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
        };

        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: true));
        return options;
    }
}
