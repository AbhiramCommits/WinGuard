using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace WinGuard.Api.Data;

/// <summary>
/// Stores <see cref="DateTimeOffset"/> values as UTC ticks.
/// </summary>
/// <remarks>
/// SQLite has no native date/time type and EF Core refuses to translate
/// <c>ORDER BY</c>/comparisons over <see cref="DateTimeOffset"/> (the textual
/// representation is not orderable across offsets). Persisting UTC ticks keeps
/// the schema provider-agnostic and makes timeline/severity queries indexable.
/// SQL Server keeps its native <c>datetimeoffset</c> column instead.
/// </remarks>
public sealed class DateTimeOffsetToUtcTicksConverter : ValueConverter<DateTimeOffset, long>
{
    public DateTimeOffsetToUtcTicksConverter()
        : base(
            value => value.UtcTicks,
            ticks => new DateTimeOffset(ticks, TimeSpan.Zero))
    {
    }
}
