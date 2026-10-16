using Microsoft.EntityFrameworkCore;
using WinGuard.Api.Data.Entities;
using Host = WinGuard.Api.Data.Entities.Host;

namespace WinGuard.Api.Data;

/// <summary>
/// The single WinGuard schema, used with SQL Server in production and SQLite for
/// local runs, tests and CI. The provider is chosen by configuration
/// (<c>Database:Provider</c>); the two provider-specific contexts below only
/// exist so each provider has its own committed migration set.
/// </summary>
public class WinGuardDbContext : DbContext
{
    public WinGuardDbContext(DbContextOptions options)
        : base(options)
    {
    }

    public DbSet<Host> Hosts => Set<Host>();

    public DbSet<HeartbeatRecord> Heartbeats => Set<HeartbeatRecord>();

    public DbSet<DetectionRecord> Detections => Set<DetectionRecord>();

    public DbSet<ProcessObservation> ProcessObservations => Set<ProcessObservation>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Host>(entity =>
        {
            entity.HasKey(h => h.Id);
            entity.HasIndex(h => h.LastHeartbeatUtc);
            entity.HasIndex(h => h.CertificateThumbprint);
        });

        modelBuilder.Entity<HeartbeatRecord>(entity =>
        {
            entity.HasKey(h => h.Id);
            entity.HasIndex(h => h.HostId);
            entity.HasIndex(h => h.TimestampUtc);
            entity.HasOne(h => h.Host)
                .WithMany(h => h.Heartbeats)
                .HasForeignKey(h => h.HostId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<DetectionRecord>(entity =>
        {
            entity.HasKey(d => d.Id);
            entity.HasIndex(d => d.HostId);
            entity.HasIndex(d => d.ObservedAtUtc);
            entity.HasIndex(d => d.Severity);
            entity.HasIndex(d => new { d.HostId, d.Pid });
            entity.HasIndex(d => new { d.HostId, d.EventId }).IsUnique();
            entity.HasOne(d => d.Host)
                .WithMany(h => h.Detections)
                .HasForeignKey(d => d.HostId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ProcessObservation>(entity =>
        {
            entity.HasKey(o => o.Id);
            entity.HasIndex(o => o.HostId);
            entity.HasIndex(o => o.ObservedAtUtc);
            entity.HasIndex(o => new { o.HostId, o.Pid });
            entity.HasOne(o => o.Host)
                .WithMany(h => h.ProcessObservations)
                .HasForeignKey(o => o.HostId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}

/// <summary>SQL Server migration set (production provider).</summary>
public sealed class SqlServerWinGuardDbContext : WinGuardDbContext
{
    public SqlServerWinGuardDbContext(DbContextOptions<SqlServerWinGuardDbContext> options)
        : base(options)
    {
    }
}

/// <summary>SQLite migration set (local runs, tests, CI).</summary>
public sealed class SqliteWinGuardDbContext : WinGuardDbContext
{
    public SqliteWinGuardDbContext(DbContextOptions<SqliteWinGuardDbContext> options)
        : base(options)
    {
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        base.ConfigureConventions(configurationBuilder);

        // SQLite cannot order/compare DateTimeOffset columns; store UTC ticks.
        configurationBuilder
            .Properties<DateTimeOffset>()
            .HaveConversion<DateTimeOffsetToUtcTicksConverter>();
    }
}
