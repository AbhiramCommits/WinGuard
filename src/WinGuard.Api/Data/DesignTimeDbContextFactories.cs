using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace WinGuard.Api.Data;

/// <summary>
/// Design-time factories used by <c>dotnet ef migrations</c>. They let each
/// provider generate its own migration set even though both contexts live in the
/// same assembly.
/// </summary>
public sealed class SqlServerWinGuardDbContextFactory : IDesignTimeDbContextFactory<SqlServerWinGuardDbContext>
{
    public SqlServerWinGuardDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<SqlServerWinGuardDbContext>()
            .UseSqlServer(
                "Server=localhost;Database=WinGuard;User Id=sa;Password=Your_password123;TrustServerCertificate=True",
                sql => sql.MigrationsAssembly(typeof(SqlServerWinGuardDbContext).Assembly.GetName().Name))
            .Options;

        return new SqlServerWinGuardDbContext(options);
    }
}

/// <summary>SQLite design-time factory.</summary>
public sealed class SqliteWinGuardDbContextFactory : IDesignTimeDbContextFactory<SqliteWinGuardDbContext>
{
    public SqliteWinGuardDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<SqliteWinGuardDbContext>()
            .UseSqlite(
                "Data Source=winguard-design.db",
                sql => sql.MigrationsAssembly(typeof(SqliteWinGuardDbContext).Assembly.GetName().Name))
            .Options;

        return new SqliteWinGuardDbContext(options);
    }
}
