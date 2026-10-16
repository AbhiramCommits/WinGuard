using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WinGuard.Api.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class InitialSqlite : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Hosts",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Hostname = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    OsVersion = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Architecture = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    AgentVersion = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Domain = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    UserName = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    RegisteredAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastHeartbeatUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    CertificateThumbprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    Active = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Hosts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Detections",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    EventId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    HostId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Pid = table.Column<int>(type: "INTEGER", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false),
                    ImagePath = table.Column<string>(type: "TEXT", maxLength: 520, nullable: false),
                    RuleId = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    SeverityBucket = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    EvidenceJson = table.Column<string>(type: "TEXT", nullable: false),
                    ObservedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    ReceivedAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Detections", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Detections_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Heartbeats",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    HostId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Sequence = table.Column<long>(type: "INTEGER", nullable: false),
                    AgentVersion = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    ProcessCount = table.Column<int>(type: "INTEGER", nullable: false),
                    PendingEventCount = table.Column<int>(type: "INTEGER", nullable: false),
                    TimestampUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    ReceivedAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Heartbeats", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Heartbeats_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ProcessObservations",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    HostId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Pid = table.Column<int>(type: "INTEGER", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false),
                    ImagePath = table.Column<string>(type: "TEXT", maxLength: 520, nullable: false),
                    ParentPid = table.Column<int>(type: "INTEGER", nullable: false),
                    UserName = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    CommandLine = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    IsProtected = table.Column<bool>(type: "INTEGER", nullable: false),
                    ModulesJson = table.Column<string>(type: "TEXT", nullable: false),
                    MemoryRegionsJson = table.Column<string>(type: "TEXT", nullable: false),
                    ObservedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    ReceivedAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProcessObservations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ProcessObservations_Hosts_HostId",
                        column: x => x.HostId,
                        principalTable: "Hosts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Detections_HostId",
                table: "Detections",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_Detections_HostId_EventId",
                table: "Detections",
                columns: new[] { "HostId", "EventId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Detections_HostId_Pid",
                table: "Detections",
                columns: new[] { "HostId", "Pid" });

            migrationBuilder.CreateIndex(
                name: "IX_Detections_ObservedAtUtc",
                table: "Detections",
                column: "ObservedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Detections_Severity",
                table: "Detections",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_Heartbeats_HostId",
                table: "Heartbeats",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_Heartbeats_TimestampUtc",
                table: "Heartbeats",
                column: "TimestampUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Hosts_CertificateThumbprint",
                table: "Hosts",
                column: "CertificateThumbprint");

            migrationBuilder.CreateIndex(
                name: "IX_Hosts_LastHeartbeatUtc",
                table: "Hosts",
                column: "LastHeartbeatUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessObservations_HostId",
                table: "ProcessObservations",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessObservations_HostId_Pid",
                table: "ProcessObservations",
                columns: new[] { "HostId", "Pid" });

            migrationBuilder.CreateIndex(
                name: "IX_ProcessObservations_ObservedAtUtc",
                table: "ProcessObservations",
                column: "ObservedAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Detections");

            migrationBuilder.DropTable(
                name: "Heartbeats");

            migrationBuilder.DropTable(
                name: "ProcessObservations");

            migrationBuilder.DropTable(
                name: "Hosts");
        }
    }
}
