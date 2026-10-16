using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WinGuard.Api.Data.Migrations.SqlServer
{
    /// <inheritdoc />
    public partial class InitialSqlServer : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Hosts",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Hostname = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    OsVersion = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Architecture = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    AgentVersion = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Domain = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    UserName = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    RegisteredAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastHeartbeatUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    CertificateThumbprint = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    Active = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Hosts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Detections",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    EventId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    HostId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Pid = table.Column<int>(type: "int", nullable: false),
                    ProcessName = table.Column<string>(type: "nvarchar(260)", maxLength: 260, nullable: false),
                    ImagePath = table.Column<string>(type: "nvarchar(520)", maxLength: 520, nullable: false),
                    RuleId = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    Severity = table.Column<int>(type: "int", nullable: false),
                    SeverityBucket = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    Title = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    EvidenceJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ObservedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ReceivedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
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
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    HostId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Sequence = table.Column<long>(type: "bigint", nullable: false),
                    AgentVersion = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ProcessCount = table.Column<int>(type: "int", nullable: false),
                    PendingEventCount = table.Column<int>(type: "int", nullable: false),
                    TimestampUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ReceivedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
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
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    HostId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Pid = table.Column<int>(type: "int", nullable: false),
                    ProcessName = table.Column<string>(type: "nvarchar(260)", maxLength: 260, nullable: false),
                    ImagePath = table.Column<string>(type: "nvarchar(520)", maxLength: 520, nullable: false),
                    ParentPid = table.Column<int>(type: "int", nullable: false),
                    UserName = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    CommandLine = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    IsProtected = table.Column<bool>(type: "bit", nullable: false),
                    ModulesJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    MemoryRegionsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ObservedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ReceivedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
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
