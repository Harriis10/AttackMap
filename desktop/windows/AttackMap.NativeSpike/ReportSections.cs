using System.Text.Json;
namespace AttackMap.NativeSpike;

public enum SectionAvailability { Missing, Present, Malformed, Partial }
public sealed record ReportSection<T>(SectionAvailability Availability, int? SuppliedCount, IReadOnlyList<T> Rows, string Notice);
public sealed record EvidenceRow(int SourceIndex, string? Id, string? Name, string? File, int? Line, string? EvidenceBasis, JsonElement Source);
public sealed record ExploitabilityRow(EvidenceRow Evidence, string? Subject, string? Route, string? Method, string? SinkKind, double? Score, string? Tier);
public sealed record PathRow(EvidenceRow Evidence, string? Impact, JsonElement? Steps);
public sealed record SurfaceRow(EvidenceRow Evidence, string? Method, string? Route, string? Exposure);
public sealed record DependencyRow(EvidenceRow Evidence, string? Version, string? Ecosystem);
// Deliberately no raw secret record, value, match or evidence text in this model.
public sealed record SecretRow(int SourceIndex, string? Id, string? Name, string? Kind, string? File, int? Line);
public sealed record SuppressedRow(EvidenceRow Evidence, string? Title, string? Reason, JsonElement? SuppressedBy, string? Expiry);
public sealed record FleetRepositoryRow(int SourceIndex, string? RepositoryId, string? Root, string? ReportDirectory, JsonElement Source);
public sealed record FleetSections(string ReadHash, string? GenerationId, ReportSection<FleetRepositoryRow> Repositories, ReportSection<EvidenceRow> Links, JsonElement? Failed, string Notice);
public sealed record ReportSections(
    string Repository, string ReadHash, string? GenerationId,
    ReportSection<ExploitabilityRow> Exploitability, ReportSection<PathRow> Paths,
    ReportSection<SurfaceRow> Surface, ReportSection<SurfaceRow> Routes, ReportSection<DependencyRow> Dependencies,
    ReportSection<EvidenceRow> Vulnerabilities, ReportSection<SecretRow> Secrets,
    ReportSection<EvidenceRow> Workflows, ReportSection<EvidenceRow> Taint,
    ReportSection<EvidenceRow> Analyzers, ReportSection<EvidenceRow> AnalyzerErrors,
    ReportSection<SuppressedRow> Suppressed, ReportSection<EvidenceRow> Fleet,
    JsonElement? ResourceLimits, JsonElement? ResourceLimitScopes, JsonElement? ResourceLimitReporting, JsonElement? Limitations, string Notice);
