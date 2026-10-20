using System.Text.Json;
namespace AttackMap.NativeSpike;

public sealed record RiskSourceLink(string File, int? Line);
public sealed record RiskPathItem(string Kind, int SourceIndex, string? Id, string Title, string? Route, string? Sink,
    string Confidence, string Classification, double? Score, string Detail, IReadOnlyList<RiskSourceLink> Sources, IReadOnlyList<string> FindingIds)
{
    public string Label => $"{Kind}: {Title} | {Classification} | confidence {Confidence}" + (Score.HasValue ? $" | core score {Score}" : "");
}
public sealed class RiskPathsViewModel
{
    public IReadOnlyList<RiskPathItem> All { get; }
    public IReadOnlyList<RiskPathItem> Visible { get; private set; }
    public RiskPathItem? Selected { get; private set; }
    public string Notice { get; private set; } = "";
    public string Generation { get; }
    private readonly ReportSections report;
    public RiskPathsViewModel(ReportSections report)
    {
        this.report = report;
        Generation = report.GenerationId ?? "unknown (legacy import)";
        var rows = new List<RiskPathItem>();
        foreach(var row in report.Exploitability.Rows)
            rows.Add(Project("Exploitability",row.Evidence,row.Subject ?? "Unnamed supplied score",row.Route,row.SinkKind,row.Score));
        foreach(var row in report.Paths.Rows)
            rows.Add(Project("Attack path",row.Evidence,row.Evidence.Name ?? "Unnamed supplied path",Text(row.Evidence.Source,"route"),Text(row.Evidence.Source,"sink_kind"),null));
        All = rows.AsReadOnly(); Visible = All; Filter();
    }
    public void Filter(string route = "",string sink = "",string confidence = "",string classification = "")
    {
        static bool Matches(string? value,string filter) => filter.Length == 0 || (value ?? "unknown").Contains(filter,StringComparison.OrdinalIgnoreCase);
        Visible = All.Where(r=>Matches(r.Route,route)&&Matches(r.Sink,sink)&&Matches(r.Confidence,confidence)&&Matches(r.Classification,classification)).ToArray();
        if (Selected != null && !Visible.Contains(Selected)) Selected = null;
        Notice = $"{Visible.Count} displayed / {All.Count} projected. Generation: {Generation}.\n" + report.Exploitability.Notice + "\n" + report.Paths.Notice;
        if (Visible.Count == 0)
            Notice += All.Count > 0 ? "\nNo rows match these filters; supplied results remain available." :
                report.Paths.Availability == SectionAvailability.Missing || report.Exploitability.Availability == SectionAvailability.Missing ? "\nA requested section is unavailable; completeness unknown." : "\nSupplied sections contain no displayable rows; inspect partial/malformed notices.";
        Notice += "\nStatic evidence and scores do not establish runtime compromise. Missing confidence/classification remains unknown.";
    }
    public void Select(RiskPathItem? item) => Selected = item != null && Visible.Contains(item) ? item : null;
    private static RiskPathItem Project(string kind,EvidenceRow evidence,string title,string? route,string? sink,double? score)
    {
        var source=evidence.Source;
        string confidence = Scalar(source,"confidence") ?? "unknown";
        string classification = Text(source,"evidence_class") ?? evidence.EvidenceBasis ?? Text(source,"classification") ?? "unknown";
        var links = new List<RiskSourceLink>();
        void Location(JsonElement location)
        {
            if(location.ValueKind != JsonValueKind.Object || Text(location,"file") is not string file) return;
            int? line = location.TryGetProperty("line",out var value)&&value.TryGetInt32Safe(out int n) ? n : null;
            links.Add(new(file,line));
        }
        Location(source);
        if(source.TryGetProperty("locations",out var locations)&&locations.ValueKind==JsonValueKind.Array)
            foreach(var location in locations.EnumerateArray()) Location(location);
        var findingIds = new List<string>();
        if(Text(source,"finding_id") is string findingId) findingIds.Add(findingId);
        if(source.TryGetProperty("finding_ids",out var ids)&&ids.ValueKind==JsonValueKind.Array)
            findingIds.AddRange(ids.EnumerateArray().Where(i=>i.ValueKind==JsonValueKind.String).Select(i=>i.GetString()!));
        var detail = new List<string> {title,$"Supplied classification: {classification}; confidence: {confidence}", $"Core score: {(score.HasValue ? score.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : "not supplied")}"};
        foreach(string field in new[]{"impact","steps","factors","evidence","code_flows","limitations","uncertainty","location"})
            if(source.TryGetProperty(field,out var value)) detail.Add($"{field} (supplied)\n{value}");
        detail.Add(links.Count==0 ? "No structured source location supplied; textual locations are not inferred into links." : "Source links require host source validation before opening.");
        if(findingIds.Count==0) detail.Add("No explicit finding link supplied; none inferred by title or route.");
        return new(kind,evidence.SourceIndex,evidence.Id,title,route,sink,confidence,classification,score,string.Join("\n\n",detail),links.AsReadOnly(),findingIds.AsReadOnly());
    }
    private static string? Text(JsonElement source,string key) => source.TryGetProperty(key,out var value)&&value.ValueKind==JsonValueKind.String ? value.GetString() : null;
    private static string? Scalar(JsonElement source,string key) => source.TryGetProperty(key,out var value)&&value.ValueKind is JsonValueKind.String or JsonValueKind.Number ? value.ToString() : null;
}
internal static class RiskJsonExtensions
{
    public static bool TryGetInt32Safe(this JsonElement value,out int number) { number=0; return value.ValueKind==JsonValueKind.Number&&value.TryGetInt32(out number); }
}
