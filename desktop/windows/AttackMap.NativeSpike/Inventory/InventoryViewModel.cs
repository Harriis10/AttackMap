using System.Text.Json;
namespace AttackMap.NativeSpike;

public sealed record InventorySourceLink(string File,int? Line);
public sealed record InventoryItem(string Group,int SourceIndex,string? Id,string Title,string Severity,string Confidence,string EvidenceBasis,string? File,int? Line,string Detail)
{
    public string Label=>$"{Title} | severity {Severity} | confidence {Confidence}";
}
public sealed record InventoryGroup(string Name,SectionAvailability Availability,int? SuppliedCount,IReadOnlyList<InventoryItem> Items,string Notice);
public sealed class InventoryViewModel
{
    public IReadOnlyList<InventoryGroup> Groups {get;}
    public InventoryGroup Current {get;private set;}
    public IReadOnlyList<InventoryItem> Visible {get;private set;}=Array.Empty<InventoryItem>();
    public InventoryItem? Selected {get;private set;}
    public string Notice {get;private set;}="";
    public string Generation {get;}
    private readonly string reportNotice;
    public InventoryViewModel(ReportSections report)
    {
        Generation=report.GenerationId??"unknown (legacy import)";
        reportNotice=report.Notice;
        if(report.Limitations is JsonElement limitations&&limitations.ValueKind==JsonValueKind.Array)
            reportNotice+="\nScan limitations: "+string.Join("; ",limitations.EnumerateArray().Where(v=>v.ValueKind==JsonValueKind.String).Select(v=>v.GetString()));
        if(report.ResourceLimitReporting is JsonElement reporting&&reporting.ValueKind==JsonValueKind.String)
            reportNotice+="\nResource-limit reporting: "+reporting.GetString();
        if(report.ResourceLimits is JsonElement limits&&limits.ValueKind==JsonValueKind.Array&&limits.GetArrayLength()>0)
            reportNotice+=$"\n{limits.GetArrayLength()} core resource-limit events supplied; coverage may be partial. Canonical report retains event details.";
        var groups=new List<InventoryGroup>();
        void Add<T>(string name,ReportSection<T> section,Func<T,InventoryItem> project) => groups.Add(new(name,section.Availability,section.SuppliedCount,section.Rows.Select(project).ToArray(),section.Notice));
        Add("Attack surface",report.Surface,r=>Project("Attack surface",r.Evidence,$"{r.Method??"unknown"} {r.Route??"unknown"}"));
        Add("Routes",report.Routes,r=>Project("Routes",r.Evidence,$"{r.Method??"unknown"} {r.Route??"unknown"}"));
        Add("Dependencies",report.Dependencies,r=>Project("Dependencies",r.Evidence,$"{r.Ecosystem??"unknown"}: {r.Evidence.Name??"unknown"} @ {r.Version??"unknown"}"));
        Add("CVE / vulnerabilities",report.Vulnerabilities,r=>Project("CVE / vulnerabilities",r,Text(r.Source,"vuln_id")??r.Id??r.Name??"Unnamed supplied vulnerability"));
        Add("Secrets",report.Secrets,r=>new InventoryItem("Secrets",r.SourceIndex,r.Id,r.Name??"Unnamed secret hint","unknown","unknown","unknown",r.File,r.Line,$"Secret hint: {r.Name??"unknown"}\nKind: {r.Kind??"unknown"}\nLocation: {r.File??"unknown"}:{r.Line?.ToString()??"unknown"}\nRaw values and secret evidence are excluded from this projection. Missing severity/confidence remain unknown."));
        Add("CI workflows",report.Workflows,r=>Project("CI workflows",r,Text(r.Source,"title")??r.Name??Text(r.Source,"kind")??"Unnamed workflow issue"));
        Add("Data flows",report.Taint,r=>Project("Data flows",r,Text(r.Source,"sink_kind")??r.Name??"Unnamed supplied flow"));
        Add("Analyzers",report.Analyzers,r=>Project("Analyzers",r,r.Name??Text(r.Source,"analyzer")??"Unnamed analyzer record"));
        Add("Analyzer errors",report.AnalyzerErrors,r=>Project("Analyzer errors",r,Text(r.Source,"analyzer")??r.Name??"Unnamed analyzer error"));
        Groups=groups.AsReadOnly();Current=Groups[0];Filter();
    }
    public void Choose(string name)
    {
        Current=Groups.First(g=>g.Name==name);Selected=null;Filter();
    }
    public void Filter(string query="",string severity="",string confidence="",string evidence="")
    {
        static bool Match(string? value,string filter)=>filter.Length==0||(value??"unknown").Contains(filter,StringComparison.OrdinalIgnoreCase);
        Visible=Current.Items.Where(r=>Match(r.Title,query)&&Match(r.Severity,severity)&&Match(r.Confidence,confidence)&&Match(r.EvidenceBasis,evidence)).ToArray();
        if(Selected!=null&&!Visible.Contains(Selected))Selected=null;
        Notice=$"{Current.Name}: {Visible.Count} displayed / {Current.Items.Count} projected; source total: {Current.SuppliedCount?.ToString()??"unknown"}. Generation: {Generation}.\n{Current.Notice}";
        if(Visible.Count==0)Notice+=Current.Items.Count>0?"\nNo matches for these filters; source records remain available.":Current.Availability==SectionAvailability.Missing?"\nSection unavailable; completeness unknown.":"\nNo displayable records supplied; inspect partial/malformed status.";
        if(Current.Name=="CVE / vulnerabilities")Notice+="\nCVE lookup state is not supplied by this projection. Empty records do not prove lookup ran or that no vulnerability exists.";
        if(Current.Name.StartsWith("Analyzer"))Notice+="\nAbsent, failed, not used and not applicable remain distinct only when explicitly supplied. Empty errors do not establish analyzer success or installation.";
        Notice+="\nCore source order is preserved. Static records do not establish runtime verification.";
        Notice+="\n"+reportNotice;
    }
    public void Select(InventoryItem? item)=>Selected=item!=null&&Visible.Contains(item)?item:null;
    private static InventoryItem Project(string group,EvidenceRow row,string title)
    {
        string severity=Scalar(row.Source,"severity")??"unknown",confidence=Scalar(row.Source,"confidence")??"unknown",basis=row.EvidenceBasis??Text(row.Source,"evidence_class")??"unknown";
        var lines=new List<string>{$"{group}: {title}",$"ID: {row.Id??"not supplied"}; source index: {row.SourceIndex}",$"Severity: {severity}; confidence: {confidence}; basis: {basis}"};
        // Explicit scalar allowlist: no raw JSON, secret value, match or evidence_text.
        foreach(string key in new[]{"name","kind","method","path","route","exposure","category","auth","ecosystem","version","dev","vuln_id","package","summary","title","status","reason","analyzer","source_analyzer","sink_kind","route_method","route_path","route_file","sink_file","sink_line","file","line","resolution","metadata_status"})
            if(Scalar(row.Source,key) is string value)lines.Add($"{key}: {value}");
        lines.Add("Unlisted or missing evidence remains unknown; no associations or scores inferred by UI.");
        string? file=row.File??Text(row.Source,"sink_file");
        int? line=row.Line;
        if(line==null&&row.Source.TryGetProperty("sink_line",out var sinkLine)&&sinkLine.ValueKind==JsonValueKind.Number&&sinkLine.TryGetInt32(out int suppliedLine))line=suppliedLine;
        return new(group,row.SourceIndex,row.Id,title,severity,confidence,basis,file,line,string.Join("\n",lines));
    }
    private static string? Text(JsonElement row,string key)=>row.TryGetProperty(key,out var value)&&value.ValueKind==JsonValueKind.String?value.GetString():null;
    private static string? Scalar(JsonElement row,string key)=>row.TryGetProperty(key,out var value)&&value.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False?value.ToString():null;
}
