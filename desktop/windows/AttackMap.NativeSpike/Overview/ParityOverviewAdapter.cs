using System.Security.Cryptography;
using System.Text.Json;
namespace AttackMap.NativeSpike;

public sealed record OverviewLink(string Kind,string Identity,string Generation,string ReportHash,int? Line=null);
public sealed record OverviewEntry(int SourceIndex,string? Id,string Title,string Detail,OverviewLink? Link);
public sealed record OverviewList(SectionAvailability Availability,int? SuppliedCount,IReadOnlyList<OverviewEntry> Items,string Notice);
public sealed record OverviewCount(string Name,int? Value,SectionAvailability Availability);
public sealed record ParityOverview(string Repository,string ReadHash,string? Generation,IReadOnlyList<OverviewCount> Counts,OverviewList Risks,OverviewList Paths,OverviewList Actions,OverviewList Strengths,string Coverage)
{
    public bool Allows(OverviewLink link,string? displayedGeneration,string displayedHash) => Generation!=null&&link.Generation==Generation&&displayedGeneration==Generation&&link.ReportHash==ReadHash&&displayedHash==ReadHash
        &&Risks.Items.Concat(Paths.Items).Concat(Actions.Items).Concat(Strengths.Items).Any(item=>item.Link==link);
}
/// <summary>Bounded WP011 preparation; same read bytes feed WP007 and structured review.</summary>
public static class ParityOverviewAdapter
{
    public static async Task<ParityOverview> Load(string path,string? expectedHash=null,string? generation=null)
    {
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(stream.Length>ReportSectionAdapter.MaxBytes)throw new InvalidDataException("Overview report exceeds preview limit.");
        byte[] bytes=new byte[(int)stream.Length];await stream.ReadExactlyAsync(bytes);
        if(await stream.ReadAsync(new byte[1])!=0)throw new InvalidDataException("Report changed while reading.");
        string hash=Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if(expectedHash!=null&&!string.Equals(expectedHash,hash,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Overview report hash changed.");
        using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=64});
        return Read(document.RootElement,ReportSectionAdapter.Read(document.RootElement,hash,generation));
    }
    public static ParityOverview Read(JsonElement root,ReportSections report)
    {
        var counts=new List<OverviewCount>();
        void Count<T>(string name,ReportSection<T> section)=>counts.Add(new(name,section.SuppliedCount,section.Availability));
        Count("Ranked risk records",report.Exploitability);Count("Attack paths",report.Paths);Count("Attack surface",report.Surface);Count("Dependencies",report.Dependencies);Count("CVE records",report.Vulnerabilities);Count("Secret hints",report.Secrets);
        OverviewLink? Link(string kind,string? id)=>id!=null&&report.GenerationId!=null?new(kind,id,report.GenerationId,report.ReadHash):null;
        var risks=new OverviewList(report.Exploitability.Availability,report.Exploitability.SuppliedCount,report.Exploitability.Rows.Take(32).Select(r=>new OverviewEntry(r.Evidence.SourceIndex,r.Evidence.Id,r.Subject??"Unnamed supplied risk",$"Core score: {r.Score?.ToString(System.Globalization.CultureInfo.InvariantCulture)??"unknown"}; tier: {r.Tier??"unknown"}; basis: {r.Evidence.EvidenceBasis??"unknown"}",Link("finding",Text(r.Evidence.Source,"finding_id")))).ToArray(),report.Exploitability.Notice+" Overview shows first 32 projected rows at most; source total retained.");
        var paths=new OverviewList(report.Paths.Availability,report.Paths.SuppliedCount,report.Paths.Rows.Take(32).Select(r=>new OverviewEntry(r.Evidence.SourceIndex,r.Evidence.Id,r.Evidence.Name??"Unnamed supplied path",$"Impact: {r.Impact??"unknown"}; basis: {r.Evidence.EvidenceBasis??"unknown"}",Link("path",r.Evidence.Id))).ToArray(),report.Paths.Notice+" Overview shows first 32 projected rows at most; source total retained.");
        JsonElement review=root.TryGetProperty("defensive_review_json",out var supplied)?supplied:default;
        if(report.Exploitability.Rows.Count>32)risks=risks with{Availability=SectionAvailability.Partial};
        if(report.Paths.Rows.Count>32)paths=paths with{Availability=SectionAvailability.Partial};
        OverviewList ReviewList(string name,string titleField)
        {
            if(review.ValueKind is not (JsonValueKind.Object or JsonValueKind.Undefined))return new(SectionAvailability.Malformed,null,Array.Empty<OverviewEntry>(),$"{name}: structured review malformed; completeness unknown.");
            if(review.ValueKind==JsonValueKind.Undefined||!review.TryGetProperty(name,out var array))return new(SectionAvailability.Missing,null,Array.Empty<OverviewEntry>(),$"{name}: unavailable; not inferred from legacy prose.");
            if(array.ValueKind!=JsonValueKind.Array)return new(SectionAvailability.Malformed,null,Array.Empty<OverviewEntry>(),$"{name}: malformed; completeness unknown.");
            var rows=new List<OverviewEntry>();int index=0,malformed=0;
            foreach(var row in array.EnumerateArray().Take(256))
            {
                if(row.ValueKind!=JsonValueKind.Object){malformed++;index++;continue;}
                string? finding=Text(row,"finding_id");string? path=Text(row,"path_id");string? inventory=Text(row,"inventory_id");
                OverviewLink? link=finding!=null?Link("finding",finding):path!=null?Link("path",path):inventory!=null?Link("inventory",inventory):null;
                rows.Add(new(index,Text(row,"id"),Text(row,titleField)??"Unnamed supplied record",$"Priority: {Scalar(row,"priority")??"unknown"}; basis: {Scalar(row,"evidence_basis")??"unknown"}; confidence: {Scalar(row,"confidence")??"unknown"}",link));index++;
            }
            bool partial=malformed>0||array.GetArrayLength()>256;
            return new(partial?SectionAvailability.Partial:SectionAvailability.Present,array.GetArrayLength(),rows.AsReadOnly(),$"{name}: {array.GetArrayLength()} supplied / {rows.Count} displayed; malformed: {malformed}; truncated: {array.GetArrayLength()>256}. Core order retained.");
        }
        var coverage=new List<string>{report.Notice,$"Generation: {report.GenerationId??"unknown (legacy import)"}. Coverage completeness: unknown; absent fields never become zero."};
        if(report.Limitations is JsonElement limits&&limits.ValueKind==JsonValueKind.Array)
        {
            coverage.Add($"Scan limitations supplied: {limits.GetArrayLength()}.");
            coverage.AddRange(limits.EnumerateArray().Where(v=>v.ValueKind==JsonValueKind.String).Select(v=>v.GetString()!));
        }
        if(report.ResourceLimitReporting is JsonElement reporting)coverage.Add($"Resource-limit reporting: {reporting}");
        if(report.ResourceLimits is JsonElement events&&events.ValueKind==JsonValueKind.Array&&events.GetArrayLength()>0)coverage.Add($"PARTIAL: {events.GetArrayLength()} resource-limit events supplied.");
        coverage.Add(report.AnalyzerErrors.Notice);coverage.Add("CVE lookup state unknown; empty records do not establish lookup execution. Secret values/evidence are not projected. Static risks do not establish compromise.");
        return new(report.Repository,report.ReadHash,report.GenerationId,counts.AsReadOnly(),risks,paths,ReviewList("recommendations","action"),ReviewList("strengths","statement"),string.Join("\n",coverage));
    }
    private static string? Text(JsonElement row,string key)=>row.TryGetProperty(key,out var value)&&value.ValueKind==JsonValueKind.String?value.GetString():null;
    private static string? Scalar(JsonElement row,string key)=>row.TryGetProperty(key,out var value)&&value.ValueKind is JsonValueKind.String or JsonValueKind.Number?value.ToString():null;
}
