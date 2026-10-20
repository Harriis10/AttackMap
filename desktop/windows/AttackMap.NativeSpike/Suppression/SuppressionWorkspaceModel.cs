using System.Text.Json;
namespace AttackMap.NativeSpike;

public sealed record SuppressedItem(int SourceIndex,string? Id,string Title,string Reason,string Origin,string Expiry)
{ public string Label=>$"{Title} | reason: {Reason}"; }
public sealed record SuppressionBaseline(string Path,string? Sha256);
public sealed record SuppressionIntent(string Operation,string FindingId,SuppressionBaseline Baseline,string Generation,string ReportHash,long ContextVersion,string? PreviewId,string? ReceiptId,bool NoSuppress);
public sealed class SuppressionWorkspaceModel
{
    private ReportSections report;
    private long version;
    private string? findingId,previewId,receiptId;
    private bool previewAllowed;
    public IReadOnlyList<SuppressedItem> Rows {get;private set;}=Array.Empty<SuppressedItem>();
    public SectionAvailability Availability=>report.Suppressed.Availability;
    public int? SuppliedCount=>report.Suppressed.SuppliedCount;
    public SuppressionBaseline? Baseline {get;private set;}
    public bool NoSuppress {get;set;}
    public bool Busy {get;private set;}
    public string Status {get;private set;}="No changes requested. Report remains the selected scan result.";
    public string Notice=>$"{report.Suppressed.Notice}\nGeneration: {report.GenerationId??"unknown"}. Explicit action finding ID: {findingId??"none selected"}. Baseline: {Baseline?.Path??"none selected"}; SHA-256: {Baseline?.Sha256??"missing/unverified"}. No-suppress next scan: {NoSuppress}.\n{Status}\nSuppression actions never recalculate this report; rescan to refresh results.";
    public bool CanPreview=>!Busy&&Baseline?.Sha256!=null&&findingId!=null&&report.GenerationId!=null&&ValidHash(report.ReadHash);
    public bool CanApply=>CanPreview&&previewAllowed&&previewId!=null&&receiptId==null;
    public bool CanUndo=>CanPreview&&receiptId!=null;
    public SuppressionWorkspaceModel(ReportSections report){this.report=report;Project();}
    private void Project()=>Rows=report.Suppressed.Rows.Select(row=>new SuppressedItem(row.Evidence.SourceIndex,row.Evidence.Id,row.Title??"Unnamed supplied suppressed record",row.Reason??"unknown",Text(row.Evidence.Source,"origin")??Origins(row.SuppressedBy),row.Expiry??Text(row.Evidence.Source,"expires")??"unknown")).ToArray();
    public long BeginBaselineSelection(){Invalidate();return version;}
    public bool CompleteBaselineSelection(long ticket,string path,string? sha256)
    {
        if(ticket!=version)return false;
        if(!SafePath(path)||sha256!=null&&!ValidHash(sha256)){Status="Baseline path/hash is invalid; choose a local absolute path without traversal or URL credentials.";return false;}
        Baseline=new(Path.GetFullPath(path),sha256?.ToLowerInvariant());Invalidate();
        Status=sha256==null?"Baseline missing or hash unverified; preview/apply blocked.":"Baseline identity supplied by host. New preview required; no file read or write performed.";return true;
    }
    public void ClearBaseline(){Baseline=null;Invalidate();Status="Explicit baseline cleared. No-suppress remains independent.";}
    public void SetFinding(string? id){if(findingId==id)return;findingId=string.IsNullOrWhiteSpace(id)?null:id;Invalidate();Status="Explicit action finding changed; new preview required. Retained row selection is read-only.";}
    public void SetReport(ReportSections next){report=next;Baseline=null;findingId=null;Invalidate();Project();Status="Report selection changed; baseline and preview invalidated.";}
    public SuppressionIntent? Request(string operation)
    {
        bool enabled=operation switch{"suppression_preview"=>CanPreview,"suppression_apply"=>CanApply,"suppression_undo"=>CanUndo,_=>false};
        if(!enabled){Status="Action blocked: select a verified baseline/finding/generation and obtain a current preview or receipt.";return null;}
        version++;Busy=true;return new(operation,findingId!,Baseline!,report.GenerationId!,report.ReadHash,version,previewId,receiptId,NoSuppress);
    }
    public bool AcceptPreview(SuppressionIntent request,SuppressionBaseline verifiedPlanBaseline,string opaquePreviewId,bool canApply)
    {
        if(request.Operation!="suppression_preview"||!Matches(request)||verifiedPlanBaseline!=Baseline||string.IsNullOrWhiteSpace(opaquePreviewId))return false;
        Busy=false;previewId=opaquePreviewId;previewAllowed=canApply;Status=canApply?"Host preview accepted for exact current context. No changes applied.":"Host preview cannot apply. Review existing suppression action detail.";return true;
    }
    public bool AcceptApplied(SuppressionIntent request,string opaqueReceiptId,string postApplyBaselineHash)
    {
        if(request.Operation!="suppression_apply"||!Matches(request)||request.PreviewId!=previewId||!ValidHash(postApplyBaselineHash)||string.IsNullOrWhiteSpace(opaqueReceiptId))return false;
        Baseline=Baseline! with{Sha256=postApplyBaselineHash.ToLowerInvariant()};Invalidate();receiptId=opaqueReceiptId;Status="Host reported apply completion; selected report is unchanged. Rescan required.";return true;
    }
    public bool AcceptUndone(SuppressionIntent request)
    {
        if(request.Operation!="suppression_undo"||!Matches(request)||request.ReceiptId!=receiptId)return false;
        Invalidate();Baseline=Baseline! with{Sha256=null};Status="Host reported undo completion. Baseline hash must be refreshed; selected report unchanged.";return true;
    }
    public void Reject(SuppressionIntent request){if(!Matches(request))return;Invalidate();Status="Host action failed or baseline changed. New baseline verification/preview required; report unchanged.";}
    private bool Matches(SuppressionIntent request)=>request.ContextVersion==version&&request.Generation==report.GenerationId&&request.ReportHash==report.ReadHash&&request.FindingId==findingId&&request.Baseline==Baseline;
    private void Invalidate(){version++;previewId=null;receiptId=null;previewAllowed=false;Busy=false;}
    private static bool ValidHash(string value)=>value.Length==64&&value.All(Uri.IsHexDigit);
    private static bool SafePath(string value)
    {
        if(string.IsNullOrWhiteSpace(value)||value.Any(char.IsControl)||value.StartsWith("\\\\")||value.StartsWith("//")||value.Contains("://"))return false;
        if(value.IndexOf(':',Math.Min(2,value.Length))>=0)return false;
        foreach(string part in value.Replace('\\','/').Split('/'))
        {
            if(part is "." or ".."||part.EndsWith(' ')||part.EndsWith('.'))return false;
            string stem=part.Split('.')[0].ToUpperInvariant();
            if(stem is "CON" or "PRN" or "AUX" or "NUL"||stem.Length==4&&(stem.StartsWith("COM")||stem.StartsWith("LPT"))&&stem[3] is >= '1' and <= '9')return false;
        }
        try{return Path.IsPathFullyQualified(value)&&Path.GetFullPath(value).Length>3;}catch(Exception error)when(error is ArgumentException or NotSupportedException or PathTooLongException){return false;}
    }
    private static string? Text(JsonElement row,string key)=>row.TryGetProperty(key,out var value)&&value.ValueKind==JsonValueKind.String?value.GetString():null;
    private static string Origins(JsonElement? source)=>source is JsonElement value&&value.ValueKind==JsonValueKind.Array?(value.GetArrayLength()==0?"none supplied (empty list)":string.Join("; ",value.EnumerateArray().Where(v=>v.ValueKind==JsonValueKind.String).Select(v=>v.GetString()))):"unknown";
}
