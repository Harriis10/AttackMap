namespace AttackMap.NativeSpike.HistoryPrep;

public sealed record HistoryArtifact(string RepositoryId,string GenerationId,string ReportHash,string ReportPath);
public sealed record RetainedGeneration(HistoryArtifact Artifact,bool IsPinned,bool IsCurrent,string State,string PolicyOutcome)
{public string Label=>$"{Artifact.GenerationId} | {(IsCurrent?"current | ":"")}{(IsPinned?"pinned | ":"")}{State}; policy {PolicyOutcome}";}
public sealed record HistoryLoadTicket(long Epoch,HistoryArtifact Artifact);
public sealed record HistorySelectionTicket(long Epoch,string RepositoryId);
public sealed record HistoryCompareIntent(long Epoch,HistoryArtifact Baseline,HistoryArtifact Current);
public sealed record HistoryPinIntent(long Epoch,HistoryArtifact Artifact,bool Pin);
public enum NextBaselineMode{None,Previous,Custom}
public sealed record NextRunHistoryIntent(string RepositoryId,NextBaselineMode Mode,HistoryArtifact? Baseline,bool FailOnNewHigh);
public sealed record CoreDiffCategory(string Name,int? SuppliedCount,IReadOnlyList<string> FindingIds);
public static class HistoryIdentity
{
    public static bool ValidHash(string? value)=>value!=null&&value.Length==64&&value.All(Uri.IsHexDigit);
    public static bool Valid(HistoryArtifact? value)=>value!=null&&!string.IsNullOrWhiteSpace(value.RepositoryId)&&!string.IsNullOrWhiteSpace(value.GenerationId)&&ValidHash(value.ReportHash)&&!string.IsNullOrWhiteSpace(value.ReportPath)&&Path.IsPathFullyQualified(value.ReportPath)&&!value.ReportPath.Any(char.IsControl);
}
/// <summary>Read-only source identities and callback intents. No filesystem or comparison policy.</summary>
public sealed class HistoryComparisonModel
{
    private long epoch;
    private IReadOnlyList<RetainedGeneration> generations=Array.Empty<RetainedGeneration>();
    public RecentRepository? Repository{get;private set;}
    public bool RepositoryAvailable{get;private set;}
    public RetainedGeneration? Selected{get;private set;}
    public IReadOnlyList<RetainedGeneration> Generations=>generations.Where(g=>g.Artifact.RepositoryId==Repository?.RepositoryId).ToArray();
    public IReadOnlyList<CoreDiffCategory> Comparison{get;private set;}=Array.Empty<CoreDiffCategory>();
    public NextRunHistoryIntent? NextRun{get;private set;}
    public string Status{get;private set;}="Choose a repository; no scan starts automatically.";
    public void SelectRepository(RecentRepository repo,bool available)
    {Repository=repo;RepositoryAvailable=available;Selected=null;NextRun=null;Comparison=Array.Empty<CoreDiffCategory>();epoch++;Status=available?"Repository selected; no scan started.":"Repository unavailable. Recover by locating it; retained reports remain read-only and no scan starts.";}
    public void SetGenerations(IReadOnlyList<RetainedGeneration> source)
    {
        if(source.Any(g=>g==null||!HistoryIdentity.Valid(g.Artifact))||source.GroupBy(g=>(g.Artifact.RepositoryId,g.Artifact.GenerationId)).Any(g=>g.Count()!=1)
            ||source.Where(g=>g.IsCurrent).GroupBy(g=>g.Artifact.RepositoryId).Any(g=>g.Count()>1))throw new InvalidDataException("Malformed/ambiguous retained generation identities.");
        generations=source.ToArray();epoch++;Comparison=Array.Empty<CoreDiffCategory>();
        if(Selected!=null)Selected=Generations.FirstOrDefault(g=>g.Artifact==Selected.Artifact);
        Status="Core generation order/identity retained. Existing next-run baseline snapshot is not advanced automatically.";
    }
    public bool SelectGeneration(HistoryArtifact artifact)
    {var item=Generations.FirstOrDefault(g=>g.Artifact==artifact);if(item==null)return false;Selected=item;epoch++;Comparison=Array.Empty<CoreDiffCategory>();Status=item.State=="completed"&&item.PolicyOutcome=="failed"?"Completed analysis; policy failed. This is not execution failure.":item.Label;return true;}
    public HistoryLoadTicket? BeginLoad()=>Selected?.State=="completed"?new(epoch,Selected.Artifact):null;
    public HistorySelectionTicket? BeginCustomSelection()=>Repository==null?null:new(epoch,Repository.RepositoryId);
    public bool AcceptCustomSelection(HistorySelectionTicket ticket,HistoryArtifact artifact)
    {if(ticket.Epoch!=epoch||ticket.RepositoryId!=Repository?.RepositoryId||artifact.RepositoryId!=ticket.RepositoryId||!HistoryIdentity.Valid(artifact))return false;epoch++;Comparison=Array.Empty<CoreDiffCategory>();return true;}
    public bool AcceptLoad(HistoryLoadTicket ticket,string exactReadHash)=>ticket.Epoch==epoch&&Selected?.Artifact==ticket.Artifact&&exactReadHash==ticket.Artifact.ReportHash;
    public bool CanCompare(HistoryArtifact baseline)=>Selected?.State=="completed"&&HistoryIdentity.Valid(baseline)&&baseline.RepositoryId==Repository?.RepositoryId;
    public HistoryCompareIntent? Compare(HistoryArtifact baseline)
    {if(!CanCompare(baseline))return null;epoch++;Comparison=Array.Empty<CoreDiffCategory>();Status=$"Awaiting core comparison: baseline {baseline.GenerationId} / {baseline.ReportHash}; current {Selected!.Artifact.GenerationId} / {Selected.Artifact.ReportHash}.";return new(epoch,baseline,Selected.Artifact);}
    public bool AcceptComparison(HistoryCompareIntent request,IReadOnlyList<CoreDiffCategory> supplied)
    {if(request.Epoch!=epoch||Selected?.Artifact!=request.Current||request.Baseline.RepositoryId!=Repository?.RepositoryId||supplied.Any(c=>c==null||string.IsNullOrWhiteSpace(c.Name)||c.SuppliedCount<0||c.FindingIds==null||c.FindingIds.Any(string.IsNullOrWhiteSpace)))return false;Comparison=supplied.Select(c=>new CoreDiffCategory(c.Name,c.SuppliedCount,c.FindingIds.ToArray())).ToArray();Status="Exact core diff categories/counts/order supplied; no title, line or score recomputation.";return true;}
    public HistoryPinIntent? Pin(bool pin)=>Selected==null?null:new(epoch,Selected.Artifact,pin);
    public bool IsCurrent(HistoryPinIntent request)=>request.Epoch==epoch&&Selected?.Artifact==request.Artifact;
    public bool SetNextRun(NextBaselineMode mode,bool failOnNewHigh,HistoryArtifact? custom=null)
    {
        if(Repository==null)return false;
        HistoryArtifact? baseline=mode switch{NextBaselineMode.None=>null,NextBaselineMode.Previous=>Generations.SingleOrDefault(g=>g.IsCurrent&&g.State=="completed")?.Artifact,NextBaselineMode.Custom=>custom,_=>null};
        if(mode!=NextBaselineMode.None&&(baseline==null||!HistoryIdentity.Valid(baseline)||baseline.RepositoryId!=Repository.RepositoryId)){Status="Exact baseline unavailable; choose a verified baseline. No fallback selected.";return false;}
        NextRun=new(Repository.RepositoryId,mode,baseline,failOnNewHigh);Status="Next-run options intent only; no scan, comparison, pin or report mutation performed.";return true;
    }
    public IReadOnlyList<HistoryArtifact> RetentionCandidates()=>Generations.Where(g=>!g.IsPinned&&!g.IsCurrent&&g.Artifact!=NextRun?.Baseline&&g.Artifact!=Selected?.Artifact).Select(g=>g.Artifact).ToArray();
}
