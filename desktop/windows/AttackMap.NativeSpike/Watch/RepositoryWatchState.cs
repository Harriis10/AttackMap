namespace AttackMap.NativeSpike;

public sealed record RepositoryWatchRequest(string RepositoryRoot,long Epoch,bool FullRescan,bool EventsUncertain);

/// <summary>Single-slot, explicit-clock policy. Caller serializes access.</summary>
public sealed class RepositoryWatchState
{
    private readonly TimeSpan debounce;
    private DateTimeOffset due;
    private bool dirty;
    private long sequence,uncertaintySequence,scanSequence;
    public string Root {get;}
    public long Epoch {get;}
    public bool Enabled {get;private set;}=true;
    public bool ScanRunning {get;private set;}
    public bool EventsUncertain {get;private set;}
    public bool Pending=>dirty;
    public RepositoryWatchState(string root,long epoch,TimeSpan debounce)
    {if(debounce<TimeSpan.Zero)throw new ArgumentOutOfRangeException(nameof(debounce));Root=root;Epoch=epoch;this.debounce=debounce;}
    public void Changed(DateTimeOffset now,bool uncertain=false)
    {if(!Enabled)return;dirty=true;due=now+debounce;sequence++;if(uncertain){EventsUncertain=true;uncertaintySequence=sequence;}}
    public RepositoryWatchRequest? TakeDue(DateTimeOffset now)
    {
        if(!Enabled||ScanRunning||!dirty||now<due)return null;
        dirty=false;ScanRunning=true;scanSequence=sequence;
        return new(Root,Epoch,true,EventsUncertain);
    }
    public void SetScanRunning(bool value){if(Enabled){if(value&&!ScanRunning)scanSequence=sequence;ScanRunning=value;}}
    // Uncertainty remains visible until the host explicitly confirms a successful full scan.
    public void Complete(bool successfulFullScan=false)
    {ScanRunning=false;if(successfulFullScan&&uncertaintySequence<=scanSequence)EventsUncertain=false;}
    public void Stop(){Enabled=false;dirty=false;ScanRunning=false;}
}
