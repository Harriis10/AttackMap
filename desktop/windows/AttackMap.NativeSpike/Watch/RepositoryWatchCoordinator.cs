namespace AttackMap.NativeSpike;

/// <summary>Owns only filesystem subscription/timer. The host owns scan processes and UI dispatch.</summary>
public sealed class RepositoryWatchCoordinator : IDisposable
{
    // srcpaths.py SKIP_DIRS: relative directory names, never absolute ancestor names.
    private static readonly HashSet<string> Skipped=new(StringComparer.Ordinal)
    {"node_modules",".git",".attackmap",".attackmap-gui",".venv","venv","__pycache__","dist","build",".next",".turbo","out","target",".tox"};
    private readonly object gate=new();
    private FileSystemWatcher? watcher;
    private Timer? timer;
    private RepositoryWatchState? state;
    private string[] outputs=Array.Empty<string>();
    private long epoch;
    private bool disposed;
    public event Action<RepositoryWatchRequest>? ScanRequested;
    public event Action<string>? NoticeChanged;
    public string Notice {get;private set;}="Watch is off. Enable it explicitly for one repository.";
    public bool Enabled {get{lock(gate)return state?.Enabled==true;}}
    public bool Pending {get{lock(gate)return state?.Pending==true;}}
    public long Epoch {get{lock(gate)return epoch;}}

    public bool Start(string repositoryRoot,IEnumerable<string>? ownedOutputRoots=null,TimeSpan? debounce=null,bool scanRunning=false)
    {
        Stop();
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed,this);
            try
            {
                string root=Path.TrimEndingDirectorySeparator(Path.GetFullPath(repositoryRoot));
                if(!OperatingSystem.IsWindows()||root.StartsWith("\\\\",StringComparison.Ordinal)||!Directory.Exists(root))
                    throw new IOException("Watch requires an available local Windows repository; remote/unsupported filesystems require manual rescans.");
                var info=new DirectoryInfo(root);
                for(DirectoryInfo? current=info;current!=null;current=current.Parent)
                    if((current.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Redirected repository paths are not supported by native watch.");
                outputs=(ownedOutputRoots??Array.Empty<string>()).Select(p=>Path.TrimEndingDirectorySeparator(Path.GetFullPath(p))).ToArray();
                if(outputs.Any(p=>Within(p,root)))throw new IOException("Watch output exclusions cannot contain the entire repository.");
                state=new(root,++epoch,debounce??TimeSpan.FromMilliseconds(750));
                state.SetScanRunning(scanRunning);
                watcher=new FileSystemWatcher(root){IncludeSubdirectories=true,NotifyFilter=NotifyFilters.FileName|NotifyFilters.DirectoryName|NotifyFilters.LastWrite|NotifyFilters.Size,InternalBufferSize=32768};
                long captured=epoch;
                watcher.Changed+=(_,e)=>Changed(captured,e.FullPath);
                watcher.Created+=(_,e)=>Changed(captured,e.FullPath);
                watcher.Deleted+=(_,e)=>Changed(captured,e.FullPath);
                watcher.Renamed+=(_,e)=>{Changed(captured,e.OldFullPath);Changed(captured,e.FullPath);};
                watcher.Error+=(_,e)=>ReportError(captured,e.GetException());
                watcher.EnableRaisingEvents=true;
                timer=new Timer(_=>Tick(captured),null,100,100);
                Notice="Watching one repository. Changes request a full scan after debounce; watch never starts a process itself.";
                return true;
            }
            catch(Exception error)when(error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                StopLocked();Notice=$"Watch unavailable: {error.Message} Changes require manual rescans.";return false;
            }
        }
    }

    public bool IsCurrent(RepositoryWatchRequest request)
    {lock(gate)return state?.Enabled==true&&request.Epoch==epoch&&request.RepositoryRoot==state.Root;}
    public void SetScanRunning(bool running){lock(gate)state?.SetScanRunning(running);}
    public void Requeue(RepositoryWatchRequest request)
    {
        lock(gate)
        {
            if(state?.Enabled!=true||request.Epoch!=epoch||request.RepositoryRoot!=state.Root)return;
            state.Complete();
            state.Changed(DateTimeOffset.UtcNow,request.EventsUncertain);
        }
    }
    public void ScanCompleted(bool successfulFullScan=false){lock(gate)state?.Complete(successfulFullScan);}
    public void ScanCompleted(long expectedEpoch,bool successfulFullScan=false){lock(gate){if(expectedEpoch==epoch)state?.Complete(successfulFullScan);}}
    public void Stop(){lock(gate){StopLocked();Notice="Watch is off. Pending callbacks and changes were discarded.";}}
    private void StopLocked()
    {epoch++;state?.Stop();state=null;timer?.Dispose();timer=null;watcher?.Dispose();watcher=null;outputs=Array.Empty<string>();}
    private void Changed(long captured,string path)
    {
        lock(gate)
        {
            if(captured!=epoch||state?.Enabled!=true)return;
            try{if(!ShouldIgnore(state.Root,path,outputs))state.Changed(DateTimeOffset.UtcNow);}
            catch(Exception error)when(error is IOException or UnauthorizedAccessException or ArgumentException)
            {MarkUncertainLocked($"Watch exclusion check failed: {error.Message}");}
        }
    }
    private void ReportError(long captured,Exception? error)
    {
        string? notice=null;
        lock(gate){if(captured!=epoch||state?.Enabled!=true)return;MarkUncertainLocked($"Filesystem events may be missing ({error?.GetType().Name??"watch error"}); full rescan requested. If errors persist, disable watch and rescan manually.");notice=Notice;}
        NoticeChanged?.Invoke(notice);
    }
    private void MarkUncertainLocked(string notice){Notice=notice;state?.Changed(DateTimeOffset.UtcNow,true);}
    private void Tick(long captured)
    {
        RepositoryWatchRequest? request;
        lock(gate){if(captured!=epoch)return;request=state?.TakeDue(DateTimeOffset.UtcNow);}
        if(request==null)return;
        try
        {
            if(ScanRequested is { } handler)handler(request);
            else {lock(gate){if(captured==epoch){state?.Complete();MarkUncertainLocked("Watch scan handler unavailable; full rescan remains pending.");}}}
        }
        catch(Exception error)
        {lock(gate){if(captured==epoch){state?.Complete();MarkUncertainLocked($"Watch scan dispatch failed ({error.GetType().Name}); full rescan remains pending.");}}}
    }
    public static bool ShouldIgnore(string root,string path,IEnumerable<string> ownedOutputRoots)
    {
        root=Path.GetFullPath(root);path=Path.GetFullPath(path);
        if(!Within(root,path))return true;
        string relative=Path.GetRelativePath(root,path);
        var parts=relative.Split(new[]{Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar},StringSplitOptions.RemoveEmptyEntries);
        // A source file whose basename is "build" remains input. Deleted directory
        // names may cause one conservative extra scan because their type is unknown.
        if(parts.SkipLast(1).Any(Skipped.Contains)||(Directory.Exists(path)&&parts.Length>0&&Skipped.Contains(parts[^1]))||ownedOutputRoots.Any(output=>Within(Path.GetFullPath(output),path)))return true;
        if(Path.GetFileName(path)==".attackmap-output")return true;
        // Match engine legacy marker exclusion; modern manifested directories may contain user sources.
        for(string? parent=Directory.Exists(path)?path:Path.GetDirectoryName(path);parent!=null&&Within(root,parent);parent=Path.GetDirectoryName(parent))
        {
            string marker=Path.Combine(parent,".attackmap-output");
            if(File.Exists(marker)&&(File.GetAttributes(marker)&FileAttributes.ReparsePoint)==0&&!File.Exists(Path.Combine(parent,"artifact-manifest.json")))return true;
        }
        return false;
    }
    private static bool Within(string root,string path)=>string.Equals(Path.TrimEndingDirectorySeparator(root),Path.TrimEndingDirectorySeparator(path),StringComparison.OrdinalIgnoreCase)||path.StartsWith(Path.TrimEndingDirectorySeparator(root)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase);
    public void Dispose(){lock(gate){if(disposed)return;StopLocked();disposed=true;Notice="Watch disposed.";}}
}
