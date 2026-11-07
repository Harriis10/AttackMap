namespace AttackMap.NativeSpike;

public sealed record FleetRepositoryWatchRequest(long Epoch, long RequestId,
    IReadOnlyList<string> RepositoryRoots, IReadOnlyList<string> ChangedRepositoryRoots,
    bool FullRescan, bool EventsUncertain);
public sealed record FleetWatchLimitation(string RepositoryRoot, string Notice);

/// <summary>Bounded opt-in aggregation of WP020 watchers; the host owns fleet execution and UI dispatch.</summary>
public sealed class FleetRepositoryWatchCoordinator : IDisposable
{
    private readonly object gate = new();
    private readonly Dictionary<string, RepositoryWatchCoordinator> watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> limitations = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> pending = new(StringComparer.OrdinalIgnoreCase);
    private string[] roots = [];
    private Timer? timer;
    private TimeSpan debounce;
    private DateTimeOffset due;
    private FleetRepositoryWatchRequest? active;
    private long epoch, requestId;
    private bool running, uncertain, disposed;
    private string notice = "Fleet watch is off. Enable explicitly for the selected repository set.";
    public event Action<FleetRepositoryWatchRequest>? ScanRequested;
    public event Action<string>? NoticeChanged;
    public bool Enabled { get { lock (gate) return watchers.Count > 0; } }
    public long Epoch { get { lock (gate) return epoch; } }
    public bool Pending { get { lock (gate) return pending.Count > 0 || watchers.Values.Any(w => w.Pending); } }
    public int PendingRepositoryCount { get { lock (gate) return watchers.Count(pair => pending.Contains(pair.Key) || pair.Value.Pending); } }
    public IReadOnlyList<string> WatchedRoots { get { lock (gate) return watchers.Keys.ToArray(); } }
    public IReadOnlyList<FleetWatchLimitation> Limitations { get { lock (gate) return limitations.Select(pair => new FleetWatchLimitation(pair.Key, pair.Value)).ToArray(); } }
    public string Notice { get { lock (gate) return notice; } }

    public bool Start(IEnumerable<string> repositoryRoots, IEnumerable<string>? ownedOutputRoots = null,
        TimeSpan? debounce = null, bool fleetRunning = false)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            StopLocked();
            try
            {
                var selected = repositoryRoots.Take(17).ToArray();
                if (selected.Length is < 2 or > 16 || selected.Any(string.IsNullOrWhiteSpace))
                    throw new ArgumentException("Fleet watch requires 2–16 explicit local repository roots.");
                if (selected.Any(p => !Path.IsPathFullyQualified(p)))
                    throw new ArgumentException("Fleet watch requires absolute repository roots.");
                roots = selected.Select(p => Path.TrimEndingDirectorySeparator(Path.GetFullPath(p))).ToArray();
                if (roots.Distinct(StringComparer.OrdinalIgnoreCase).Count() != roots.Length)
                    throw new ArgumentException("Fleet watch requires unique repository roots.");
                this.debounce = debounce ?? TimeSpan.FromMilliseconds(750);
                if (this.debounce < TimeSpan.Zero || this.debounce > TimeSpan.FromMinutes(1))
                    throw new ArgumentException("Choose a fleet watch debounce between zero and one minute.");
                var outputs = (ownedOutputRoots ?? []).ToArray();
                running = fleetRunning;
                long captured = epoch;
                foreach (string root in roots)
                {
                    var watcher = new RepositoryWatchCoordinator();
                    watcher.ScanRequested += request => Changed(captured, root, watcher, request);
                    watcher.NoticeChanged += message => ChildNotice(captured, root, message);
                    if (watcher.Start(root, outputs, this.debounce, fleetRunning)) watchers.Add(root, watcher);
                    else { limitations[root] = watcher.Notice; watcher.Dispose(); }
                }
                notice = $"Watching {watchers.Count} of {roots.Length} selected fleet roots. Changes request one full fleet rescan; no process starts here."
                    + (limitations.Count > 0 ? " Some roots cannot be watched; inspect limitations and rescan manually." : "");
                if (watchers.Count > 0) timer = new Timer(_ => Tick(captured), null, 100, 100);
                return watchers.Count > 0;
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                StopLocked(); notice = $"Fleet watch unavailable: {error.Message} Use manual fleet rescans.";
                return false;
            }
        }
    }

    public bool IsCurrent(FleetRepositoryWatchRequest request)
    { lock (gate) return watchers.Count > 0 && request.Epoch == epoch && active?.RequestId == request.RequestId; }

    public void SetFleetRunning(bool value)
    {
        lock (gate)
        {
            running = value;
            foreach (var watcher in watchers.Values) watcher.SetScanRunning(value);
            if (!value && pending.Count > 0) due = DateTimeOffset.UtcNow + debounce;
        }
    }

    public void FleetCompleted(long expectedEpoch, bool successfulFullScan = false)
    {
        lock (gate)
        {
            if (expectedEpoch != epoch || watchers.Count == 0) return;
            running = false; active = null;
            foreach (var watcher in watchers.Values) watcher.ScanCompleted(successfulFullScan);
            if (pending.Count > 0) due = DateTimeOffset.UtcNow + debounce;
        }
    }

    public bool FleetCompleted(FleetRepositoryWatchRequest request, bool successfulFullScan = false)
    {
        lock (gate)
        {
            if (request.Epoch != epoch || active?.RequestId != request.RequestId || watchers.Count == 0) return false;
            FleetCompleted(request.Epoch, successfulFullScan);
            return true;
        }
    }

    public void Requeue(FleetRepositoryWatchRequest request)
    {
        lock (gate)
        {
            if (request.Epoch != epoch || active?.RequestId != request.RequestId || watchers.Count == 0) return;
            foreach (string root in request.ChangedRepositoryRoots) pending.Add(root);
            uncertain |= request.EventsUncertain;
            active = null;
            // Preserve an independently running host action. A rejected UI
            // dispatch does not imply that the host has become idle.
            foreach (var watcher in watchers.Values) watcher.ScanCompleted();
            if (running) foreach (var watcher in watchers.Values) watcher.SetScanRunning(true);
            due = DateTimeOffset.UtcNow + debounce;
        }
    }

    private void Changed(long captured, string root, RepositoryWatchCoordinator watcher, RepositoryWatchRequest request)
    {
        lock (gate)
        {
            if (captured != epoch || !watchers.TryGetValue(root, out var current) || current != watcher || !watcher.IsCurrent(request)) return;
            pending.Add(root); uncertain |= request.EventsUncertain;
            due = DateTimeOffset.UtcNow + debounce;
        }
    }

    private void ChildNotice(long captured, string root, string message)
    {
        string update;
        lock (gate)
        {
            if (captured != epoch || !watchers.ContainsKey(root)) return;
            limitations[root] = message;
            update = notice = "Fleet filesystem events may be incomplete; full rescan requested. Inspect root limitations.";
        }
        NoticeChanged?.Invoke(update);
    }

    private void Tick(long captured)
    {
        FleetRepositoryWatchRequest request;
        lock (gate)
        {
            if (captured != epoch || running || active != null || pending.Count == 0 || DateTimeOffset.UtcNow < due) return;
            request = new(epoch, ++requestId, Array.AsReadOnly(roots.ToArray()),
                Array.AsReadOnly(roots.Where(pending.Contains).ToArray()), true, uncertain);
            pending.Clear(); uncertain = false; active = request;
            foreach (var watcher in watchers.Values) watcher.SetScanRunning(true);
        }
        try
        {
            if (ScanRequested is { } handler) handler(request);
            else Requeue(request);
        }
        catch { Requeue(request); }
    }

    public void Stop()
    { lock (gate) { StopLocked(); notice = "Fleet watch is off. All subscriptions and pending changes were discarded."; } }
    private void StopLocked()
    {
        epoch++; timer?.Dispose(); timer = null;
        foreach (var watcher in watchers.Values) watcher.Dispose();
        watchers.Clear(); limitations.Clear(); pending.Clear(); roots = [];
        active = null; running = uncertain = false;
    }
    public void Dispose()
    { lock (gate) { if (disposed) return; StopLocked(); disposed = true; notice = "Fleet watch disposed."; } }
}
