namespace AttackMap.NativeSpike;

public sealed record ScanActivity(TimeSpan Elapsed, string State, string Stage);

/// <summary>Selected-run presentation only. Time input must be monotonic elapsed time, not wall clock.</summary>
public sealed class ScanProgressModel
{
    private string run = "", repository = "";
    private long generation, revision = -1;
    private TimeSpan lastTime, firstTime;
    private long firstCompleted;
    private int observations;
    private readonly List<ScanActivity> activity = new();
    public IReadOnlyList<ScanActivity> Activity => activity.AsReadOnly();
    public int EarlierActivityCount { get; private set; }
    public string State { get; private set; } = "idle";
    public string Stage { get; private set; } = "";
    public long? Completed { get; private set; }
    public long? Total { get; private set; }
    public bool Terminal { get; private set; }
    public bool Indeterminate => !Terminal && (!Total.HasValue || Total <= 0 || !Completed.HasValue);
    public double? Percent => Total > 0 && Completed.HasValue ? 100.0 * Completed.Value / Total.Value : null;
    public TimeSpan? EstimatedRemaining { get; private set; }
    public string EtaText => EstimatedRemaining is TimeSpan eta ? $"Estimated remaining: {Math.Ceiling(eta.TotalSeconds):0} seconds (current stage only)" : "Estimated remaining: unavailable";
    public void Select(string runId, string repositoryId, long selectedGeneration)
    {
        if (string.IsNullOrWhiteSpace(runId) || string.IsNullOrWhiteSpace(repositoryId) || selectedGeneration < 1) throw new ArgumentException("Selected run identity required.");
        run = runId; repository = repositoryId; generation = selectedGeneration; revision = -1;
        activity.Clear(); EarlierActivityCount = 0;
        State = "queued"; Stage = ""; Completed = Total = null; Terminal = false; ResetEstimate();
    }
    public void ClearSelection() { run = repository = ""; generation = 0; revision = -1; State = "idle"; Stage = ""; Completed = Total = null; Terminal = false; activity.Clear(); EarlierActivityCount = 0; ResetEstimate(); }
    public void RequestCancel() { if (!Terminal && State != "idle") { State = "cancelling"; ResetEstimate(); } }
    public bool Accept(EngineProgressSnapshot value, TimeSpan elapsed)
    {
        if (value.RunId != run || value.Repository != repository || value.Generation != generation || value.Revision <= revision || Terminal || elapsed < TimeSpan.Zero) return false;
        if (value.Terminal ? value.State is not ("completed" or "failed" or "cancelled") : value.State is not ("queued" or "running" or "cancelling")) return false;
        if (!value.Terminal && ((State == "cancelling" && value.State != "cancelling") || (State == "running" && value.State == "queued"))) return false;
        if (value.Completed < 0 || value.Total < 0 || (value.Total.HasValue && (!value.Completed.HasValue || value.Completed > value.Total))) return false;
        bool sameStage = value.Stage == Stage && value.Total == Total;
        if (sameStage && value.Completed.HasValue && Completed.HasValue && value.Completed < Completed) return false;
        if (!sameStage || value.Terminal || value.State != "running" || value.Total is null or 0 || !value.Completed.HasValue || (observations > 0 && elapsed <= lastTime)) ResetEstimate();
        if (!value.Terminal && value.State == "running" && value.Total > 0 && value.Completed.HasValue)
        {
            if (observations == 0) { firstTime = elapsed; firstCompleted = value.Completed.Value; observations = 1; }
            else if (value.Completed > Completed) observations++;
            lastTime = elapsed;
            double seconds = (elapsed - firstTime).TotalSeconds;
            long delta = value.Completed.Value - firstCompleted;
            if (observations >= 3 && seconds >= 2 && delta > 0)
            {
                double remaining = seconds * (value.Total.Value - value.Completed.Value) / delta;
                EstimatedRemaining = remaining is >= 0 and <= 604800 ? TimeSpan.FromSeconds(remaining) : null;
            }
        }
        if (activity.Count == 0 || value.State != activity[^1].State || value.Stage != activity[^1].Stage)
        {
            if (activity.Count == 200) { activity.RemoveAt(0); EarlierActivityCount++; }
            activity.Add(new(elapsed, value.State, value.Stage));
        }
        revision = value.Revision; State = value.State; Stage = value.Stage; Completed = value.Completed; Total = value.Total; Terminal = value.Terminal;
        return true;
    }
    private void ResetEstimate() { observations = 0; EstimatedRemaining = null; lastTime = firstTime = TimeSpan.Zero; firstCompleted = 0; }
}
