namespace AttackMap.NativeSpike;

public sealed record RunIdentity(string RunId, string Repository, long Generation, DateTimeOffset RequestedAt);
public sealed record DisplayedReport(string Repository, string RunLabel, string TimestampLabel, string Coverage);
public sealed class RunPresentation
{
    public string? SelectedRepository { get; private set; }
    public RunIdentity? ActiveRun { get; private set; }
    public DisplayedReport? Displayed { get; private set; }
    public bool PreviousResult { get; private set; }
    public string Phase { get; private set; } = "Idle";
    public void SelectRepository(string? path)
    {
        SelectedRepository = path;
        if (Displayed != null && !string.Equals(Displayed.Repository, path, StringComparison.OrdinalIgnoreCase)) PreviousResult = true;
    }
    public void Begin(RunIdentity run)
    {
        ActiveRun = run;
        SelectedRepository ??= run.Repository;
        PreviousResult = Displayed != null;
        Phase = "Starting; artifacts pending";
    }
    public void Update(string phase) => Phase = phase;
    public void Publish(DisplayedReport report)
    {
        Displayed = report;
        PreviousResult = ActiveRun != null && report.RunLabel != ActiveRun.RunId;
    }
    public void End(string phase) { Phase = phase; ActiveRun = null; }
    public string Summary => $"Selected repository: {SelectedRepository ?? "none"}\n" +
        (ActiveRun == null ? $"Run state: {Phase}\n" : $"Active run: {ActiveRun.RunId} / generation {ActiveRun.Generation}\nActive repository: {ActiveRun.Repository}\nRequested at (client UTC): {ActiveRun.RequestedAt.UtcDateTime:O}\n{Phase}\n") +
        (Displayed == null ? "Displayed report: none" : $"{(PreviousResult ? "PREVIOUS VALID REPORT" : "Displayed report")}: {Displayed.RunLabel}\nReport repository: {Displayed.Repository}\n{Displayed.TimestampLabel}");
    public string Coverage => Displayed?.Coverage ?? "No report coverage available.";
}
