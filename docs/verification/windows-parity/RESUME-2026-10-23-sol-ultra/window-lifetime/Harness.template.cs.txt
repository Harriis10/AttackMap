using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
namespace LifetimeRegression;

// Deliberately no WinUI reference. Production bodies in ExtractedWindows.cs use
// these controlled asynchronous boundaries and instrumented stand-in controls.
public static class UiProbe
{
    public static int Reads, Writes, Publishes;
    public static void Read() => Interlocked.Increment(ref Reads);
    public static void Write() => Interlocked.Increment(ref Writes);
    public static void Reset() { Reads = 0; Writes = 0; Publishes = 0; }
    public static int Accesses => Reads + Writes;
}
public enum Visibility { Visible, Collapsed }
public class RoutedEventArgs { }
public class NavigationViewSelectionChangedEventArgs
{
    public object? SelectedItem { get; set; }
    public bool IsSettingsSelected { get; set; }
}
public class NavigationViewItem { public object? Content { get; set; } }
public class FakeControl
{
    string text = "";
    public string Text { get { UiProbe.Read(); return text; } set { UiProbe.Write(); text = value; } }
    public object? ItemsSource { set { UiProbe.Write(); } }
    public int SelectedIndex { set { UiProbe.Write(); } }
    public bool? IsChecked { get { UiProbe.Read(); return false; } }
    public Visibility Visibility { set { UiProbe.Write(); } }
    public string CurrentReportPath { set { UiProbe.Write(); } }
    public void SetContext(string _, JsonElement __, string ___) => UiProbe.Write();
}
public class NavigationView : FakeControl
{
    readonly List<object> items = [new NavigationViewItem { Content = "Overview" }, new NavigationViewItem { Content = "Findings" }];
    public List<object> MenuItems { get { UiProbe.Read(); return items; } }
    public object? SelectedItem { set { UiProbe.Write(); } }
    public bool IsBackEnabled { set { UiProbe.Write(); } }
}
public class ProviderControl : FakeControl
{
    public ProviderConfiguration ReadConfiguration() { UiProbe.Read(); return new(); }
}
public record ProviderConfiguration(bool EnableAi = false, string Provider = "local", string? Endpoint = null);
public record NativeScanOptions(ProviderConfiguration? Provider = null, bool Cve = false);
public record FixtureFinding(string Id);
public record StructureData;
public record Sections;
public record Overview;
public record DisplayedReport(string Repository, string RunLabel, string TimestampLabel, string Coverage);
public record RunIdentity(string RunId, string Repository, long Generation, DateTimeOffset RequestedAt);
public sealed class FakePresentation
{
    public void Publish(DisplayedReport _) => Interlocked.Increment(ref UiProbe.Publishes);
}
public sealed class FakeDisposable : IDisposable
{
    public int Calls;
    public void Dispose() => Calls++;
}
public sealed class FakeEngine
{
    public int Disconnects;
    public void Disconnect() => Disconnects++;
}
public class FrameworkElement
{
    public FakeXamlRoot XamlRoot { get { UiProbe.Read(); return new(); } }
}
public class FakeXamlRoot { public double RasterizationScale => 1; }
public class FakeAppWindow
{
    public object Presenter { get { UiProbe.Read(); return new Microsoft.UI.Windowing.OverlappedPresenter(); } }
    public (int Width, int Height) Size => (1200, 800);
    public (int X, int Y) Position => (0, 0);
}
public record WindowPlacement(double Width, double Height, int? Left, int? Top);

public interface IWindowScenario
{
    Task<bool> Load(string path);
    Task Fixture();
    void SendNavigation();
    void SendNetwork();
    void SendPlacement();
    void Close();
}
public class WindowFixture
{
    public bool ready = true;
    public long generation;
    public readonly CancellationTokenSource actionLifetime = new();
    public bool MiddleReady, MiddleCanceled;
    public long MiddleGeneration;
    public List<FixtureFinding> all = [];
    public List<JsonElement> findingRecords = [];
    public string? displayedReportPath;
    public string displayedRepository = "", displayedRun = "", displayedReadHash = "", reportLabel = "";
    public long findingRevision;
    public NativeScanOptions? activeScanOptions;
    public bool navigatingBack, inventoryView;
    public object? previousDestination;
    public Stack<object> navigationBack = new();
    public StructureData? structure;
    public ExportSelection? exportSelection;
    public Task parityViewBinding = Task.CompletedTask;
    public bool placementPersistenceEnabled = true;
    public WindowPlacement? lastPlacement;
    public object Content = new FrameworkElement();
    public FakeAppWindow AppWindow = new();
    public FakeDisposable keyboardBindings = new();
    public FakeEngine engine = new();
    public FakePresentation presentation = new();
    public NavigationView Navigation = new();
    public ProviderControl Provider = new();
    public FakeControl Status = new(), Suppression = new(), History = new(), ArtifactRows = new(), ArtifactText = new(),
        ArtifactStatus = new(), ReviewText = new(), OverviewText = new(), Search = new(), Findings = new(), Heading = new(),
        NetworkDisclosure = new(), CveOption = new(), FindingsPanel = new(), OverviewPanel = new(), ReportsPanel = new(),
        StructurePanel = new(), HistoryPanel = new(), ProviderPanel = new(), ScanOptionsPanel = new(), RiskPaths = new(),
        EvidenceInventory = new(), Diagrams = new(), Fleet = new(), SuppressionWorkspace = new();
    public void ResetAiReview() => UiProbe.Write();
    public void BindParityReport(Sections _, Overview __, ExportSelection ___) => UiProbe.Write();
    public void UpdateRunSummary() => UiProbe.Write();
    public void ShowMatches() => UiProbe.Write();
    public void ShowStructure() => UiProbe.Write();
    public Task LoadRetainedGenerations() { UiProbe.Write(); return Task.CompletedTask; }
    public void ObserveMiddleClosedSubscriber()
    {
        MiddleReady = ready; MiddleCanceled = actionLifetime.IsCancellationRequested; MiddleGeneration = generation;
    }
}
public record ReportData
{
    public List<FixtureFinding> Findings { get; init; } = [new("finding")];
    public List<JsonElement> FindingRecords { get; init; } = [];
    public string ReadHash => "readhash";
    public string Repository => "repository";
    public StructureData Structure => new();
    public string Review => "review";
    public string Overview => "overview";
    public string Coverage => "coverage";
}
public sealed record ExportSelection(string ReportPath)
{
    public string? RunId => "test-run";
    public bool Verified => true;
    public string Disclosure => "fixture";
    public static ExportSelection CaptureSavedGeneration(string path, string _, string __) => new(path);
    public static ExportSelection Capture(string path, string _, RunIdentity __) => new(path);
}
public enum Stage { Report, Timing, Sections, Overview }
public sealed class PendingRead
{
    public readonly TaskCompletionSource<ReportData> Report = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource<string> Timing = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource<Sections> Sections = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource<Overview> Overview = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly Stage? pending;
    public PendingRead(Stage? pending)
    {
        this.pending = pending;
        if (pending != Stage.Report) Report.SetResult(new());
        if (pending != Stage.Timing) Timing.SetResult("timing");
        if (pending != Stage.Sections) Sections.SetResult(new());
        if (pending != Stage.Overview) Overview.SetResult(new());
    }
    public void Release(Exception? error)
    {
        switch (pending)
        {
            case Stage.Report: if (error == null) Report.SetResult(new()); else Report.SetException(error); break;
            case Stage.Timing: if (error == null) Timing.SetResult("timing"); else Timing.SetException(error); break;
            case Stage.Sections: if (error == null) Sections.SetResult(new()); else Sections.SetException(error); break;
            case Stage.Overview: if (error == null) Overview.SetResult(new()); else Overview.SetException(error); break;
            default: throw new InvalidOperationException("No pending read");
        }
    }
}
public static class ReportAdapter
{
    public static readonly Dictionary<string, PendingRead> Plans = new();
    public static int Calls;
    public static Task<ReportData> Load(string path) { Calls++; return Plans[path].Report.Task; }
}
public static class ScanTiming
{
    public static Task<string> ReadLabel(ExportSelection selection) => ReportAdapter.Plans[selection.ReportPath].Timing.Task;
}
public static class ReportSectionAdapter
{
    public static Task<Sections> Load(string path, string _, string? __) => ReportAdapter.Plans[path].Sections.Task;
}
public static class ParityOverviewAdapter
{
    public static Task<Overview> Load(string path, string _, string? __) => ReportAdapter.Plans[path].Overview.Task;
}
// Shadows only the fixture-read boundary in the exact extracted LoadData body.
public static class File
{
    public static TaskCompletionSource<string> FixtureRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public static TaskCompletionSource<bool> FixtureEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public static Task<string> ReadAllTextAsync(string _)
    {
        FixtureEntered.TrySetResult(true);
        return FixtureRead.Task;
    }
    public static void Reset()
    {
        FixtureRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        FixtureEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
public static class Program
{
    static readonly List<object> cases = [];
    static int assertions;
    static int pathCounter;
    static void Check(bool value, string message)
    {
        assertions++;
        if (!value) throw new Exception(message);
    }
    static (IWindowScenario Scenario, WindowFixture State) Create(string variant)
    {
        WindowFixture state = variant switch { "Baseline" => new BaselineWindow(), "Core" => new CoreWindow(), _ => new OptionalWindow() };
        UiProbe.Reset(); ReportAdapter.Calls = 0; ReportAdapter.Plans.Clear();
        return ((IWindowScenario)state, state);
    }
    static string AddRead(PendingRead read)
    {
        string path = Path.GetFullPath($"controlled-report-{++pathCounter}.json");
        ReportAdapter.Plans.Add(path, read); return path;
    }
    static Exception ImportError(int index) => index switch
    {
        0 => new IOException("controlled IO fault"), 1 => new JsonException("controlled JSON fault"),
        2 => new UnauthorizedAccessException("controlled access fault"), 3 => new InvalidDataException("controlled data fault"),
        4 => new InvalidOperationException("controlled operation fault"), _ => new KeyNotFoundException("controlled key fault"),
    };
    static async Task Bounded(Task task) => await task.WaitAsync(TimeSpan.FromSeconds(5));
    public static async Task Main()
    {
        foreach (string variant in new[] { "Baseline", "Core", "Optional" })
        {
            bool fixedCore = variant != "Baseline", fixedOptional = variant == "Optional";
            foreach (Stage stage in Enum.GetValues<Stage>())
            {
                // Every exception type actually caught by the production importer.
                for (int errorIndex = 0; errorIndex < 6; errorIndex++)
                {
                    var (window, state) = Create(variant);
                    var read = new PendingRead(stage); string path = AddRead(read);
                    Task<bool> task = window.Load(path); Check(!task.IsCompleted, "Read must really be pending");
                    long requested = state.generation; window.Close(); UiProbe.Reset();
                    read.Release(ImportError(errorIndex)); await Bounded(task);
                    Check(!await task, "Closed import must return false");
                    Check(UiProbe.Writes == (fixedCore ? 0 : 1), "Late catch write regression");
                    Check(UiProbe.Publishes == 0, "Late catch cannot publish");
                    Check(state.engine.Disconnects == 1 && state.keyboardBindings.Calls == 1, "Normal cleanup exactly once");
                    Check(state.actionLifetime.IsCancellationRequested, "Lifetime canceled");
                    Check(!fixedCore || (!state.MiddleReady && state.MiddleCanceled && state.MiddleGeneration == requested + 1), "Invalidation precedes existing cleanup subscribers");
                    cases.Add(new { variant, name = "delayed-import-fault-after-close", stage, errorIndex, writes = UiProbe.Writes });
                }
                {
                    var (window, state) = Create(variant); var read = new PendingRead(stage);
                    Task<bool> task = window.Load(AddRead(read)); window.Close(); UiProbe.Reset();
                    read.Release(null); await Bounded(task);
                    Check(!await task && UiProbe.Accesses == 0 && UiProbe.Publishes == 0, "Late successful read cannot publish or touch controls");
                    cases.Add(new { variant, name = "delayed-import-success-after-close", stage });
                }
                {
                    var (window, _) = Create(variant); var read = new PendingRead(stage);
                    Task<bool> old = window.Load(AddRead(read));
                    Task<bool> current = window.Load(AddRead(new PendingRead(null))); await Bounded(current);
                    Check(await current, "Current generation must load"); UiProbe.Reset();
                    read.Release(new IOException("old generation")); await Bounded(old);
                    Check(!await old && UiProbe.Accesses == 0 && UiProbe.Publishes == 0, "Old generation failure cannot replace current UI");
                    cases.Add(new { variant, name = "superseded-import-failure", stage });
                }
            }
            {
                var (window, _) = Create(variant); Task<bool> task = window.Load(AddRead(new PendingRead(null))); await Bounded(task);
                Check(await task && UiProbe.Publishes == 1 && UiProbe.Writes > 0, "Open window still publishes a valid report");
                window.SendNavigation(); window.SendNetwork();
                cases.Add(new { variant, name = "normal-report-and-events" });
            }
            {
                var (window, state) = Create(variant); window.Close(); UiProbe.Reset();
                window.SendNavigation(); window.SendNetwork();
                Check(fixedCore ? UiProbe.Accesses == 0 : UiProbe.Writes > 0, "Queued navigation/network callback terminal guard");
                Check(state.ready == !fixedCore, "ready invalidates on close");
                cases.Add(new { variant, name = "queued-events-after-close", accesses = UiProbe.Accesses });
            }
            {
                var (window, state) = Create(variant); state.actionLifetime.Cancel(); UiProbe.Reset();
                window.SendNavigation(); window.SendNetwork();
                Check(fixedCore ? UiProbe.Accesses == 0 : UiProbe.Writes > 0, "Explicit lifetime cancellation guards events even before ready reset");
                cases.Add(new { variant, name = "queued-events-after-cancel", accesses = UiProbe.Accesses });
            }
            {
                var (window, _) = Create(variant); string path = AddRead(new PendingRead(null)); window.Close(); UiProbe.Reset();
                Task<bool> task = window.Load(path); await Bounded(task);
                Check(!await task && UiProbe.Accesses == 0 && ReportAdapter.Calls == (fixedCore ? 0 : 1), "New import after close must avoid starting a read");
                cases.Add(new { variant, name = "new-import-after-close", readCalls = ReportAdapter.Calls });
            }
            {
                var (window, state) = Create(variant); var binding = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                state.parityViewBinding = binding.Task; Task<bool> task = window.Load(AddRead(new PendingRead(null)));
                Check(!task.IsCompleted && UiProbe.Publishes == 1, "Binding must actually be pending after publication");
                window.Close(); UiProbe.Reset(); binding.SetException(new IOException("late binding fault")); await Bounded(task);
                Check(!await task && UiProbe.Writes == (fixedCore ? 0 : 1), "Late binding catch must not write after close");
                cases.Add(new { variant, name = "delayed-binding-fault-after-close", writes = UiProbe.Writes });
            }
            {
                var (window, state) = Create(variant);
                using var registration = state.actionLifetime.Token.Register(() => throw new InvalidOperationException("controlled cancellation callback"));
                bool threw = false; try { window.Close(); } catch (AggregateException) { threw = true; }
                Check(threw, "Cancellation failure remains observable");
                Check(!fixedCore || (!state.ready && state.generation == 1 && state.actionLifetime.IsCancellationRequested), "State is invalidated before throwing cancellation callback");
                // A throwing Closed subscriber can still prevent later cleanup. This
                // remains a limitation; the patch does not claim independent cleanup.
                Check(state.engine.Disconnects == 0, "Do not claim cleanup when cancellation interrupted subscribers");
                cases.Add(new { variant, name = "cancellation-callback-throws", observable = threw, disconnects = state.engine.Disconnects });
            }
            foreach (bool fail in new[] { false, true })
            {
                var (window, _) = Create(variant); File.Reset(); Task task = window.Fixture(); await Bounded(File.FixtureEntered.Task);
                window.Close(); UiProbe.Reset();
                if (fail) File.FixtureRead.SetException(new IOException("controlled fixture fault")); else File.FixtureRead.SetResult("[{\"Id\":\"fixture\"}]");
                await Bounded(task);
                int expected = fail ? (fixedOptional ? 0 : 1) : (fixedCore ? 0 : 99);
                Check(expected == 99 ? UiProbe.Writes > 0 : UiProbe.Writes == expected, "Fixture continuation scope matches core/optional split");
                cases.Add(new { variant, name = "delayed-fixture-after-close", fail, writes = UiProbe.Writes });
            }
            {
                var (window, _) = Create(variant); window.Close(); UiProbe.Reset(); window.SendPlacement();
                Check(fixedOptional ? UiProbe.Accesses == 0 : UiProbe.Reads > 0, "Closed placement callback reads native objects unless optional guard is present");
                cases.Add(new { variant, name = "placement-after-close", accesses = UiProbe.Accesses });
            }
        }
        Console.WriteLine(JsonSerializer.Serialize(new { passed = true, assertions, cases = cases.Count, results = cases,
            scope = "Exact extracted method bodies with fake read/control boundaries, not WinUI/COM or crash reproduction" },
            new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } }));
    }
}
