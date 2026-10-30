using AttackMap.GraphExplorer;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed class FleetView : UserControl
{
    private readonly FleetWorkspace workspace = new();
    private readonly ListView repositories = new() { SelectionMode = ListViewSelectionMode.Single, MaxHeight = 220 };
    private readonly StackPanel results = new() { Spacing = 8 };
    private readonly StackPanel childStatuses = new() { Spacing = 4 };
    private FleetGeneration? renderedGeneration;
    private FleetSummaryIdentityMap? summaryIdentity;
    private readonly FleetGraphPane graph = new() { Height = 460, Visibility = Visibility.Collapsed };
    private readonly ScrollViewer workspaceScroll = new() { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    private XamlRoot? sizingRoot;
    private bool graphDisposed, sizingAttached;
    private readonly NumberBox budget = new() { Header = "Whole fleet allowance (seconds)", Minimum = 1, Maximum = 86400, Value = 600 };
    private readonly NumberBox workers = new() { Header = "Concurrent repository workers (1–4)", Minimum = 1, Maximum = 4, Value = 1 };
    private readonly TextBlock allowance = new() { TextWrapping = TextWrapping.Wrap };
    public FleetExecutionOptions ExecutionOptions
    {
        get
        {
            if (!double.IsFinite(budget.Value) || budget.Value != Math.Truncate(budget.Value) || !double.IsFinite(workers.Value) || workers.Value != Math.Truncate(workers.Value))
                throw new InvalidDataException("Fleet allowance and worker count must be whole numbers.");
            var value = new FleetExecutionOptions((int)budget.Value, (int)workers.Value); value.Validate(); return value;
        }
    }
    public event Action<FleetGraphExport>? GraphExportRequested;
    public event Action<FleetGraphSourceRequest>? GraphSourceRequested;
    public GraphContext? GraphContext => graph.Context;
    internal bool HasGraphNativeLayout => graph.HasNativeLayout;
    internal bool HasInteractiveGraphLayoutAcknowledgement => graph.HasInteractiveLayoutAcknowledgement;
    internal IReadOnlyList<GraphRepository> GraphRepositories => graph.Repositories;
    public bool VerifyGraphSourceRequest(FleetGraphSourceRequest request) =>
        !workspace.IsRunning && workspace.Active?.RunId == request.Context.RunId && graph.VerifySourceRequest(request);
    public bool BackToGraphSelection(FleetGraphSourceRequest request) => VerifyGraphSourceRequest(request) && graph.BackToSelection(request);
    internal void SetExecutionOptions(FleetExecutionOptions options)
    {
        if (workspace.IsRunning) throw new InvalidOperationException("Wait for the active fleet before changing its allowance.");
        options.Validate(); budget.Value = options.TimeoutSeconds; workers.Value = options.MaxWorkers;
    }
    internal Task SelectGraphSurface(bool vector) => graph.SelectSurface(vector);
    public async Task ShowArchitecture(FleetGeneration generation, GraphDocument document)
    {
        if (workspace.Active != generation || workspace.IsRunning) return;
        await graph.SetDocumentAsync(document);
        if ((workspace.Active != generation || workspace.IsRunning) && graph.Context == document.Context) graph.Clear();
    }
    public ValueTask DisposeGraphAsync()
    {
        if (graphDisposed) return ValueTask.CompletedTask;
        graphDisposed = true; Loaded -= GraphHostLoaded; Unloaded -= GraphHostUnloaded; DetachGraphSizing();
        return graph.DisposeAsync();
    }
    private readonly TextBlock status = new() { TextWrapping = TextWrapping.Wrap };
    private readonly CheckBox watch = new() { Content = "Watch selected repositories", IsChecked = false };
    private readonly TextBlock watchNotice = new() { Text = "Fleet watch is off. Enable it explicitly to request rescans after changes.", TextWrapping = TextWrapping.Wrap };
    public FleetWorkspace Workspace => workspace;
    public bool WatchRequested { get => watch.IsChecked == true; set { if (WatchRequested != value) watch.IsChecked = value; } }
    public IReadOnlyList<FleetRoot> SelectedRoots => Array.AsReadOnly(workspace.Repositories.ToArray());
    public event Action<bool>? WatchRequestedChanged;
    public event Action<IReadOnlyList<FleetRoot>>? RepositorySetChanged;
    public event Action? AddRepositoryRequested;
    public event Action<IReadOnlyList<FleetRoot>>? ScanRequested;
    public event Action? CancelRequested;
    public event Action<FleetOpenRepository>? OpenRepositoryRequested;
    public FleetView()
    {
        repositories.ItemTemplate = (DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load("""
            <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
                <TextBlock Name="FleetRepositoryPath" Text="{Binding RepositoryPath}" TextWrapping="Wrap" Margin="0,6" />
            </DataTemplate>
            """);
        var rowStyle = new Style { TargetType = typeof(ListViewItem) };
        rowStyle.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch));
        repositories.ItemContainerStyle = rowStyle;
        ScrollViewer.SetHorizontalScrollMode(repositories, ScrollMode.Disabled);
        ScrollViewer.SetHorizontalScrollBarVisibility(repositories, ScrollBarVisibility.Disabled);
        var panel = new StackPanel { Spacing = 12, Padding = new Thickness(16) };
        panel.Children.Add(new TextBlock { Text = "Fleet workspace", FontSize = 26 });
        panel.Children.Add(new TextBlock { Text = "Explicitly select 2–16 local repositories. Fleet AI, baselines, custom suppressions and secret history are unsupported. Partial runs remain diagnostic and never replace a current analysis.", TextWrapping = TextWrapping.Wrap });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        Button Add(string title, Action action) { var b = new Button { Content = title }; b.Click += (_,_) => action(); buttons.Children.Add(b); return b; }
        Add("Add repository…", () => AddRepositoryRequested?.Invoke());
        Add("Remove selected", () => { if (repositories.SelectedItem is FleetRoot root) RemoveRepository(root.RepositoryId); });
        Add("Scan fleet", () => { if (workspace.Repositories.Count < 2) status.Text = "Select at least two repositories."; else ScanRequested?.Invoke(workspace.Repositories.ToArray()); });
        Add("Cancel fleet", () => CancelRequested?.Invoke());
        watch.Checked += (_, _) => WatchRequestedChanged?.Invoke(true);
        watch.Unchecked += (_, _) => WatchRequestedChanged?.Invoke(false);
        panel.Children.Add(buttons); panel.Children.Add(budget); panel.Children.Add(workers); panel.Children.Add(allowance);
        void RefreshAllowance() { try { allowance.Text = ExecutionOptions.Notice; } catch (InvalidDataException error) { allowance.Text = error.Message; } }
        budget.ValueChanged += (_, _) => RefreshAllowance(); workers.ValueChanged += (_, _) => RefreshAllowance(); RefreshAllowance();
        graph.OpenRepositoryRootRequested += root => { if (summaryIdentity?.ResolveRoot(root) is { } request) OpenRepositoryRequested?.Invoke(request); };
        graph.ExportRequested += request => { if (graph.Context == request.Context && workspace.Active?.RunId == request.Context.RunId && !workspace.IsRunning) GraphExportRequested?.Invoke(request); };
        graph.OpenEvidenceSourceRequested += request => { if (VerifyGraphSourceRequest(request)) GraphSourceRequested?.Invoke(request); };
        panel.Children.Add(watch); panel.Children.Add(watchNotice);
        panel.Children.Add(new TextBlock { Text = "Watching requests full fleet rescans. Unsupported roots require manual rescans.", TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(repositories); panel.Children.Add(status); panel.Children.Add(graph); panel.Children.Add(childStatuses); panel.Children.Add(results);
        workspaceScroll.Content = panel; Content = workspaceScroll;
        Loaded += GraphHostLoaded; Unloaded += GraphHostUnloaded;
        Refresh();
    }
    private void GraphHostLoaded(object sender, RoutedEventArgs args)
    {
        if (graphDisposed) return;
        if (!sizingAttached) { workspaceScroll.SizeChanged += GraphHostSizeChanged; sizingAttached = true; }
        if (!ReferenceEquals(sizingRoot, XamlRoot))
        {
            if (sizingRoot != null) sizingRoot.Changed -= GraphRootChanged;
            sizingRoot = XamlRoot;
            if (sizingRoot != null) sizingRoot.Changed += GraphRootChanged;
        }
        ResizeGraph();
    }
    private void GraphHostUnloaded(object sender, RoutedEventArgs args) => DetachGraphSizing();
    private void GraphHostSizeChanged(object sender, SizeChangedEventArgs args) { if (!graphDisposed && sizingAttached) ResizeGraph(); }
    private void GraphRootChanged(XamlRoot sender, XamlRootChangedEventArgs args) { if (!graphDisposed && ReferenceEquals(sender, sizingRoot)) ResizeGraph(); }
    private void ResizeGraph()
    {
        double available = workspaceScroll.ViewportHeight > 0 ? workspaceScroll.ViewportHeight - 32 : (sizingRoot?.Size.Height ?? 650) - 190;
        if (!double.IsFinite(available) || available <= 0) return;
        double height = Math.Clamp(available, 460, 900);
        if (Math.Abs(graph.Height - height) > 1) graph.Height = height;
    }
    private void DetachGraphSizing()
    {
        if (sizingRoot != null) sizingRoot.Changed -= GraphRootChanged;
        sizingRoot = null;
        if (sizingAttached) workspaceScroll.SizeChanged -= GraphHostSizeChanged;
        sizingAttached = false;
    }
    private void Attempt(Action action)
    {
        var before = workspace.Repositories.ToArray();
        try { action(); Refresh(); }
        catch (Exception e) when (e is InvalidOperationException or InvalidDataException) { status.Text = e.Message; return; }
        if (!before.SequenceEqual(workspace.Repositories)) RepositorySetChanged?.Invoke(SelectedRoots);
    }
    public void AddRepository(string id, string path) => Attempt(() => workspace.Add(id,path));
    public void RemoveRepository(string id) => Attempt(() => workspace.Remove(id));
    public void SetWatchNotice(string notice) => watchNotice.Text = notice;
    public void Refresh()
    {
        if (renderedGeneration != workspace.Active) { results.Children.Clear(); summaryIdentity = null; graph.Clear(); renderedGeneration = workspace.Active; }
        budget.IsEnabled = workers.IsEnabled = !workspace.IsRunning;
        childStatuses.Children.Clear();
        foreach (var child in workspace.Children)
        {
            var row = new StackPanel { Spacing = 4 };
            row.Children.Add(new TextBlock { Text = $"{child.RepositoryId}: {child.State}\n{child.RepositoryPath}", TextWrapping = TextWrapping.Wrap });
            if (child.State == "completed")
            {
                var captured = workspace.Open(child.RepositoryId)!;
                var open = new Button { Content = "Open verified repository result", IsEnabled = !workspace.IsRunning };
                open.Click += (_,_) => { if (workspace.Active == captured.Generation && !workspace.IsRunning) OpenRepositoryRequested?.Invoke(captured); };
                row.Children.Add(open);
            }
            childStatuses.Children.Add(row);
        }
        string? selectedId = (repositories.SelectedItem as FleetRoot)?.RepositoryId;
        var roots = workspace.Repositories.ToArray();
        repositories.ItemsSource = roots;
        if (selectedId != null) repositories.SelectedItem = roots.SingleOrDefault(root => root.RepositoryId == selectedId);
        status.Text = $"Fleet: {workspace.Outcome}. {workspace.Repositories.Count} selected repositories. " + (workspace.IsCurrent ? "All children completed." : "No complete fleet generation published by this view.");
    }
    public void ShowSummary(FleetGeneration generation, FleetSummary summary)
    {
        if (workspace.Active != generation) return;
        summaryIdentity = FleetSummaryIdentityMap.Bind(workspace, summary);
        renderedGeneration = generation;
        results.Children.Clear();
        foreach (var repo in summary.Repositories)
        {
            var row = new StackPanel { Spacing = 4 };
            row.Children.Add(new TextBlock { Text = $"{repo.RepositoryId} · {repo.Findings?.ToString() ?? "unknown"} supplied findings\n{repo.Root}", TextWrapping = TextWrapping.Wrap });
            var open = new Button { Content = "Open verified repository result", IsEnabled = summaryIdentity.Resolve(repo.RepositoryId) != null };
            open.Click += (_,_) => { if (workspace.Active == generation && summaryIdentity?.Resolve(repo.RepositoryId) is { } request) OpenRepositoryRequested?.Invoke(request); };
            row.Children.Add(open); results.Children.Add(row);
        }
        foreach (var child in workspace.Children.Where(c => c.State != "completed")) results.Children.Add(new TextBlock { Text = $"{child.RepositoryId}: {child.State}", TextWrapping = TextWrapping.Wrap });
        foreach (var failure in summary.Failures) results.Children.Add(new TextBlock { Text = "Failed repository: " + failure, TextWrapping = TextWrapping.Wrap });
        foreach (var link in summary.Links)
            results.Children.Add(new Expander { Header = $"{link.Client} → {link.Server}: {link.Description}", Content = new TextBlock { Text = $"{link.Method} {link.Route}\nReason: {link.Reason}\nProxy: {link.Proxy ?? "none supplied"}\n{link.Source}", TextWrapping = TextWrapping.Wrap } });
        void Evidence(string title, IReadOnlyList<System.Text.Json.JsonElement> records) { foreach (var record in records) results.Children.Add(new Expander { Header = title + " · speculative core evidence", Content = new TextBlock { Text = record.ToString(), TextWrapping = TextWrapping.Wrap } }); }
        Evidence("Cross-boundary flow",summary.Flows); Evidence("Trust gap",summary.Gaps); Evidence("Cross-repository anomaly",summary.Anomalies);
        Refresh();
    }
}
