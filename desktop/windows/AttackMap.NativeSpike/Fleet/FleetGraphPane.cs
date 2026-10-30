using AttackMap.GraphExplorer;
using AttackMap.GraphExplorer.Native;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed record FleetGraphExport(GraphContext Context, string Extension, string Content);

/// <summary>Native presentation of a host-verified core graph; never invents relationships.</summary>
public sealed class FleetGraphPane : UserControl, IAsyncDisposable
{
    private readonly GraphExplorerView explorer = new();
    private readonly GraphWebView interactive = new();
    private readonly ComboBox surface = new() { MaxWidth = 260, HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly TextBox evidence = new() { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MaxHeight = 150 };
    private readonly StackPanel evidencePane = new() { Spacing = 6, Visibility = Visibility.Collapsed };
    private readonly ScrollViewer evidenceViewport = new() { Visibility = Visibility.Collapsed, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
    private readonly Grid views = new();
    private readonly TextBlock evidenceHeading = new() { TextWrapping = TextWrapping.Wrap };
    private readonly ComboBox evidencePicker = new() { DisplayMemberPath = nameof(FleetGraphEvidenceItem.DisplayName), HorizontalAlignment = HorizontalAlignment.Stretch, MaxDropDownHeight = 240 };
    private readonly TextBlock sourceNotice = new() { TextWrapping = TextWrapping.Wrap };
    private readonly Button openSource = new() { Content = "Inspect source location", IsEnabled = false };
    private readonly TextBlock notice = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock interpretation = new() { TextWrapping = TextWrapping.Wrap, MaxWidth = 420, IsTextSelectionEnabled = true };
    private readonly AppBarButton open = new() { Label = "Open selected repository report", Icon = new SymbolIcon(Symbol.OpenFile), IsEnabled = false };
    private readonly AppBarButton inspect = new() { Label = "Inspect selected evidence", Icon = new SymbolIcon(Symbol.Find), IsEnabled = false };
    private readonly AppBarButton json = new() { Label = "Export complete graph JSON", Icon = new SymbolIcon(Symbol.Save), IsEnabled = false };
    private readonly AppBarButton svg = new() { Label = "Export entire diagram SVG", Icon = new SymbolIcon(Symbol.Save), IsEnabled = false };
    private readonly bool singleReport;
    private GraphDocument? document;
    private GraphSelection? selected;
    private long version;
    private GraphContext? nativeContext, webContext;
    private Task surfaceTransition = Task.CompletedTask;
    private bool disposed;
    private bool? effectiveVisibility;
    public GraphContext? Context => document?.Context;
    internal long InteractiveInitializationAttemptCount => interactive.InitializationAttemptCount;
    internal long InteractiveCoreInitializationCount => interactive.CoreInitializationCount;
    public bool IsInspectingEvidence => evidenceViewport.Visibility == Visibility.Visible;
    public bool HasNativeLayout => document != null && explorer.Snapshot?.Context == document.Context;
    public bool HasInteractiveLayoutAcknowledgement => document != null && interactive.LayoutAcknowledgedContext == document.Context;
    public IReadOnlyList<GraphRepository> Repositories => document?.Repositories.ToArray() ?? [];
    public FleetGraphSourceRequest? SelectedSourceRequest => document is { } current && CurrentSelection() is { } selection && evidencePicker.SelectedItem is FleetGraphEvidenceItem item
        ? FleetGraphEvidenceNavigation.BuildSourceRequest(current, current.Context, selection, item.Id, out _) : null;
    public event Action<string>? OpenRepositoryRootRequested;
    public event Action<FleetGraphSourceRequest>? OpenEvidenceSourceRequested;
    public event Action<FleetGraphExport>? ExportRequested;

    public FleetGraphPane(bool singleReport = false)
    {
        this.singleReport = singleReport;
        if (singleReport) open.Visibility = Visibility.Collapsed;
        var panel = new Grid { RowSpacing = 8 };
        panel.RowDefinitions.Add(new() { Height = GridLength.Auto });
        panel.RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) });
        var actions = new StackPanel { Spacing = 4 };
        var arguments = Environment.GetCommandLineArgs();
        bool nativeOnly = arguments.Contains("--render-diagnostics", StringComparer.Ordinal)
            && arguments.Contains("--render-native-only", StringComparer.Ordinal);
        surface.Items.Add("Interactive overview"); surface.Items.Add("Vector diagram"); surface.SelectedIndex = nativeOnly ? 1 : 0;
        surface.IsEnabled = !nativeOnly;
        AutomationProperties.SetName(surface, nativeOnly ? "Diagram view: vector only for rendering diagnostics" : "Diagram view");
        var heading = new Grid { ColumnSpacing = 8 };
        heading.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        heading.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        heading.Children.Add(new TextBlock { Text = singleReport ? "Report architecture" : "Fleet architecture", FontSize = 22, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center });
        var explanation = new Expander { Header = new TextBlock { Text = "Interpretation and coverage", TextWrapping = TextWrapping.Wrap, MaxWidth = 220 },
            Content = interpretation, HorizontalAlignment = HorizontalAlignment.Stretch, MaxWidth = 420 };
        AutomationProperties.SetName(explanation, (singleReport ? "Report" : "Fleet") + " graph interpretation, partial coverage and aggregate path warning");
        Grid.SetColumn(explanation, 1); heading.Children.Add(explanation); actions.Children.Add(heading);
        actions.Children.Add(notice);
        var commands = new CommandBar { Content = surface, IsDynamicOverflowEnabled = true, DefaultLabelPosition = CommandBarDefaultLabelPosition.Right };
        foreach (var command in new[] { open, inspect, json, svg })
        {
            AutomationProperties.SetName(command, command.Label); ToolTipService.SetToolTip(command, command.Label);
            commands.PrimaryCommands.Add(command);
        }
        actions.Children.Add(commands);
        panel.Children.Add(actions);
        views.Children.Add(explorer); views.Children.Add(interactive);
        explorer.Visibility = Visibility.Collapsed; json.Visibility = svg.Visibility = Visibility.Collapsed;
        Grid.SetRow(views, 1); panel.Children.Add(views);
        AutomationProperties.SetName(evidencePicker, "Evidence records with source or target repository identity");
        AutomationProperties.SetName(evidence, "Canonical relationship and selected evidence details");
        AutomationProperties.SetName(openSource, "Inspect selected evidence source location in its verified repository");
        var evidenceActions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        var back = new Button { Content = "Back to graph" };
        back.Click += (_, _) => CloseEvidenceInspector();
        evidenceActions.Children.Add(openSource); evidenceActions.Children.Add(back);
        evidencePane.Children.Add(evidenceHeading); evidencePane.Children.Add(evidencePicker); evidencePane.Children.Add(evidenceActions);
        evidencePane.Children.Add(sourceNotice); evidencePane.Children.Add(evidence);
        evidenceViewport.Content = evidencePane;
        Grid.SetRow(evidenceViewport, 1); panel.Children.Add(evidenceViewport); Content = panel;
        SizeChanged += (_, _) => explorer.Fit();
        LayoutUpdated += OnLayoutUpdated;
        explorer.SelectionChanged += (_, value) =>
        {
            if (document?.Context != value.Context) return;
            selected = value; CloseEvidenceInspector(restoreFocus: false); inspect.IsEnabled = true;
            open.IsEnabled = !singleReport && SelectedRepository() is { Status: "completed" or "partial" };
        };
        explorer.OpenEvidenceRequested += (_, value) =>
        {
            if (document?.Context != value.Context) return;
            InspectSelectedEvidence();
        };
        explorer.SnapshotChanged += () => svg.IsEnabled = document != null && explorer.Snapshot?.Context == document.Context;
        surface.SelectionChanged += (_, _) =>
        {
            if (nativeOnly && surface.SelectedIndex != 1) { surface.SelectedIndex = 1; return; }
            if (document != null) surfaceTransition = ActivateSurface();
        };
        interactive.FallbackShown += message =>
        {
            if (document != null && surface.SelectedIndex == 0)
            {
                notice.Text = message + " The native vector diagram remains available.";
                notice.Visibility = Visibility.Visible;
                surface.SelectedIndex = 1;
            }
        };
        interactive.SelectionChanged += value =>
        {
            if (document?.Context != value.Context) return;
            selected = new(value.Context, "interactive-selection", value.EdgeIds.Length > 0, value.NodeIds, value.EdgeIds, value.EvidenceIds);
            open.IsEnabled = !singleReport && SelectedRepository() is { Status: "completed" or "partial" };
            CloseEvidenceInspector(restoreFocus: false); inspect.IsEnabled = true;
        };
        interactive.EvidenceRequested += value =>
        {
            if (document?.Context != value.Context) return;
            selected = new(value.Context, "interactive-selection", value.EdgeIds.Length > 0, value.NodeIds, value.EdgeIds, value.EvidenceIds);
            inspect.IsEnabled = true;
            open.IsEnabled = !singleReport && SelectedRepository() is { Status: "completed" or "partial" };
            InspectSelectedEvidence();
        };
        interactive.ExportRequested += request =>
        {
            if (document?.Context == request.Context && request.Format == "json") ExportRequested?.Invoke(new(request.Context, ".json", request.CanonicalJson));
        };
        open.Click += (_, _) => { if (!singleReport && SelectedRepository() is { Status: "completed" or "partial" } repo) OpenRepositoryRootRequested?.Invoke(repo.Root); };
        inspect.Click += (_, _) => InspectSelectedEvidence();
        evidencePicker.SelectionChanged += (_, _) => RefreshEvidenceRecord();
        openSource.Click += (_, _) =>
        {
            var request = SelectedSourceRequest;
            if (request == null) { RefreshEvidenceRecord(); return; }
            OpenEvidenceSourceRequested?.Invoke(request);
        };
        json.Click += (_, _) => { if (document is { } current) ExportRequested?.Invoke(new(current.Context, ".json", ExportJson(current))); };
        svg.Click += (_, _) =>
        {
            if (document is not { } current || explorer.CurrentProjection is not { } projection || explorer.Snapshot is not { } layout) return;
            try { ExportRequested?.Invoke(new(current.Context, ".svg", GraphExporter.Svg(projection, layout))); }
            catch (InvalidOperationException error) { notice.Text = error.Message; notice.Visibility = Visibility.Visible; }
        };
    }

    private void OnLayoutUpdated(object? sender, object args)
    {
        bool visible = UiActivation.IsEffectivelyVisible(this);
        if (effectiveVisibility == visible) return;
        effectiveVisibility = visible;
        if (visible && !disposed && document != null) surfaceTransition = ActivateSurface();
    }

    public async Task SetDocumentAsync(GraphDocument value)
    {
        if (disposed) return;
        long captured = ++version; document = value; selected = null; open.IsEnabled = false; Visibility = Visibility.Visible;
        inspect.IsEnabled = json.IsEnabled = svg.IsEnabled = false; CloseEvidenceInspector(restoreFocus: false);
        notice.Text = $"{value.Repositories.Length} {(value.Repositories.Length == 1 ? "repository" : "repositories")}; coverage may be partial. Aggregated paths do not prove service reachability.";
        notice.Visibility = singleReport ? Visibility.Collapsed : Visibility.Visible;
        interpretation.Text = (singleReport ? notice.Text + "\nCaptured report snapshot; " : "Independent child snapshots; ") +
            "coverage may be partial. Choose Vector diagram for SVG export. " + GraphDocument.AggregatePathWarning;
        nativeContext = webContext = null;
        surfaceTransition = ActivateSurface(); await surfaceTransition;
        if (version != captured || document?.Context != value.Context) return;
        json.IsEnabled = true; svg.IsEnabled = explorer.Snapshot?.Context == value.Context;
    }

    private async Task ActivateSurface()
    {
        if (disposed || !UiActivation.IsEffectivelyVisible(this) || document is not { } current) return;
        bool vector = surface.SelectedIndex == 1;
        explorer.Visibility = vector ? Visibility.Visible : Visibility.Collapsed;
        interactive.Visibility = vector ? Visibility.Collapsed : Visibility.Visible;
        json.Visibility = svg.Visibility = vector ? Visibility.Visible : Visibility.Collapsed;
        if (vector && nativeContext != current.Context)
        {
            nativeContext = current.Context;
            await explorer.SetDocumentAsync(current, expandRepositories: singleReport);
        }
        else if (!vector && webContext != current.Context)
        {
            webContext = current.Context;
            await interactive.LoadGraph(System.Text.Encoding.UTF8.GetBytes(current.SourceJson), current.Context);
        }
        if (disposed || document?.Context != current.Context) return;
        svg.IsEnabled = explorer.Snapshot?.Context == current.Context;
    }

    public Task SelectSurface(bool vector)
    {
        if (disposed) return Task.CompletedTask;
        int index = vector ? 1 : 0;
        if (surface.SelectedIndex != index) surface.SelectedIndex = index;
        return surfaceTransition;
    }

    public void Clear()
    {
        if (disposed) return;
        ++version; document = null; selected = null; nativeContext = webContext = null; explorer.Clear(); interactive.Clear(); open.IsEnabled = inspect.IsEnabled = openSource.IsEnabled = json.IsEnabled = svg.IsEnabled = false;
        evidence.Text = sourceNotice.Text = evidenceHeading.Text = ""; evidencePicker.ItemsSource = null; CloseEvidenceInspector(restoreFocus: false); Visibility = Visibility.Collapsed;
    }

    private FleetGraphSelection? CurrentSelection() => document is { } current && selected is { } selection && selection.Context == current.Context
        ? new(selection.Context, selection.PresentationId, selection.IsEdge, selection.NodeIds, selection.EdgeIds) : null;

    public bool InspectSelectedEvidence(string? evidenceId = null)
    {
        if (document is not { } current || CurrentSelection() is not { } selection ||
            !FleetGraphEvidenceNavigation.TryDescribe(current, current.Context, selection, out var detail, out _)) return false;
        if (evidenceId != null && !detail!.Items.Any(item => item.Id == evidenceId)) return false;
        ShowEvidence(selection, evidenceId); return true;
    }

    private void ShowEvidence(FleetGraphSelection selection, string? evidenceId = null)
    {
        if (document is not { } current || !FleetGraphEvidenceNavigation.TryDescribe(current, current.Context, selection, out var detail, out string reason)) return;
        evidenceHeading.Text = $"{detail!.Edges.Length} original relationships; {detail.Items.Length} referenced evidence records; {detail.Items.Count(item => item.Record == null)} unavailable. " +
            "Source/target labels identify endpoint repositories. Endpoint-only records do not establish a relationship. " +
            (singleReport ? "Captured report snapshot; " : "Independent child snapshots; ") + "live source may have changed.";
        evidencePicker.ItemsSource = detail.Items;
        evidencePicker.SelectedItem = detail.Items.FirstOrDefault(item => item.Id == evidenceId) ?? detail.Items.FirstOrDefault();
        views.Visibility = Visibility.Collapsed; evidenceViewport.Visibility = evidencePane.Visibility = Visibility.Visible;
        RefreshEvidenceRecord();
    }

    public void CloseEvidenceInspector(bool restoreFocus = true)
    {
        evidenceViewport.Visibility = evidencePane.Visibility = Visibility.Collapsed;
        views.Visibility = Visibility.Visible;
        if (restoreFocus) surface.Focus(FocusState.Programmatic);
    }

    private void RefreshEvidenceRecord()
    {
        openSource.IsEnabled = false;
        if (document is not { } current || CurrentSelection() is not { } selection ||
            !FleetGraphEvidenceNavigation.TryDescribe(current, current.Context, selection, out var detail, out string reason)) return;
        string facts = string.Join("\n\n", detail!.Edges.Select(edge => $"Original relationship: {edge.Id}\n{edge.Source} → {edge.Target}\n{edge.Kind}; directed {edge.Directed}; resolution {edge.Resolution}; basis {edge.Basis}; confidence {edge.Confidence ?? "unknown"}; proxy {edge.Proxy}"));
        if (evidencePicker.SelectedItem is not FleetGraphEvidenceItem item)
        { evidence.Text = facts + "\n\nNo evidence references were supplied for this selection."; sourceNotice.Text = "Source location unknown."; return; }
        evidence.Text = facts + $"\n\nEvidence: {item.Id}\n{item.Side}\n{item.RepositoryLabel}\n" +
            (item.EndpointOnly ? "Endpoint-only evidence; this record does not establish the selected relationship.\n" : "Referenced by the selected canonical facts.\n") +
            $"Relationships referencing this record or endpoint: {string.Join(", ", item.EdgeIds)}\n" + (item.Record?.Data.ToString() ?? "Evidence record unavailable; source unknown.");
        var request = FleetGraphEvidenceNavigation.BuildSourceRequest(current, current.Context, selection, item.Id, out reason);
        openSource.IsEnabled = request != null;
        sourceNotice.Text = request == null ? reason : $"{request.RepositoryRoot} · {request.RelativePath} · line {request.Line?.ToString() ?? "unknown"}. Inspect the current file against this captured location.";
    }

    public bool VerifySourceRequest(FleetGraphSourceRequest request) => document is { } current && CurrentSelection() is { } selection &&
        FleetGraphEvidenceNavigation.SameSelection(selection, request.Selection) && FleetGraphEvidenceNavigation.TryValidate(current, current.Context, request, out _);

    public bool BackToSelection(FleetGraphSourceRequest request)
    {
        if (!VerifySourceRequest(request)) return false;
        if (surface.SelectedIndex == 1) explorer.Select(request.Selection.PresentationId, request.Selection.IsEdge);
        else if (selected is { } selection) interactive.Select(new(selection.Context, selection.NodeIds, selection.EdgeIds, selection.EvidenceIds));
        ShowEvidence(request.Selection, request.EvidenceId);
        evidencePicker.Focus(FocusState.Programmatic);
        return true;
    }

    private GraphRepository? SelectedRepository()
    {
        if (document is not { } current || selected is not { } selection || selection.Context != current.Context) return null;
        var ids = selection.NodeIds.ToHashSet(StringComparer.Ordinal);
        var repos = current.Nodes.Where(node => ids.Contains(node.Id)).Select(node => node.RepoId ?? node.Id).Distinct().ToArray();
        return repos.Length == 1 ? current.Repositories.SingleOrDefault(repo => repo.Id == repos[0]) : null;
    }

    private string ExportJson(GraphDocument value)
    {
        return GraphExporter.JsonWithMetadata(value, explorer.CurrentProjection);
    }

    public ValueTask DisposeAsync()
    {
        if (disposed) return ValueTask.CompletedTask;
        Clear();
        disposed = true;
        LayoutUpdated -= OnLayoutUpdated;
        interactive.Stop();
        return explorer.DisposeAsync();
    }
}
