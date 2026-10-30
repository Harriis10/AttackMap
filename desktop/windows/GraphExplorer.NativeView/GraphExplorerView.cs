using System.Collections.Immutable;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;

namespace AttackMap.GraphExplorer.Native;

public sealed record GraphSelection(GraphContext Context, string PresentationId, bool IsEdge,
    ImmutableArray<string> NodeIds, ImmutableArray<string> EdgeIds, ImmutableArray<string> EvidenceIds);
public sealed record EvidenceRequest(GraphContext Context, ImmutableArray<string> EvidenceIds);

/// <summary>Isolated Canvas/MSAGL comparison control. Host owns artifact verification and evidence navigation.</summary>
public sealed class GraphExplorerView : UserControl, IAsyncDisposable
{
    private readonly LayoutSession layouts = new();
    private readonly HashSet<string> collapsed = new(StringComparer.Ordinal);
    private readonly Canvas canvas = new();
    private readonly ScrollViewer viewport = new() { ZoomMode = ZoomMode.Enabled, MinZoomFactor = 0.1f, MaxZoomFactor = 3f,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        HorizontalScrollMode = ScrollMode.Enabled, VerticalScrollMode = ScrollMode.Enabled };
    private readonly ListView alternatives = new() { SelectionMode = ListViewSelectionMode.Single, MinHeight = 150 };
    private readonly TextBox search = new() { PlaceholderText = "Find a node or edge", MinWidth = 180, MaxWidth = 260 };
    private readonly TextBlock notice = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(8) };
    private readonly TextBox details = new() { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap,
        BorderThickness = new Thickness(0), MaxHeight = 240 };
    private readonly Button toggle = new() { Content = "Expand selected group", IsEnabled = false };
    private readonly Button evidence = new() { Content = "Open selected evidence", IsEnabled = false };
    private readonly ComboBox resolutions = new() { Width = 190 };
    private readonly AppBarToggleButton interRepository = new() { Label = "Inter-repository only", Icon = new SymbolIcon(Symbol.Link) };
    private GraphNeighborhood neighborhood;
    private string? focusNodeId;
    private readonly Dictionary<string, Button> nodeButtons = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Microsoft.UI.Xaml.Shapes.Path> edgePaths = new(StringComparer.Ordinal);
    private GraphDocument? document;
    private GraphProjection? projection;
    private LayoutSnapshot? snapshot;
    private GraphSelection? selection;
    private long requestVersion;
    private bool disposed, syncing, unloaded, resumeLayoutOnLoad;

    public event EventHandler<GraphSelection>? SelectionChanged;
    public event EventHandler<EvidenceRequest>? OpenEvidenceRequested;
    public event Action? SnapshotChanged;
    public LayoutSnapshot? Snapshot => snapshot;
    public GraphProjection? CurrentProjection => projection;

    public GraphExplorerView()
    {
        var root = new Grid();
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) });
        var toolbar = new CommandBar { IsDynamicOverflowEnabled = true, DefaultLabelPosition = CommandBarDefaultLabelPosition.Right,
            Margin = new Thickness(8), Content = search };
        search.MinWidth = 140; search.Width = 180;
        toolbar.PrimaryCommands.Add(Command("Fit", () => Fit(), Symbol.FullScreen));
        toolbar.PrimaryCommands.Add(Command("Zoom out", () => Zoom(0.8f), Symbol.ZoomOut));
        toolbar.PrimaryCommands.Add(Command("Zoom in", () => Zoom(1.25f), Symbol.ZoomIn));
        toolbar.PrimaryCommands.Add(Command("Collapse all", async () => { if (document is null) return; collapsed.Clear(); foreach (var repo in document.Repositories) collapsed.Add(repo.Id); await ArrangeAsync(); }, Symbol.BackToWindow));
        toolbar.PrimaryCommands.Add(Command("Expand all", async () => { collapsed.Clear(); await ArrangeAsync(); }, Symbol.FullScreen));
        root.Children.Add(toolbar);
        foreach (string option in new[] { "All resolutions", "Observed (+ proxy)", "Candidate", "Inferred" }) resolutions.Items.Add(option);
        resolutions.SelectedIndex = 0; AutomationProperties.SetName(resolutions, "Relationship resolution filter");
        var filterbar = new CommandBar { IsDynamicOverflowEnabled = true, DefaultLabelPosition = CommandBarDefaultLabelPosition.Right, Content = resolutions, Margin = new Thickness(8, 0, 8, 0) };
        filterbar.PrimaryCommands.Add(interRepository);
        filterbar.PrimaryCommands.Add(Command("Upstream (one hop)", async () => await NeighborhoodAsync(GraphNeighborhood.Upstream), Symbol.Back));
        filterbar.PrimaryCommands.Add(Command("Downstream (one hop)", async () => await NeighborhoodAsync(GraphNeighborhood.Downstream), Symbol.Forward));
        filterbar.PrimaryCommands.Add(Command("All neighborhoods", async () => { neighborhood = GraphNeighborhood.All; focusNodeId = null; await ArrangeAsync(); }, Symbol.ViewAll));
        Grid.SetRow(filterbar, 1); root.Children.Add(filterbar);
        resolutions.SelectionChanged += async (_, _) => await ArrangeAsync();
        interRepository.Checked += async (_, _) => await ArrangeAsync(); interRepository.Unchecked += async (_, _) => await ArrangeAsync();
        Grid.SetRow(notice, 2); root.Children.Add(notice);
        var body = new Grid(); body.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        body.ColumnDefinitions.Add(new() { Width = new GridLength(290) });
        viewport.Content = canvas;
        viewport.Background = Brush("LayerFillColorDefaultBrush", Colors.Transparent);
        body.Children.Add(viewport);
        var panel = new Grid { Margin = new Thickness(8), RowSpacing = 6 };
        panel.RowDefinitions.Add(new() { Height = GridLength.Auto }); panel.RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) });
        panel.RowDefinitions.Add(new() { Height = GridLength.Auto }); panel.RowDefinitions.Add(new() { Height = GridLength.Auto }); panel.RowDefinitions.Add(new() { Height = GridLength.Auto });
        panel.Children.Add(new TextBlock { Text = "Nodes and relationships", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        Grid.SetRow(alternatives, 1); panel.Children.Add(alternatives);
        Grid.SetRow(details, 2); panel.Children.Add(details);
        Grid.SetRow(toggle, 3); panel.Children.Add(toggle); Grid.SetRow(evidence, 4); panel.Children.Add(evidence);
        Grid.SetColumn(panel, 1); body.Children.Add(panel); Grid.SetRow(body, 3); root.Children.Add(body); Content = root;
        body.SizeChanged += (_, args) => { details.MaxHeight = Math.Clamp(args.NewSize.Height * 0.30, 80, 240); alternatives.MinHeight = 80; };
        AutomationProperties.SetName(viewport, "Architecture graph. Use the nodes and relationships list for keyboard selection.");
        AutomationProperties.SetName(alternatives, "Architecture nodes and relationships");
        AutomationProperties.SetName(search, "Find architecture node or relationship");
        AutomationProperties.SetName(details, "Selected architecture facts and evidence");
        search.TextChanged += (_, _) => RefreshList();
        alternatives.SelectionChanged += (_, _) => { if (!syncing && alternatives.SelectedItem is Item item) Select(item.Id, item.IsEdge); };
        toggle.Click += async (_, _) => { if (selection is not { IsEdge: false } current) return; if (!collapsed.Remove(current.PresentationId)) collapsed.Add(current.PresentationId); await ArrangeAsync(); };
        evidence.Click += (_, _) => { if (selection is { EvidenceIds.Length: > 0 } current) OpenEvidenceRequested?.Invoke(this, new(current.Context, current.EvidenceIds)); };
        ActualThemeChanged += (_, _) => { if (snapshot is not null) Render(); };
        Unloaded += (_, _) =>
        {
            unloaded = true;
            resumeLayoutOnLoad = document != null && snapshot == null;
            requestVersion++; layouts.CancelPending();
        };
        Loaded += async (_, _) =>
        {
            unloaded = false;
            if (disposed) return;
            if (resumeLayoutOnLoad && document != null && snapshot == null)
            {
                resumeLayoutOnLoad = false;
                await ArrangeAsync();
            }
            else Fit();
        };
        notice.Text = "Choose a verified fleet architecture artifact. No graph loaded.";
    }

    public async Task SetDocumentAsync(GraphDocument value, CancellationToken cancellationToken = default, bool expandRepositories = false)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (!DispatcherQueue.HasThreadAccess) throw new InvalidOperationException("Graph document must be assigned on the UI thread.");
        document = value; collapsed.Clear();
        if (!expandRepositories) foreach (var repo in value.Repositories) collapsed.Add(repo.Id);
        resumeLayoutOnLoad = false;
        neighborhood = GraphNeighborhood.All; focusNodeId = null;
        projection = null; snapshot = null; canvas.Children.Clear(); nodeButtons.Clear(); edgePaths.Clear(); alternatives.ItemsSource = null;
        selection = null; details.Text = "Select a node or relationship to inspect original facts.";
        toggle.IsEnabled = false; evidence.IsEnabled = false;
        await ArrangeAsync(cancellationToken);
    }

    public void Clear()
    {
        requestVersion++; layouts.CancelPending(); document = null; projection = null; snapshot = null; selection = null;
        resumeLayoutOnLoad = false;
        collapsed.Clear(); canvas.Children.Clear(); canvas.Width = canvas.Height = 0; nodeButtons.Clear(); edgePaths.Clear();
        alternatives.ItemsSource = null; details.Text = ""; toggle.IsEnabled = evidence.IsEnabled = false;
        neighborhood = GraphNeighborhood.All; focusNodeId = null;
        notice.Text = "No verified fleet architecture artifact selected.";
        SnapshotChanged?.Invoke();
    }

    private async Task ArrangeAsync(CancellationToken cancellationToken = default)
    {
        if (document is null || disposed) return;
        if (unloaded) { resumeLayoutOnLoad = true; return; }
        long version = ++requestVersion;
        var current = GraphProjection.Create(document, collapsed, new((GraphResolutionFilter)resolutions.SelectedIndex, interRepository.IsChecked == true, neighborhood, focusNodeId));
        notice.Text = "Laying out the selected projection…";
        snapshot = null; SnapshotChanged?.Invoke();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            var measures = current.Nodes.Select(node => {
                var label = new TextBlock { Text = node.Original.Label, FontSize = 13, TextWrapping = TextWrapping.Wrap, MaxWidth = 200 };
                label.Measure(new Size(200, double.PositiveInfinity));
                return new NodeMeasure(node.Id, Math.Clamp(label.DesiredSize.Width + 28, 150, 228), Math.Clamp(label.DesiredSize.Height + 34, 56, 100));
            }).ToImmutableArray();
            var edgeMeasures = current.Edges.Select(edge => {
                var label = new TextBlock { Text = $"{edge.Kind} ({edge.Count})", FontSize = 11, MaxWidth = 150, TextTrimming = TextTrimming.CharacterEllipsis };
                label.Measure(new Size(150, 24));
                return new EdgeMeasure(edge.Id, Math.Max(25, label.DesiredSize.Width), Math.Max(16, label.DesiredSize.Height));
            }).ToImmutableArray();
            var result = await layouts.ReplaceAsync(new(current, measures, edgeMeasures, MaxNodes: 1000, MaxEdges: 3000), deadline.Token);
            if (result is null || disposed || unloaded || version != requestVersion || document is null || !result.IsCurrent(document.Context)) return;
            projection = current; snapshot = result; Render(); RefreshList(); SnapshotChanged?.Invoke();
            notice.Text = $"{document.Repositories.Length} repositories; {current.Nodes.Length} visible / {document.Nodes.Length} captured nodes; {current.Edges.Length} visible relationships; {current.HiddenNodeCount} hidden nodes; {current.HiddenInternalEdgeCount} internal edges; {current.FilteredEdgeCount} original relationships excluded by filters ({current.Filter.Resolution}, inter-repository {current.Filter.InterRepositoryOnly}, {current.Filter.Neighborhood}). " + GraphDocument.AggregatePathWarning;
            Fit();
        }
        catch (OperationCanceledException)
        {
            if (version != requestVersion || disposed || unloaded) return;
            projection = current; snapshot = null; canvas.Children.Clear(); RefreshList(); SnapshotChanged?.Invoke();
            notice.Text = "Graph layout cancelled or exceeded its 15 second allowance; the native list and complete JSON remain available. Narrow the displayed relationships and retry.";
        }
        catch (Exception error) when (error is GraphReadException or ArgumentException or InvalidOperationException)
        {
            if (version != requestVersion || disposed || unloaded) return;
            projection = current; snapshot = null; canvas.Children.Clear(); RefreshList(); SnapshotChanged?.Invoke();
            notice.Text = $"Graph layout unavailable: {error.Message} Captured facts remain in the native list and full JSON export.";
        }
    }

    private async Task NeighborhoodAsync(GraphNeighborhood mode)
    {
        if (selection is not { IsEdge: false } current) { notice.Text = "Select a node or repository group for its modeled one-hop neighborhood. This is not runtime reachability."; return; }
        focusNodeId = current.PresentationId; neighborhood = mode; await ArrangeAsync();
    }

    private void Render()
    {
        if (projection is null || snapshot is null) return;
        canvas.Children.Clear(); nodeButtons.Clear(); edgePaths.Clear(); canvas.Width = snapshot.Bounds.Width; canvas.Height = snapshot.Bounds.Height;
        bool dark = ActualTheme == ElementTheme.Dark;
        SolidColorBrush Color(byte red, byte green, byte blue) => new(Windows.UI.Color.FromArgb(255, red, green, blue));
        var stroke = dark ? Color(119, 153, 181) : Color(115, 147, 173);
        var foreground = dark ? Color(227, 237, 247) : Color(28, 52, 73);
        viewport.Background = dark ? Color(17, 29, 41) : Color(248, 250, 252);
        foreach (var group in snapshot.Nodes.Where(x => x.IsGroup).OrderBy(x => Depth(x.Id)))
        {
            var background = new Border { Width = group.Bounds.Width, Height = group.Bounds.Height, CornerRadius = new CornerRadius(8),
                BorderThickness = new Thickness(1), BorderBrush = stroke, Background = dark ? Color(33, 55, 74) : Color(232, 240, 248), IsHitTestVisible = false };
            Place(background, group.Bounds.X, group.Bounds.Y);
        }
        foreach (var edge in snapshot.Edges)
        {
            var geometry = Geometry(edge);
            var model = projection.Edges.Single(x => x.Id == edge.Id);
            var visible = new Microsoft.UI.Xaml.Shapes.Path { Data = geometry, Stroke = stroke, StrokeThickness = 1.5, IsHitTestVisible = false };
            if (model.Resolution is "candidate" or "unresolved" or "unknown") visible.StrokeDashArray = new DoubleCollection { 4, 3 };
            canvas.Children.Add(visible);
            edgePaths.Add(edge.Id, visible);
            var hit = new Microsoft.UI.Xaml.Shapes.Path { Data = Geometry(edge), Stroke = new SolidColorBrush(Colors.Transparent), StrokeThickness = 12 };
            hit.PointerPressed += (_, e) => { Select(edge.Id, true); e.Handled = true; }; canvas.Children.Add(hit);
            foreach (var arrow in new[] { edge.SourceArrow, edge.TargetArrow }.OfType<LayoutArrow>())
                canvas.Children.Add(new Polygon { Points = new PointCollection { P(arrow.Tip), P(arrow.Left), P(arrow.Right) }, Fill = stroke, IsHitTestVisible = false });
            if (edge.LabelBounds is { } label)
            {
                var text = new TextBlock { Text = $"{model.Kind} ({model.Count})", FontSize = 11, Foreground = foreground,
                    MaxWidth = label.Width, MaxHeight = label.Height, TextTrimming = TextTrimming.CharacterEllipsis,
                    IsHitTestVisible = false };
                Place(text, label.X, label.Y);
            }
        }
        foreach (var node in snapshot.Nodes.OrderBy(x => Depth(x.Id)))
        {
            var model = projection.Nodes.Single(x => x.Id == node.Id);
            var header = new StackPanel { Spacing = 2 };
            header.Children.Add(new TextBlock { Text = model.Original.Label, TextTrimming = TextTrimming.CharacterEllipsis, MaxWidth = node.Bounds.Width - 24, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            string state = document?.Repositories.FirstOrDefault(x => x.Id == node.Id)?.Status ?? model.Original.Kind;
            header.Children.Add(new TextBlock { Text = state + (model.Collapsed ? $" · {model.UnderlyingNodeIds.Length - 1} hidden" : ""), FontSize = 11 });
            var button = new Button { Content = header, Width = node.Bounds.Width, Height = node.IsGroup ? 56 : node.Bounds.Height,
                Background = dark ? Color(36, 68, 93) : Color(220, 235, 248), Foreground = foreground,
                HorizontalContentAlignment = HorizontalAlignment.Left, Padding = new Thickness(10, 6, 10, 6),
                BorderBrush = selection?.PresentationId == node.Id ? Brush("AccentFillColorDefaultBrush", Colors.DodgerBlue) : stroke,
                BorderThickness = new Thickness(selection?.PresentationId == node.Id ? 2 : 1) };
            AutomationProperties.SetName(button, $"{model.Original.Label}, {state}, {model.UnderlyingNodeIds.Length} underlying nodes, {model.InternalEdgeIds.Length} internal relationships");
            ToolTipService.SetToolTip(button, model.Original.Label);
            button.Click += (_, _) => Select(node.Id, false); nodeButtons.Add(node.Id, button); Place(button, node.Bounds.X, node.Bounds.Y);
        }
    }

    private void RefreshList()
    {
        if (projection is null) return;
        string query = search.Text.Trim();
        var items = projection.Nodes.Select(n => new Item(n.Id, false, $"{n.Original.Label} · {document?.Repositories.FirstOrDefault(x => x.Id == n.Id)?.Status ?? n.Original.Kind}"))
            .Concat(projection.Edges.Select(e => new Item(e.Id, true, $"{Label(e.Source)} → {Label(e.Target)} · {e.Kind} · {e.Resolution} · {e.Count}")))
            .Where(x => query.Length == 0 || x.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || x.Id.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
        syncing = true; alternatives.ItemsSource = items; alternatives.SelectedItem = items.FirstOrDefault(x => x.Id == selection?.PresentationId); syncing = false;
        AutomationProperties.SetName(alternatives, $"Architecture nodes and relationships. {items.Length} search matches. Search filters this list; graph shows the full selected projection.");
    }

    public void Select(string id, bool isEdge)
    {
        if (projection is null || document is null) return;
        var nodeIds = ImmutableArray<string>.Empty; var edgeIds = ImmutableArray<string>.Empty;
        if (isEdge)
        {
            var edge = projection.Edges.FirstOrDefault(x => x.Id == id); if (edge is null) return; edgeIds = edge.UnderlyingEdgeIds;
        }
        else
        {
            var node = projection.Nodes.FirstOrDefault(x => x.Id == id); if (node is null) return;
            nodeIds = node.UnderlyingNodeIds; edgeIds = node.InternalEdgeIds;
        }
        var refs = document.Nodes.Where(n => nodeIds.Contains(n.Id)).SelectMany(n => n.EvidenceRefs)
            .Concat(document.Edges.Where(e => edgeIds.Contains(e.Id)).SelectMany(e => e.EvidenceRefs)).Distinct(StringComparer.Ordinal).ToImmutableArray();
        selection = new(document.Context, id, isEdge, nodeIds, edgeIds, refs);
        var facts = document.Edges.Where(e => edgeIds.Contains(e.Id)).Select(e => $"{e.Id}\n{e.Source} → {e.Target}\n{e.Kind}; {e.Resolution}; {e.Basis}; confidence {e.Confidence ?? "unknown"}");
        details.Text = $"{(isEdge ? "Relationship" : "Node")}: {id}\nRun: {document.Context.RunId}\nGeneration: {document.Context.GenerationId}\nOriginal nodes: {nodeIds.Length}; original edges: {edgeIds.Length}\n" + string.Join("\n\n", facts)
            + $"\n\nEvidence IDs ({refs.Length}):\n" + string.Join("\n", refs) + "\n\n" + GraphDocument.AggregatePathWarning;
        toggle.IsEnabled = !isEdge && document.Nodes.Any(n => n.ParentId == id);
        toggle.Content = collapsed.Contains(id) ? "Expand selected group" : "Collapse selected group"; evidence.IsEnabled = refs.Length > 0;
        foreach (var (nodeId, button) in nodeButtons) { button.BorderThickness = new Thickness(nodeId == id ? 2 : 1); button.BorderBrush = nodeId == id ? Brush("AccentFillColorDefaultBrush", Colors.DodgerBlue) : Brush("TextFillColorSecondaryBrush", Colors.SlateGray); }
        foreach (var (edgeId, path) in edgePaths) { path.StrokeThickness = edgeId == id ? 3 : 1.5; path.Stroke = edgeId == id ? Brush("AccentFillColorDefaultBrush", Colors.DodgerBlue) : Brush("TextFillColorSecondaryBrush", Colors.SlateGray); }
        RefreshList(); SelectionChanged?.Invoke(this, selection);
    }

    public void Fit()
    {
        if (snapshot is null || viewport.ViewportWidth <= 0 || viewport.ViewportHeight <= 0) return;
        float scale = (float)Math.Clamp(Math.Min(viewport.ViewportWidth / snapshot.Bounds.Width, viewport.ViewportHeight / snapshot.Bounds.Height), 0.1, 1);
        viewport.ChangeView(0, 0, scale, true);
    }
    public void Zoom(float factor) => viewport.ChangeView(null, null, Math.Clamp(viewport.ZoomFactor * factor, viewport.MinZoomFactor, viewport.MaxZoomFactor), true);
    private string Label(string id) => projection?.Nodes.FirstOrDefault(x => x.Id == id)?.Original.Label ?? id;
    private int Depth(string id)
    {
        int depth = 0; var parents = projection!.Nodes.ToDictionary(x => x.Id, x => x.ParentId, StringComparer.Ordinal);
        for (string? p = parents[id]; p is not null; p = parents[p]) depth++;
        return depth;
    }
    private void Place(FrameworkElement element, double x, double y) { Canvas.SetLeft(element, x); Canvas.SetTop(element, y); canvas.Children.Add(element); }
    private static Point P(LayoutPoint p) => new(p.X, p.Y);
    private static PathGeometry Geometry(LayoutEdge edge)
    {
        var geometry = new PathGeometry();
        foreach (var segment in edge.Segments)
        {
            var figure = new PathFigure { StartPoint = P(segment.Start), IsClosed = false, IsFilled = false };
            if (segment.Kind == "cubic" && segment.Control1 is { } c1 && segment.Control2 is { } c2)
                figure.Segments.Add(new BezierSegment { Point1 = P(c1), Point2 = P(c2), Point3 = P(segment.End) });
            else figure.Segments.Add(new LineSegment { Point = P(segment.End) });
            geometry.Figures.Add(figure);
        }
        return geometry;
    }
    private static AppBarButton Command(string text, Action click, Symbol icon)
    {
        var button = new AppBarButton { Label = text, Icon = new SymbolIcon(icon) }; AutomationProperties.SetName(button, text);
        button.Click += (_, _) => click(); return button;
    }
    private static Brush Brush(string resource, Windows.UI.Color fallback) => Application.Current.Resources.TryGetValue(resource, out var value) && value is Brush brush ? brush : new SolidColorBrush(fallback);
    private sealed record Item(string Id, bool IsEdge, string Name) { public override string ToString() => Name; }
    public async ValueTask DisposeAsync() { disposed = true; resumeLayoutOnLoad = false; requestVersion++; await layouts.DisposeAsync(); }
}
