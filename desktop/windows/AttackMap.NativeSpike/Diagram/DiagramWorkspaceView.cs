using AttackMap.GraphExplorer;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

/// <summary>One selected report, with a canonical graph and the original inert artifacts.</summary>
public sealed class DiagramWorkspaceView : UserControl
{
    private readonly DiagramView legacy = new();
    private readonly FleetGraphPane architecture = new(singleReport: true);
    private readonly ComboBox view = new() { ItemsSource = new[] { "Interactive architecture", "Report diagrams and summary" }, SelectedIndex = 0 };
    private readonly TextBlock notice = new() { Text = "Open a completed scan to explore its architecture.", TextWrapping = TextWrapping.Wrap, MaxLines = 2, TextTrimming = TextTrimming.CharacterEllipsis };
    private ExportSelection? selection;
    private GraphDocument? document;
    private GraphContext? boundContext;
    private Task loading = Task.CompletedTask;
    private long revision;
    private long graphLoadCount;
    private bool stopped;
    private bool activationStarting;
    private bool? effectiveVisibility;

    public Func<ExportSelection, Task<GraphDocument>>? GraphLoader { get; set; }
    internal long GraphLoadCount => graphLoadCount;
    internal long LegacySelectionLoadCount => legacy.SelectionLoadCount;
    internal long InteractiveInitializationAttemptCount => architecture.InteractiveInitializationAttemptCount;
    internal object ActivationDiagnostics => UiActivation.Describe(this);
    internal delegate void DiagramActivationEvent(string kind, string viewKind, long selectionRevision, Exception? error = null);
    internal event DiagramActivationEvent? ActivationEvent;
    public event Action<string>? ExportTextRequested;
    public event Action<FleetGraphExport>? GraphExportRequested;
    public event Action<FleetGraphSourceRequest>? GraphSourceRequested;
    public event Action? FleetRequested;
    internal GraphDocument? CurrentGraph => document;
    internal FleetGraphPane GraphPane => architecture;

    public DiagramWorkspaceView()
    {
        var root = new Grid { RowSpacing = 8, Padding = new Thickness(16, 8, 16, 0) };
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) });
        var commands = new Grid { ColumnSpacing = 12 };
        commands.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        commands.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        view.MaxWidth = 360; view.HorizontalAlignment = HorizontalAlignment.Stretch;
        var fleet = new Button { Content = new TextBlock { Text = "Open Fleet explorer", TextWrapping = TextWrapping.Wrap, MaxWidth = 160 }, VerticalAlignment = VerticalAlignment.Bottom };
        fleet.Click += (_, _) => FleetRequested?.Invoke();
        Grid.SetColumn(fleet, 1);
        commands.Children.Add(view); commands.Children.Add(fleet); root.Children.Add(commands);
        Grid.SetRow(notice, 1); root.Children.Add(notice);
        Grid.SetRow(architecture, 2); Grid.SetRow(legacy, 2);
        root.Children.Add(architecture); root.Children.Add(legacy); legacy.Visibility = Visibility.Collapsed;
        Content = root;
        AutomationProperties.SetName(view, "Choose interactive architecture or original report diagrams and summary");
        view.SelectionChanged += async (_, _) =>
        {
            bool original = view.SelectedIndex == 1;
            legacy.Visibility = original ? Visibility.Visible : Visibility.Collapsed;
            architecture.Visibility = original || document == null ? Visibility.Collapsed : Visibility.Visible;
            notice.Visibility = original ? Visibility.Collapsed : Visibility.Visible;
            if (!original) await ActivateInteractive();
        };
        LayoutUpdated += OnLayoutUpdated;
        legacy.ExportTextRequested += text => ExportTextRequested?.Invoke(text);
        architecture.ExportRequested += request => { if (document?.Context == request.Context) GraphExportRequested?.Invoke(request); };
        architecture.OpenEvidenceSourceRequested += request => { if (document?.Context == request.Context) GraphSourceRequested?.Invoke(request); };
    }

    private async void OnLayoutUpdated(object? sender, object args)
    {
        bool visible = UiActivation.IsEffectivelyVisible(this);
        if (effectiveVisibility == visible) return;
        effectiveVisibility = visible;
        if (visible) await ActivateInteractive();
    }

    public async Task SetSelection(ExportSelection? value)
    {
        if (stopped) return;
        ++revision; selection = value; document = null; boundContext = null; architecture.Clear(); loading = Task.CompletedTask;
        notice.MaxLines = 2;
        notice.Text = value?.Verified == true ? "Select Interactive architecture to explore this captured report." : "Open a completed scan with a verified manifest to explore its architecture.";
        await legacy.SetSelection(value);
        await ActivateInteractive();
    }

    public Task ActivateInteractive()
    {
        if (stopped || view.SelectedIndex != 0 || selection?.Verified != true || GraphLoader == null) return Task.CompletedTask;
        if (!UiActivation.IsEffectivelyVisible(this))
        {
            ActivationEvent?.Invoke("activation-suppressed-hidden", "interactive", revision);
            return Task.CompletedTask;
        }
        if (activationStarting || !loading.IsCompleted) return loading;
        activationStarting = true;
        try
        {
            if (document is { } current)
            {
                if (boundContext == current.Context) return Task.CompletedTask;
                return loading = BindGraph(current, revision);
            }
            return loading = LoadGraph(selection, revision);
        }
        finally { activationStarting = false; }
    }

    private async Task LoadGraph(ExportSelection selected, long captured)
    {
        notice.Text = "Loading architecture from the selected report…";
        try
        {
            ActivationEvent?.Invoke("activation-attempt", "interactive", captured);
            ++graphLoadCount;
            var graph = await GraphLoader!(selected);
            if (stopped || captured != revision || selection != selected) return;
            document = graph;
            if (UiActivation.IsEffectivelyVisible(this)) await BindGraph(graph, captured);
            else ActivationEvent?.Invoke("activation-suppressed-hidden", "interactive", captured);
        }
        catch (Exception error)
        {
            if (!stopped && captured == revision && selection == selected)
            {
                ActivationEvent?.Invoke("activation-failed", "interactive", captured, error);
                document = null; boundContext = null; architecture.Clear();
                notice.MaxLines = 0;
                notice.Text = "Interactive architecture unavailable: " + error.Message + " Choose Report diagrams and summary to inspect the original artifacts.";
            }
        }
    }

    private async Task BindGraph(GraphDocument graph, long captured)
    {
        if (stopped || captured != revision || selection == null || document != graph || !UiActivation.IsEffectivelyVisible(this)) return;
        architecture.Visibility = Visibility.Visible;
        await architecture.SetDocumentAsync(graph);
        if (stopped || captured != revision || document != graph || !UiActivation.IsEffectivelyVisible(this)) return;
        boundContext = graph.Context;
        architecture.Visibility = Visibility.Visible;
        notice.Text = $"Captured run {graph.Context.RunId}. {graph.Nodes.Length} nodes; {graph.Edges.Length} original relationships. Containment shows component ownership; it does not imply service communication.";
        ToolTipService.SetToolTip(notice, notice.Text); AutomationProperties.SetName(notice, notice.Text);
        ActivationEvent?.Invoke("activation-completed", "interactive", captured);
    }

    internal void SelectLegacyView() => view.SelectedIndex = 1;
    internal void SelectInteractiveView() => view.SelectedIndex = 0;
    public void Stop()
    {
        if (stopped) return;
        stopped = true; ++revision; selection = null; document = null; boundContext = null;
        LayoutUpdated -= OnLayoutUpdated;
        legacy.Stop(); _ = architecture.DisposeAsync();
    }
}
