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
        panel.Children.Add(buttons); panel.Children.Add(watch); panel.Children.Add(watchNotice);
        panel.Children.Add(new TextBlock { Text = "Watching requests full fleet rescans. Unsupported roots require manual rescans.", TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(repositories); panel.Children.Add(status); panel.Children.Add(childStatuses); panel.Children.Add(results);
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Refresh();
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
        if (renderedGeneration != workspace.Active) { results.Children.Clear(); renderedGeneration = workspace.Active; }
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
        renderedGeneration = generation;
        results.Children.Clear();
        foreach (var repo in summary.Repositories)
        {
            var row = new StackPanel { Spacing = 4 };
            row.Children.Add(new TextBlock { Text = $"{repo.RepositoryId} · {repo.Findings?.ToString() ?? "unknown"} supplied findings\n{repo.Root}", TextWrapping = TextWrapping.Wrap });
            var open = new Button { Content = "Open verified repository result", IsEnabled = workspace.Open(repo.RepositoryId) != null };
            open.Click += (_,_) => { if (workspace.Active == generation && workspace.Open(repo.RepositoryId) is { } request) OpenRepositoryRequested?.Invoke(request); };
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
