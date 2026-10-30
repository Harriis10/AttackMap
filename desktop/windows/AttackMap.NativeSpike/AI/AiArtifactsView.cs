using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

/// <summary>Inert selected-run AI text; no provider dispatch, links, or source editing.</summary>
public sealed partial class AiArtifactsView : UserControl
{
    private readonly AiArtifactWorkspace workspace = new();
    private readonly ComboBox modes = new() { Header = "Saved AI section", ItemsSource = AiArtifactProjection.Modes, SelectedIndex = 0 };
    private readonly TextBlock status = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private readonly MarkdownView prose = new();
    private readonly TextBlock details = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private readonly TextBox metadata = new() { Header = "Complete supplied metadata (read only)", IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap };
    private AiArtifactSnapshot? snapshot;
    private ExportSelection? currentSelection;
    private string currentMode = "review";
    private bool synchronizingMode;
    private long revision;
    private bool stopped;
    private Task selectionTask = Task.CompletedTask;
    public Task SelectionSettled => selectionTask;
    internal string CurrentMode => currentMode;
    internal AiArtifactSnapshot? CurrentSnapshot => snapshot;
    public Task<AiArtifactPage?> SelectMode(string mode)
    {
        if (!AiArtifactProjection.Modes.Contains(mode, StringComparer.Ordinal)) throw new ArgumentException("Unknown AI mode.", nameof(mode));
        if (stopped) return Task.FromResult<AiArtifactPage?>(null);
        currentMode = mode;
        SetSelectedMode();
        Task pending = BeginLoad();
        long captured = revision;
        return FinishModeSelection(pending, captured, mode);
    }
    private async Task<AiArtifactPage?> FinishModeSelection(Task pending, long captured, string mode)
    {
        await pending;
        if (stopped || captured != revision || pending != selectionTask || snapshot == null) return null;
        return snapshot.Pages.Single(page => page.Mode == mode);
    }
    public AiArtifactsView()
    {
        var panel = new StackPanel { Spacing = 12 };
        panel.Children.Add(modes); panel.Children.Add(status); panel.Children.Add(prose);
        var technical = new StackPanel { Spacing = 12 }; technical.Children.Add(details); technical.Children.Add(metadata);
        panel.Children.Add(new Expander { Header = "Evidence checks and complete metadata", IsExpanded = false, Content = technical, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch });
        Content = panel;
        AutomationProperties.SetName(prose, "Saved selected-generation AI output; model judgement only");
        modes.SelectionChanged += (_, _) =>
        {
            if (!synchronizingMode && modes.SelectedItem?.ToString() is { } mode) _ = SelectMode(mode);
        };
        Clear();
    }
    /// <summary>Terminal invalidation for Window.Closed; deliberately touches no XAML objects.</summary>
    public void Stop() { stopped = true; revision++; workspace.Stop(); snapshot = null; currentSelection = null; }
    public void Clear() { if (stopped) return; currentSelection = null; ResetDisplay(); }
    private void ResetDisplay()
    {
        revision++; workspace.Cancel(); snapshot = null;
        prose.Text = metadata.Text = details.Text = "";
        status.Text = "No saved AI output selected. Displaying saved output sends no provider request.";
    }
    public Task SetSelection(ExportSelection? selection)
    {
        if (stopped) return Task.CompletedTask;
        currentSelection = selection;
        SetSelectedMode();
        return BeginLoad();
    }
    private Task BeginLoad()
    {
        if (stopped) return selectionTask;
        var selected = currentSelection;
        string mode = currentMode;
        ResetDisplay();
        workspace.Select(selected);
        return selectionTask = LoadSelection(selected, mode, revision);
    }
    private async Task LoadSelection(ExportSelection? selection, string mode, long captured)
    {
        if (stopped || captured != revision) return;
        status.Text = "Reading selected generation AI artifacts…";
        try
        {
            var result = await workspace.Load(mode);
            if (stopped || captured != revision || result == null) return;
            snapshot = result; Show();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or ArgumentException or InvalidOperationException)
        {
            if (!stopped && captured == revision)
            {
                prose.Text = metadata.Text = details.Text = "";
                status.Text = "AI output unavailable: selected files changed, metadata is invalid, or the preview limit was exceeded. Reopen the report. No provider request was sent.";
            }
        }
    }
    private void SetSelectedMode()
    {
        synchronizingMode = true;
        try { modes.SelectedItem = currentMode; }
        finally { synchronizingMode = false; }
    }
    private void Show()
    {
        if (stopped || snapshot == null) return;
        var page = snapshot.Pages.Single(p => p.Mode == currentMode);
        status.Text = $"Selected generation: {snapshot.Generation}\n{page.Summary}";
        prose.Text = page.Markdown; details.Text = page.Notice; metadata.Text = page.Metadata;
    }
}
