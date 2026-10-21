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
    private readonly TextBlock prose = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private readonly TextBox metadata = new() { Header = "Complete supplied metadata (read only)", IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap };
    private AiArtifactSnapshot? snapshot;
    private long revision;
    private bool stopped;
    private Task selectionTask = Task.CompletedTask;
    public Task SelectionSettled => selectionTask;
    public async Task<AiArtifactPage?> SelectMode(string mode)
    {
        if (!AiArtifactProjection.Modes.Contains(mode)) throw new ArgumentException("Unknown AI mode.", nameof(mode));
        if (stopped) return null;
        long captured = revision; Task pending = selectionTask;
        await pending;
        if (stopped || captured != revision || pending != selectionTask || snapshot == null) return null;
        modes.SelectedItem = mode; Show();
        return snapshot.Pages.Single(page => page.Mode == mode);
    }
    public AiArtifactsView()
    {
        var panel = new StackPanel { Spacing = 12 };
        panel.Children.Add(modes); panel.Children.Add(status); panel.Children.Add(prose);
        panel.Children.Add(new Expander { Header = "Inspect metadata", Content = metadata, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch });
        Content = panel;
        AutomationProperties.SetName(prose, "Saved selected-generation AI output; model judgement only");
        modes.SelectionChanged += (_, _) => Show(); Clear();
    }
    /// <summary>Terminal invalidation for Window.Closed; deliberately touches no XAML objects.</summary>
    public void Stop() { stopped = true; revision++; workspace.Stop(); snapshot = null; }
    public void Clear() { if (stopped) return; revision++; workspace.Cancel(); snapshot = null; prose.Text = metadata.Text = ""; status.Text = "No saved AI output selected. Displaying saved output sends no provider request."; }
    public Task SetSelection(ExportSelection? selection) => selectionTask = LoadSelection(selection);
    private async Task LoadSelection(ExportSelection? selection)
    {
        if (stopped) return;
        Clear(); long captured = revision; workspace.Select(selection);
        if (stopped || captured != revision) return;
        status.Text = "Reading selected generation AI artifacts…";
        try { var result = await workspace.Load(); if (stopped || captured != revision || result == null) return; snapshot = result; Show(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or ArgumentException or InvalidOperationException)
        { if (!stopped && captured == revision) { prose.Text = metadata.Text = ""; status.Text = "AI output unavailable: selected files changed, metadata is invalid, or the preview limit was exceeded. Reopen the report. No provider request was sent."; } }
    }
    private void Show()
    {
        if (stopped || snapshot == null) return;
        var page = snapshot.Pages.Single(p => p.Mode == (modes.SelectedItem?.ToString() ?? "review"));
        status.Text = $"Selected generation: {snapshot.Generation}\n{page.Notice}"; prose.Text = page.Markdown; metadata.Text = page.Metadata;
    }
}
