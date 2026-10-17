using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using System.Text.Json;
using Windows.Storage.Pickers;

namespace AttackMap.NativeSpike;

public sealed record ComparisonRequest(string BaselinePath, string CurrentPath);
public sealed record RetentionPinRequest(string RunId, bool Pin);

/// <summary>Native selection/presentation only; the shared core owns comparison semantics.</summary>
public sealed class HistoryComparisonView : UserControl
{
    public event Action<ComparisonRequest>? CompareRequested;
    public event Action? GenerationsRequested;
    public event Action<RetentionPinRequest>? PinRequested;
    public event Action? DiagnosticsExportRequested;
    public string SummaryText => summary.Text;
    public int ResultCount => results.Items.Count;
    public int GenerationCount => generations.Items.Count;
    public string ComparisonDetailText => detail.Text;
    public string ComparisonNotesText => notes.Text;
    public bool ChooseBaselineEnabled => chooseBaseline.IsEnabled;
    public bool CompareEnabled => compare.IsEnabled;
    public string RetentionSummaryText => retentionSummary.Text;
    public bool PinToggleEnabled => togglePin.IsEnabled;
    public string PinToggleText => togglePin.Content?.ToString() ?? "";
    public void SelectGenerationForSmoke(int index) => generations.SelectedIndex = index;
    public nint OwnerWindowHandle { get; set; }

    private readonly TextBlock currentLabel = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock baselineLabel = new() { Text = "Choose a baseline report.", TextWrapping = TextWrapping.Wrap };
    private readonly Button chooseBaseline = new() { Content = "Choose baseline report…" };
    private readonly Button compare = new() { Content = "Compare reports", IsEnabled = false };
    private readonly TextBlock summary = new() { Text = "Choose a baseline, then compare.", TextWrapping = TextWrapping.Wrap };
    private readonly ListView results = new() { Height = 240, FontSize = 14, DisplayMemberPath = nameof(ComparisonRow.Label), SelectionMode = ListViewSelectionMode.Single };
    private readonly TextBlock detail = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private readonly TextBlock selectedChange = new() { Text = "Selected change", FontSize = 14, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, Visibility = Visibility.Collapsed };
    private readonly ScrollViewer detailSection = new() { MaxHeight = 280, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Visibility = Visibility.Collapsed };
    private readonly TextBlock notes = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private readonly Button refreshGenerations = new() { Content = "Refresh generations" };
    private readonly Button togglePin = new() { Content = "Pin selected", IsEnabled = false };
    private readonly Button exportDiagnostics = new() { Content = "Export diagnostics…" };
    private readonly ListView generations = new()
    {
        Height = 180, FontSize = 14, SelectionMode = ListViewSelectionMode.Single,
        ItemTemplate = GenerationItemTemplate(),
    };
    private readonly TextBlock retentionSummary = new() { Text = "Generations are kept per repository; the engine retains the newest completed runs under a storage budget. Pinned and current runs are never removed.", TextWrapping = TextWrapping.Wrap };
    private bool retentionBusy;
    private string currentPath = "";
    private string baselinePath = "";
    private bool busy;
    public string BaselineReportPath
    {
        get => baselinePath;
        set
        {
            string next = value ?? "";
            if (string.Equals(baselinePath, next, StringComparison.OrdinalIgnoreCase)) return;
            baselinePath = next;
            baselineLabel.Text = baselinePath.Length == 0 ? "Choose a baseline report." : $"Baseline report: {baselinePath}";
            results.ItemsSource = null;
            SetRowsVisible(false);
            detail.Text = "";
            notes.Text = "";
            summary.Text = "The baseline report changed. Compare again for the selected reports.";
            UpdateActions();
        }
    }

    public string CurrentReportPath
    {
        get => currentPath;
        set
        {
            if (currentPath == value) return;
            currentPath = value ?? "";
            currentLabel.Text = currentPath.Length == 0 ? "No current report is displayed." : $"Displayed current report: {currentPath}";
            results.ItemsSource = null;
            SetRowsVisible(false);
            detail.Text = "";
            notes.Text = "";
            summary.Text = "The displayed report changed. Compare again to update history.";
            UpdateActions();
        }
    }

    public HistoryComparisonView()
    {
        AutomationProperties.SetName(chooseBaseline, "Choose comparison baseline report");
        AutomationProperties.SetAutomationId(chooseBaseline, "HistoryCompareBaseline");
        AutomationProperties.SetName(compare, "Compare baseline with displayed current report");
        AutomationProperties.SetAutomationId(compare, "HistoryCompare");
        AutomationProperties.SetName(results, "Finding comparison results from AttackMap core");
        AutomationProperties.SetAutomationId(results, "HistoryCompareResults");
        AutomationProperties.SetName(detail, "Selected comparison evidence and recommendation");
        chooseBaseline.Click += ChooseBaseline;
        compare.Click += (_, _) =>
        {
            if (CompareRequested is null)
            {
                SetError("Comparison is unavailable. Connect the shared core action runner and try again.");
                return;
            }
            SetBusy(true);
            CompareRequested(new ComparisonRequest(baselinePath, currentPath));
        };
        results.SelectionChanged += (_, _) => ShowDetail();
        results.Visibility = Visibility.Collapsed;
        detailSection.Content = detail;
        AutomationProperties.SetName(refreshGenerations, "Refresh the retained generation list for the selected repository");
        AutomationProperties.SetAutomationId(refreshGenerations, "HistoryRefreshGenerations");
        AutomationProperties.SetName(togglePin, "Pin or unpin the selected generation so cleanup always keeps it");
        AutomationProperties.SetAutomationId(togglePin, "HistoryToggleGenerationPin");
        AutomationProperties.SetName(exportDiagnostics, "Export a redacted diagnostic bundle for this repository's output base");
        AutomationProperties.SetAutomationId(exportDiagnostics, "HistoryExportDiagnostics");
        AutomationProperties.SetName(generations, "Retained report generations for the selected repository");
        AutomationProperties.SetAutomationId(generations, "HistoryGenerationList");
        refreshGenerations.Click += (_, _) => RequestGenerations();
        exportDiagnostics.Click += (_, _) =>
        {
            if (DiagnosticsExportRequested is null) SetRetentionStatus("Diagnostics export is unavailable without the shared core action runner.");
            else DiagnosticsExportRequested();
        };
        togglePin.Click += (_, _) =>
        {
            if (generations.SelectedItem is GenerationRow row && PinRequested is not null)
                PinRequested(new RetentionPinRequest(row.RunId, !row.Pinned));
        };
        generations.SelectionChanged += (_, _) => UpdateRetentionActions();
        foreach (var text in new[] { currentLabel, baselineLabel, summary, detail, notes, retentionSummary }) text.FontSize = 14;
        currentLabel.IsTextSelectionEnabled = baselineLabel.IsTextSelectionEnabled = true;
        Content = new StackPanel
        {
            Spacing = 12, MaxWidth = 1080, HorizontalAlignment = HorizontalAlignment.Stretch,
            Children =
            {
                new TextBlock { Text = "Compare runs", FontSize = 20, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                new TextBlock { Text = "Compare a saved baseline with your displayed report.", FontSize = 14, TextWrapping = TextWrapping.Wrap },
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { chooseBaseline, compare } },
                new Expander { Header = "Selected report files", HorizontalAlignment = HorizontalAlignment.Stretch,
                    Content = new StackPanel { Spacing = 8, Children = { currentLabel, baselineLabel } } },
                summary, results,
                selectedChange, detailSection,
                new Expander { Header = "Coverage and comparison notes", HorizontalAlignment = HorizontalAlignment.Stretch,
                    Content = new ScrollViewer { MaxHeight = 220, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Content = notes } },
                new TextBlock { Text = "Generation retention", FontSize = 20, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
                retentionSummary,
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { refreshGenerations, togglePin, exportDiagnostics } },
                generations,
            }
        };
        currentLabel.Text = "No current report is displayed.";
    }

    private async void ChooseBaseline(object sender, RoutedEventArgs args)
    {
        try
        {
            if (OwnerWindowHandle == 0)
            {
                SetError("The report picker has no owner window. Reopen History and try again.");
                return;
            }
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".json");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, OwnerWindowHandle);
            var selected = await picker.PickSingleFileAsync();
            if (selected is null) return;
            BaselineReportPath = selected.Path;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            SetError("Baseline selection failed. Choose a readable canonical report and try again.");
        }
    }

    public void SetBusy(bool value)
    {
        busy = value;
        if (value) summary.Text = "Comparing selected report files in the shared core…";
        UpdateActions();
    }

    public void SetError(string message)
    {
        SetBusy(false);
        summary.Text = message;
        results.ItemsSource = null;
            SetRowsVisible(false);
        detail.Text = "";
        notes.Text = "";
    }

    public void SetResult(JsonElement result)
    {
        if (Text(result, "comparison_version") != "1.0")
        {
            SetError("Unsupported comparison version. Update the app and engine, then compare again.");
            return;
        }
        if (!result.TryGetProperty("current", out var current) ||
            !string.Equals(Text(current, "report_path"), currentPath, StringComparison.OrdinalIgnoreCase) ||
            !result.TryGetProperty("baseline", out var baseline) ||
            !string.Equals(Text(baseline, "report_path"), baselinePath, StringComparison.OrdinalIgnoreCase))
        {
            SetError("Selected reports changed while comparing. Compare again for the displayed report.");
            return;
        }
        if (!result.TryGetProperty("changes", out var changes) || changes.ValueKind != JsonValueKind.Object)
        {
            SetError("Comparison results are incomplete. Retry the shared core action.");
            return;
        }
        var groups = new (string Key, string Label)[]
        {
            ("new", "New"), ("new_instances", "New instance"), ("persisted", "Persisted"),
            ("resolved", "Resolved"), ("newly_suppressed", "Newly suppressed"),
            ("resolution_uncertain", "Resolution uncertain due to coverage"),
        };
        var rows = new List<ComparisonRow>();
        foreach (var (key, label) in groups)
            if (changes.TryGetProperty(key, out var entries) && entries.ValueKind == JsonValueKind.Array)
                foreach (var entry in entries.EnumerateArray())
                    rows.Add(new ComparisonRow($"{label} · {Text(entry, "title")}", label, entry.Clone()));
        results.ItemsSource = rows;
        SetRowsVisible(rows.Count > 0);
        summary.Text = result.TryGetProperty("counts", out var counts) ? $"Core comparison counts: {counts}" : "Core comparison completed; counts unavailable.";
        notes.Text = result.TryGetProperty("notes", out var suppliedNotes) && suppliedNotes.ValueKind == JsonValueKind.Array
            ? string.Join("\n", suppliedNotes.EnumerateArray().Select(value => value.ToString())) : "Coverage notes unavailable.";
        SetBusy(false);
        if (rows.Count > 0) results.SelectedIndex = 0;
        else detail.Text = "No comparison entries were supplied.";
    }

    private static Microsoft.UI.Xaml.DataTemplate GenerationItemTemplate()
    {
        // Explicit template: the code-created ListView never rendered
        // DisplayMemberPath content in captures.
        var xaml = "<DataTemplate xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" " +
                   "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\">" +
                   "<TextBlock Text=\"{Binding Label}\" TextWrapping=\"Wrap\" Margin=\"0,4\"/>" +
                   "</DataTemplate>";
        return (Microsoft.UI.Xaml.DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load(xaml);
    }

    private void SetRowsVisible(bool value)
    {
        var visibility = value ? Visibility.Visible : Visibility.Collapsed;
        results.Visibility = selectedChange.Visibility = detailSection.Visibility = visibility;
    }

    public void RequestGenerations()
    {
        if (GenerationsRequested is null)
        {
            SetRetentionStatus("Generation listing is unavailable without the shared core action runner.");
            return;
        }
        SetRetentionBusy(true);
        GenerationsRequested();
    }

    public void SetGenerations(JsonElement payload)
    {
        if (Text(payload, "export_type") != "attackmap_diagnostic_export")
        {
            SetRetentionError("Unsupported diagnostics version. Update the app and engine, then refresh again.");
            return;
        }
        var rows = new List<GenerationRow>();
        if (payload.TryGetProperty("generations", out var entries) && entries.ValueKind == JsonValueKind.Array)
            foreach (var entry in entries.EnumerateArray())
            {
                string runId = Text(entry, "run_id");
                if (runId == "unknown / not supplied") continue;
                bool isCurrent = entry.TryGetProperty("current", out var current) && current.ValueKind == JsonValueKind.True;
                bool isPinned = entry.TryGetProperty("pinned", out var pinned) && pinned.ValueKind == JsonValueKind.True;
                long sizeBytes = entry.TryGetProperty("size_bytes", out var size) && size.ValueKind == JsonValueKind.Number ? size.GetInt64() : -1;
                rows.Add(new GenerationRow(runId, isPinned, isCurrent,
                    $"{runId} · {Text(entry, "created_at")} · {(sizeBytes >= 0 ? string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0:F1} MiB", sizeBytes / 1048576.0) : "size unknown")}{(isCurrent ? " · current" : "")}{(isPinned ? " · pinned" : "")}"));
            }
        generations.ItemsSource = rows;
        string posture = "retention summary unavailable";
        if (payload.TryGetProperty("retention", out var retention) && retention.ValueKind == JsonValueKind.Object)
        {
            posture = retention.TryGetProperty("mode", out var mode) && mode.GetString() == "dry_run_summary"
                ? string.Format(System.Globalization.CultureInfo.InvariantCulture,
                    "keeping the newest {0} completed runs under a {1:F1} GiB soft budget",
                    Text(retention, "keep_completed"), Number(retention, "soft_budget_bytes") / 1073741824.0)
                : "retention summary unavailable";
            if (retention.TryGetProperty("budget_overage_bytes", out var overage) && overage.ValueKind == JsonValueKind.Number && overage.GetInt64() > 0)
                posture += string.Format(System.Globalization.CultureInfo.InvariantCulture, "; protected runs exceed the budget by {0:F1} MiB", overage.GetInt64() / 1048576.0);
        }
        retentionSummary.Text = rows.Count == 0
            ? "No completed generations are retained for this repository yet. Run a scan first."
            : $"{rows.Count} retained generation(s) for this repository; {posture}. Cleanup never removes pinned or current runs.";
        SetRetentionBusy(false);
        UpdateRetentionActions();
    }

    public void SetRetentionBusy(bool value)
    {
        retentionBusy = value;
        if (value) retentionSummary.Text = "Loading retained generations from the shared core…";
        UpdateRetentionActions();
    }

    public void SetRetentionError(string message)
    {
        retentionSummary.Text = message;
        generations.ItemsSource = null;
        SetRetentionBusy(false);
    }

    public void SetRetentionStatus(string message) => retentionSummary.Text = message;

    private void UpdateRetentionActions()
    {
        refreshGenerations.IsEnabled = !retentionBusy;
        exportDiagnostics.IsEnabled = !retentionBusy;
        if (generations.SelectedItem is GenerationRow row)
        {
            togglePin.IsEnabled = !retentionBusy && !row.Current;
            togglePin.Content = row.Pinned ? "Unpin selected" : "Pin selected";
        }
        else
        {
            togglePin.IsEnabled = false;
            togglePin.Content = "Pin selected";
        }
    }

    private static long Number(JsonElement value, string field) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(field, out var found) && found.ValueKind == JsonValueKind.Number ? found.GetInt64() : 0;

    private void UpdateActions()
    {
        chooseBaseline.IsEnabled = !busy;
        compare.IsEnabled = !busy && currentPath.Length > 0 && baselinePath.Length > 0;
    }

    private void ShowDetail()
    {
        if (results.SelectedItem is not ComparisonRow row) return;
        var entry = row.Entry;
        detail.Text = $"{row.Category}: {Text(entry, "title")}\nID: {Text(entry, "id")}\n" +
            $"Evidence basis: {Text(entry, "evidence_basis")}\nConfidence: {Text(entry, "confidence")}\n" +
            $"Engine priority score: {Text(entry, "score")}\nPriority factors: {Text(entry, "priority_factors")}\n" +
            $"Locations: {Text(entry, "locations")}\nEvidence: {Text(entry, "evidence")}\n" +
            $"Observed controls: {Text(entry, "observed_controls")}\nTrust chain: {Text(entry, "code_flows")}\n" +
            $"Supplied uncertainty: {Text(entry, "uncertainty")}\n" +
            $"Recommendation: {Text(entry, "mitigation")}\nSuppression reason: {Text(entry, "reason")}\n" +
            $"Resolution uncertainty: {Text(entry, "resolution_reason")}\n" +
            $"New instance locations: {Text(entry, "new_instance_locations")}";
    }

    private static string Text(JsonElement value, string field) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(field, out var found) && found.ValueKind != JsonValueKind.Null
            ? found.ToString() : "unknown / not supplied";

    private sealed record ComparisonRow(string Label, string Category, JsonElement Entry);
    public sealed record GenerationRow(string RunId, bool Pinned, bool Current, string Label);
}
