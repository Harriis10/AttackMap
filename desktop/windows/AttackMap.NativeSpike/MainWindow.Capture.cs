using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private async void CaptureStartupLoaded(object sender, RoutedEventArgs args)
    {
        var root = (FrameworkElement)Content;
        root.Loaded -= CaptureStartupLoaded;
        var arguments = Environment.GetCommandLineArgs();
        int index = Array.IndexOf(arguments, "--capture-startup-smoke");
        if (index < 0 || index + 1 >= arguments.Length) { Close(); return; }
        string directory = Path.GetFullPath(arguments[index + 1]);
        var captures = new List<CaptureMetadata>();
        try
        {
            if (!Directory.Exists(directory)) throw new DirectoryNotFoundException("Create a fresh QA directory first.");
            foreach (var size in new[] { (Width: 1024, Height: 700), (Width: 1600, Height: 1000) })
            foreach (var theme in new[] { ElementTheme.Light, ElementTheme.Dark })
            {
                root.RequestedTheme = theme;
                double scale = root.XamlRoot.RasterizationScale;
                AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(size.Width * scale), (int)Math.Round(size.Height * scale)));
                captures.Add(await CaptureStrict(root, Path.Combine(directory, $"{size.Width}x{size.Height}-{theme}-StartWorkspace.png")));
            }
            File.WriteAllText(Path.Combine(directory, "startup-capture-manifest.json"), JsonSerializer.Serialize(new { captures, overviewVisible = OverviewPanel.Visibility == Visibility.Visible, findingsVisible = FindingsPanel.Visibility == Visibility.Visible, selected = (Navigation.SelectedItem as NavigationViewItem)?.Content?.ToString(), initialViewPassed = OverviewPanel.Visibility == Visibility.Visible && FindingsPanel.Visibility == Visibility.Collapsed && Navigation.SelectedItem == Navigation.MenuItems[0], personalSettingsRead = false, acceptedC25 = false }, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception error)
        {
            if (Directory.Exists(directory)) File.WriteAllText(Path.Combine(directory, "startup-capture-failure.json"), JsonSerializer.Serialize(new { error = error.ToString(), completed = captures.Count }));
        }
        finally { Close(); }
    }

    private async void CaptureRetentionLoaded(object sender, RoutedEventArgs args)
    {
        var root = (FrameworkElement)Content;
        root.Loaded -= CaptureRetentionLoaded;
        var arguments = Environment.GetCommandLineArgs();
        int index = Array.IndexOf(arguments, "--capture-retention");
        if (index < 0 || index + 1 >= arguments.Length) { Close(); return; }
        string directory = Path.GetFullPath(arguments[index + 1]);
        var captures = new List<CaptureMetadata>();
        try
        {
            if (!Directory.Exists(directory)) throw new DirectoryNotFoundException("Create a fresh QA directory first.");
            var payload = JsonSerializer.SerializeToElement(new
            {
                schema_version = "1.0",
                export_type = "attackmap_diagnostic_export",
                current_generation = new { generation = "20261016T190000-demo", state = "valid" },
                pinned = new[] { "20261016T180000-demo" },
                retention = new { mode = "dry_run_summary", keep_completed = 20, soft_budget_bytes = 2147483648L, budget_overage_bytes = 0L },
                generations = new object[]
                {
                    new { run_id = "20261016T190000-demo", created_at = "2026-10-16T19:00:00+00:00", size_bytes = 33_554_432L, current = true, pinned = false },
                    new { run_id = "20261016T180000-demo", created_at = "2026-10-16T18:00:00+00:00", size_bytes = 32_501_158L, current = false, pinned = true },
                    new { run_id = "20261016T170000-demo", created_at = "2026-10-16T17:00:00+00:00", size_bytes = 32_112_021L, current = false, pinned = false },
                },
            });
            // Also populate the comparison list to compare both code-created
            // ListViews in the same capture.
            string baseline = Path.Combine(Path.GetTempPath(), "retention-capture-baseline.json");
            string currentReport = Path.Combine(Path.GetTempPath(), "retention-capture-current.json");
            var comparison = JsonSerializer.SerializeToElement(new
            {
                comparison_version = "1.0",
                baseline = new { report_path = baseline },
                current = new { report_path = currentReport },
                changes = new { persisted = new[] { new { id = "p-1", title = "Persisted fixture finding", mitigation = "Fixture recommendation" } } },
                counts = new { persisted = 1 },
                notes = new[] { "fixture comparison note" },
            });
            foreach (var size in new[] { (Width: 1024, Height: 700), (Width: 1600, Height: 1000) })
            foreach (var theme in new[] { ElementTheme.Light, ElementTheme.Dark })
            {
                root.RequestedTheme = theme;
                double scale = root.XamlRoot.RasterizationScale;
                AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(size.Width * scale), (int)Math.Round(size.Height * scale)));
                Navigation.SelectedItem = Navigation.MenuItems[5];
                var settled = new TaskCompletionSource();
                DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => settled.SetResult());
                await settled.Task;
                History.CurrentReportPath = currentReport;
                History.BaselineReportPath = baseline;
                History.SetResult(comparison);
                History.SetGenerations(payload);
                History.SelectGenerationForSmoke(1);
                root.UpdateLayout();
                await Task.Delay(450); // let ListView entrance animations settle before capture
                captures.Add(await CaptureStrict(root, Path.Combine(directory, $"{size.Width}x{size.Height}-{theme}-HistoryRetention.png")));
            }
            File.WriteAllText(Path.Combine(directory, "retention-capture-manifest.json"), JsonSerializer.Serialize(new { captures, view = "History with fixture generation-retention payload; pinned row selected", os = Environment.OSVersion.ToString(), scope = NativeCaptureProbe.Scope, acceptedC25 = false }, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception error)
        {
            if (Directory.Exists(directory)) File.WriteAllText(Path.Combine(directory, "retention-capture-failure.json"), JsonSerializer.Serialize(new { error = error.ToString(), completed = captures.Count }));
        }
        finally { Close(); }
    }

    private async void CaptureReportsArtifactsLoaded(object sender, RoutedEventArgs args)
    {
        var root = (FrameworkElement)Content;
        root.Loaded -= CaptureReportsArtifactsLoaded;
        var arguments = Environment.GetCommandLineArgs();
        int index = Array.IndexOf(arguments, "--capture-reports-artifacts");
        if (index < 0 || index + 2 >= arguments.Length) { Close(); return; }
        string directory = Path.GetFullPath(arguments[index + 2]);
        var captures = new List<CaptureMetadata>();
        try
        {
            if (!Directory.Exists(directory)) throw new DirectoryNotFoundException("Create a fresh QA directory first.");
            if (!await LoadReport(arguments[index + 1])) throw new InvalidDataException("QA report could not be loaded.");
            RawArtifacts.IsExpanded = true;
            ArtifactRows.ItemsSource = new[]
            {
                new ArtifactRecord("attackmap-report.json", "canonical report JSON", "json", @"C:\fixture\attackmap-report.json", "a1b2c3d4e5f6a7b8", 512_000),
                new ArtifactRecord("ai-review.md", "AI-assisted defensive review", "md", @"C:\fixture\ai-review.md", "b2c3d4e5f6a7b8a1", 18_432),
                new ArtifactRecord("fleet-summary.md", "fleet markdown summary", "md", @"C:\fixture\fleet-summary.md", "c3d4e5f6a7b8a1b2", 9_216),
                new ArtifactRecord("finding-details.json", "finding evidence detail", "json", @"C:\fixture\finding-details.json", "d4e5f6a7b8a1b2c3", 131_072),
            };
            ArtifactRows.SelectedIndex = 0;
            ArtifactStatus.Text = "attackmap-report.json: verified selected-run text (json). Read-only text from the exact displayed generation.";
            ArtifactText.Text = "{\n  \"schema_version\": \"1.0\",\n  \"repository\": \"juice-shop\",\n  \"findings\": 18,\n  \"severity\": { \"critical\": 1, \"high\": 4, \"medium\": 9, \"low\": 4 }\n}";
            foreach (var size in new[] { (Width: 1024, Height: 700), (Width: 1600, Height: 1000) })
            foreach (var theme in new[] { ElementTheme.Light, ElementTheme.Dark })
            {
                root.RequestedTheme = theme;
                double scale = root.XamlRoot.RasterizationScale;
                AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(size.Width * scale), (int)Math.Round(size.Height * scale)));
                Navigation.SelectedItem = Navigation.MenuItems[4];
                var settled = new TaskCompletionSource();
                DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => settled.SetResult());
                await settled.Task;
                root.UpdateLayout();
                await Task.Delay(450); // let ListView entrance animations settle before capture
                captures.Add(await CaptureStrict(root, Path.Combine(directory, $"{size.Width}x{size.Height}-{theme}-ReportsArtifacts.png")));
            }
            File.WriteAllText(Path.Combine(directory, "reports-artifacts-capture-manifest.json"), JsonSerializer.Serialize(new { captures, view = "Reports with fixture artifact rows, expander expanded", os = Environment.OSVersion.ToString(), scope = NativeCaptureProbe.Scope, acceptedC25 = false }, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception error)
        {
            if (Directory.Exists(directory)) File.WriteAllText(Path.Combine(directory, "reports-artifacts-capture-failure.json"), JsonSerializer.Serialize(new { error = error.ToString(), completed = captures.Count }));
        }
        finally { Close(); }
    }

    private FrameworkElement ActiveCapturePanel()
    {
        if (Navigation.SelectedItem == Navigation.SettingsItem) return ProviderPanel;
        int index = Navigation.MenuItems.IndexOf(Navigation.SelectedItem);
        FrameworkElement[] panels = [OverviewPanel, FindingsPanel, StructurePanel, StructurePanel, ReportsPanel,
            HistoryPanel, ScanOptionsPanel, RiskPaths, EvidenceInventory, Diagrams, Fleet, SuppressionWorkspace];
        return index >= 0 && index < panels.Length ? panels[index] : throw new InvalidOperationException("No selected capture destination.");
    }

    private IReadOnlyList<CaptureRegion> RequiredCaptureRegions(FrameworkElement root, FrameworkElement activePanel)
    {
        if (root.RequestedTheme != ElementTheme.Default && root.ActualTheme != root.RequestedTheme)
            throw new InvalidOperationException("Capture theme has not settled to the requested theme.");
        if (Navigation.SelectedItem is not NavigationViewItem selected)
            throw new InvalidOperationException("Capture requires a selected navigation item.");
        string selectedLabel = ReferenceEquals(selected, Navigation.SettingsItem) ? "Settings" : selected.Content?.ToString() ?? "";
        if (string.IsNullOrWhiteSpace(selectedLabel) || Heading.Text != selectedLabel)
            throw new InvalidOperationException("Selected destination and capture heading disagree.");
        FrameworkElement[] panels = [OverviewPanel, FindingsPanel, StructurePanel, ReportsPanel,
            HistoryPanel, ScanOptionsPanel, RiskPaths, EvidenceInventory, Diagrams, Fleet, SuppressionWorkspace, ProviderPanel];
        var visiblePanels = panels.Where(CaptureEffectivelyVisible).ToArray();
        if (visiblePanels.Length != 1 || !ReferenceEquals(visiblePanels[0], activePanel))
            throw new InvalidOperationException("Exactly one selected destination panel must be effectively visible.");
        var navigationText = ProviderScrollElements(selected).OfType<TextBlock>().FirstOrDefault(text =>
            !string.IsNullOrWhiteSpace(text.Text) && CaptureEffectivelyVisible(text) && ProviderPreviewBounds(text, root).FullyWithinClippedViewport);
        if (navigationText == null) throw new InvalidOperationException("Selected navigation label has no visible text region.");
        var pageText = ProviderScrollElements(activePanel).OfType<TextBlock>().FirstOrDefault(text =>
            !string.IsNullOrWhiteSpace(text.Text) && CaptureEffectivelyVisible(text) && ProviderPreviewBounds(text, root).FullyWithinClippedViewport);
        if (pageText == null) throw new InvalidOperationException("Selected page has no visible nonempty text region.");
        return [NativeCaptureProbe.RequireTextRegion(root, Heading, "heading"),
            NativeCaptureProbe.RequireTextRegion(root, navigationText, "selected-navigation"),
            NativeCaptureProbe.RequireTextRegion(root, pageText, "page-text-0")];
    }

    private async Task<CaptureMetadata> CaptureStrict(FrameworkElement root, string path, bool requireVisibleContent = true)
    {
        if (!requireVisibleContent) throw new ArgumentException("QA captures must use strict required-text validation.", nameof(requireVisibleContent));
        if (Navigation.SelectedItem is FrameworkElement selected)
            selected.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false, VerticalAlignmentRatio = 0.5 });
        var settled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => settled.SetResult()))
            throw new InvalidOperationException("Capture dispatcher is unavailable.");
        await settled.Task;
        root.UpdateLayout();
        return await CaptureWithDiagnostics(root, path, RequiredCaptureRegions(root, ActiveCapturePanel()));
    }

    private async Task<CaptureMetadata> CaptureWithDiagnostics(FrameworkElement root, string path, IReadOnlyList<CaptureRegion> requiredText)
    {
        try
        {
            var capture = await NativeCaptureProbe.Capture(root, path, requireVisibleContent: true, requiredText);
            RenderDiagnosticsCapture(capture, Path.GetFileName(path));
            return capture;
        }
        catch (CaptureValidationException error)
        {
            RenderDiagnosticsCapture(error.Metadata, Path.GetFileName(path));
            throw;
        }
    }

    private static bool CaptureEffectivelyVisible(FrameworkElement element)
    {
        for (FrameworkElement? current = element; current is not null;
            current = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(current) as FrameworkElement)
            if (!current.IsLoaded || current.Visibility != Visibility.Visible || current.ActualWidth <= 0 || current.ActualHeight <= 0)
                return false;
        return true;
    }

    private async void CaptureLoaded(object sender, RoutedEventArgs args)
    {
        var root = (FrameworkElement)Content;
        root.Loaded -= CaptureLoaded;
        var arguments = Environment.GetCommandLineArgs();
        int index = Array.IndexOf(arguments, "--capture-smoke");
        if (index < 0 || index + 2 >= arguments.Length) { Close(); return; }
        string directory = Path.GetFullPath(arguments[index + 2]);
        var captures = new List<CaptureMetadata>();
        var aiSummaryProofs = new List<object>();
        int aiModeIndex = Array.IndexOf(arguments, "--capture-ai-mode");
        string? aiMode = aiModeIndex < 0 ? null : arguments[aiModeIndex + 1];
        bool forceInvalidRegion = arguments.Contains("--capture-invalid-region");
        int expected = aiMode != null ? 4 : arguments.Contains("--capture-structure-only") ? 8 : 4 * (Navigation.MenuItems.Count + 2);
        var runState = new CaptureRunState(expected);
        try
        {
            if (!Directory.Exists(directory)) throw new DirectoryNotFoundException("Create a fresh QA directory first.");
            if (!await LoadReport(arguments[index + 1])) throw new InvalidDataException("QA report could not be loaded.");
            await parityViewBinding;
            if (aiMode != null)
            {
                if (await AiArtifacts.SelectMode(aiMode) == null) throw new InvalidDataException("Selected saved AI mode is unavailable.");
                AiArtifactsExpander.IsExpanded = true;
            }
            async Task CaptureOne(string name, string path)
            {
                try
                {
                    captures.Add(forceInvalidRegion
                        ? await CaptureWithDiagnostics(root, path,
                            [new CaptureRegion("forced-invalid-region", -1, 0, 10, 10, 255, 255, 255)])
                        : await CaptureStrict(root, path, requireVisibleContent: true));
                    runState.Success(name);
                }
                catch (CaptureValidationException error)
                {
                    captures.Add(error.Metadata);
                    runState.Failure(name, error.Message);
                }
            }
            foreach (var size in new[] { (Width: 1024, Height: 700), (Width: 1600, Height: 1000) })
            foreach (var theme in new[] { ElementTheme.Light, ElementTheme.Dark })
            {
                root.RequestedTheme = theme;
                double scale = root.XamlRoot.RasterizationScale;
                AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(size.Width * scale), (int)Math.Round(size.Height * scale)));
                foreach (var destination in Navigation.MenuItems.Cast<object>().Append(Navigation.SettingsItem)
                    .Where(item => aiMode == null || item == Navigation.MenuItems[4])
                    .Where(item => !arguments.Contains("--capture-structure-only") || (item as NavigationViewItem)?.Content?.ToString() is "Architecture" or "Inventory"))
                {
                    Navigation.SelectedItem = destination;
                    var settled = new TaskCompletionSource();
                    DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => settled.SetResult());
                    await settled.Task;
                    root.UpdateLayout();
                    string view = (destination as NavigationViewItem)?.Content?.ToString() ?? "Settings";
                    string filename = $"{size.Width}x{size.Height}-{theme}-{view}.png";
                    if (aiMode != null)
                    {
                        await Task.Delay(450);
                        foreach (var scroll in ProviderScrollElements(AiArtifactsExpander).OfType<ScrollViewer>())
                            scroll.ChangeView(null, 0, null, disableAnimation: true);
                        root.UpdateLayout();
                        var summary = ProviderScrollElements(AiArtifacts).OfType<TextBlock>().Single(text =>
                            text.Text.StartsWith("Selected generation:", StringComparison.Ordinal));
                        summary.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false, VerticalAlignmentRatio = 0 });
                        await ProviderScrollDispatchTurns(); root.UpdateLayout();
                        var bounds = ProviderPreviewBounds(summary, root);
                        if (Navigation.SelectedItem != Navigation.MenuItems[4] || Heading.Text != "Reports" || !bounds.FullyWithinClippedViewport)
                            throw new InvalidOperationException("Actual selected-generation AI summary is not fully visible in Reports.");
                        aiSummaryProofs.Add(new { filename, selected = view, summary.Text, bounds });
                    }
                    await CaptureOne(filename, Path.Combine(directory, filename));
                    if (view is "Architecture" or "Inventory")
                    {
                        var rows = Enumerable.Range(0, Math.Min(StructureRecords.Items.Count, 16)).Select(rowIndex =>
                        {
                            var container = StructureRecords.ContainerFromIndex(rowIndex) as ListViewItem;
                            return new { index = rowIndex, realized = container != null, width = container?.ActualWidth, height = container?.ActualHeight, opacity = container?.Opacity,
                                texts = container == null ? [] : FaultSmokeElements(container).OfType<TextBlock>().Select(text => new { text.Text, text.ActualWidth, text.ActualHeight, text.Opacity, foreground = (text.Foreground as Microsoft.UI.Xaml.Media.SolidColorBrush)?.Color.ToString() }).ToArray() };
                        }).ToArray();
                        File.WriteAllText(Path.Combine(directory, filename + ".rows.json"), JsonSerializer.Serialize(new { view, boundCount = StructureRecords.Items.Count, width = StructureRecords.ActualWidth, height = StructureRecords.ActualHeight, panelWidth = StructurePanel.ActualWidth, panelHeight = StructurePanel.ActualHeight, rows }, new JsonSerializerOptions { WriteIndented = true }));
                    }
                }
                if (aiMode != null || arguments.Contains("--capture-structure-only")) continue;
                Navigation.SelectedItem = Navigation.MenuItems[1];
                if (all.Count > 0) Findings.SelectedIndex = 0;
                root.UpdateLayout();
                FindingInspector.Focus(FocusState.Programmatic);
                FindingInspector.ChangeView(null, Math.Min(FindingInspector.ScrollableHeight, Math.Max(0, Detail.ActualHeight - FindingInspector.ActualHeight / 2)), null, disableAnimation: true);
                string detailName = $"{size.Width}x{size.Height}-{theme}-FindingDetail.png";
                await CaptureOne(detailName, Path.Combine(directory, detailName));
                FindingInspector.ChangeView(null, 0, null, disableAnimation: true);
            }
            File.WriteAllText(Path.Combine(directory, "capture-manifest.json"), JsonSerializer.Serialize(new {
                status = runState.Status, attempts = runState.Attempts, captures, expected, completed = captures.Count,
                aiSummaryProofs, os = Environment.OSVersion.ToString(), aiMode, selectedReportSha256 = displayedReadHash,
                providerCalled = false, findingDetailState = "Production master/detail view with the first finding selected, inspector focused and scrolled toward the recommendation. No separate detail destination is invented.",
                scope = NativeCaptureProbe.Scope, manual_review = "not-run", live_window_acceptance = "not-established", acceptedC25 = false
            }, new JsonSerializerOptions { WriteIndented = true }));
            if (runState.Failed > 0)
                File.WriteAllText(Path.Combine(directory, "capture-failure.json"), JsonSerializer.Serialize(new {
                    error = "One or more required-text capture regions failed.", status = runState.Status,
                    attempts = runState.Attempts, completed = captures.Count
                }, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception error)
        {
            if (Directory.Exists(directory)) File.WriteAllText(Path.Combine(directory, "capture-failure.json"), JsonSerializer.Serialize(new {
                error = error.ToString(), status = runState.Status, attempts = runState.Attempts, completed = captures.Count
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        finally { Close(); }
    }
}
