using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    // Reproduce the user journey with a real static scan and existing native destinations.
    private async void NavigationRenderSmokeLoaded(object sender, RoutedEventArgs args)
    {
        var root = (FrameworkElement)Content;
        root.Loaded -= NavigationRenderSmokeLoaded;
        var argv = Environment.GetCommandLineArgs();
        string output = argv[3];
        var states = new List<object>();
        var captures = new List<CaptureMetadata>();
        var captureFailures = new List<object>();
        string? failure = null;
        bool scanned = false;
        string mode = Environment.GetEnvironmentVariable("ATTACKMAP_NAVIGATION_QA_MODE") ?? "all-captures";
        try
        {
            if (mode is not ("all-captures" or "single-capture" or "detach" or "diagrams" or "diagrams-nowrap-control" or "report-graph" or "report-graph-fallback"))
                throw new ArgumentException("Unknown navigation QA mode.");
            providerRenderActionDirectory = Path.Combine(output, "actions");
            if (!await LoadReport(argv[2])) throw new InvalidDataException("Saved report unavailable.");
            PythonPath.Text = argv[4]; repositoryPath = displayedRepository;
            presentation.SelectRepository(repositoryPath);
            ApplyScanOptions(new NativeScanOptions(Provider: new ProviderConfiguration(EnableAi: false)), "");
            root.RequestedTheme = ElementTheme.Dark;
            AppWindow.Resize(new Windows.Graphics.SizeInt32(1905, 1005));
            if (mode is "report-graph" or "report-graph-fallback")
            {
                await ReportGraphSmoke(output, fallbackOnly: mode == "report-graph-fallback");
                return;
            }
            if (mode.StartsWith("diagrams", StringComparison.Ordinal))
            {
                await DiagramNavigationRenderSmoke(output, mode, captures);
                return;
            }
            if (mode == "all-captures")
            {
                await RunSelectedRepository(Path.Combine(output, "reports"));
                scanned = scanProgress.Terminal && scanProgress.State == "completed";
                if (!scanned) throw new InvalidOperationException(Status.Text);
            }
            FrameworkElement[] panels = [OverviewPanel, FindingsPanel, StructurePanel, ReportsPanel,
                HistoryPanel, ScanOptionsPanel, RiskPaths, EvidenceInventory, Diagrams, Fleet, SuppressionWorkspace, ProviderPanel];
            var host = (Grid)FindingsPanel.Parent;
            Search.Text = "route";
            TimeoutOption.Text = "1800";
            for (int round = 0; round < 3; round++)
            foreach (var destination in Navigation.MenuItems.Cast<NavigationViewItem>().Append((NavigationViewItem)Navigation.SettingsItem))
            {
                Navigation.SelectedItem = destination;
                // Diagnostic experiment only: this is not an accepted production rendering fix.
                if (mode == "detach")
                    foreach (var panel in panels)
                        if (panel.Visibility == Visibility.Collapsed) host.Children.Remove(panel);
                        else if (!host.Children.Contains(panel)) host.Children.Add(panel);
                await Task.Delay(400);
                root.UpdateLayout();
                string requested = ReferenceEquals(destination, Navigation.SettingsItem) ? "Settings" : destination.Content?.ToString() ?? "";
                var attached = panels.Where(p => p.Parent != null).ToArray();
                if (panels.Count(p => p.Visibility == Visibility.Visible) != 1 || Heading.Text != requested ||
                    (mode == "detach" && (attached.Length != 1 || attached[0].Visibility != Visibility.Visible)))
                    throw new InvalidOperationException("Selected destination and active page disagree.");
                if (Search.Text != "route" || TimeoutOption.Text != "1800")
                    throw new InvalidOperationException("Navigation lost edited filter/options.");
                var texts = ProviderScrollElements(root).OfType<TextBlock>().Where(t => t.ActualWidth > 0 && t.ActualHeight > 0).ToArray();
                states.Add(new { round, requested, heading = Heading.Text, selected = (Navigation.SelectedItem as NavigationViewItem)?.Content?.ToString(),
                    visiblePanels = panels.Where(p => p.Visibility == Visibility.Visible).Select(p => p.Name).ToArray(),
                    attachedPanels = attached.Select(p => p.Name).ToArray(),
                    labels = Navigation.MenuItems.OfType<NavigationViewItem>().Select(p => p.Content?.ToString()).ToArray(),
                    laidOutTextCount = texts.Length, text = texts.Select(t => new { t.Name, t.Text, t.Opacity, t.ActualWidth, t.ActualHeight }).ToArray(),
                    memoryBytes = System.Diagnostics.Process.GetCurrentProcess().PrivateMemorySize64 });
                File.WriteAllText(Path.Combine(output, "states.json"), JsonSerializer.Serialize(states, new JsonSerializerOptions { WriteIndented = true }));
                // Do not use frame capture to drive navigation; retain failures instead of passing blank captures.
                if (mode == "all-captures" ? round == 0 || requested is "Fleet" or "Findings" or "Inventory" : round == 2 && requested == "Settings")
                {
                    string name = $"round{round}-{requested.Replace(' ', '-')}.png";
                    try { captures.Add(await CaptureStrict(root, Path.Combine(output, name), requireVisibleContent: true)); }
                    catch (CaptureValidationException error)
                    {
                        captures.Add(error.Metadata);
                        captureFailures.Add(new { round, requested, error = error.Message, metadata = error.Metadata });
                    }
                }
            }
        }
        catch (Exception error) { failure = error.ToString(); }
        finally
        {
            if (failure == null && captureFailures.Count > 0) failure = "One or more required-text captures failed.";
            File.WriteAllText(Path.Combine(output, "proof.json"), JsonSerializer.Serialize(new { mode, scanned, passed = failure == null && captureFailures.Count == 0,
                failure, states = states.Count, captures, captureFailures, providerCalls = 0, scope = NativeCaptureProbe.Scope }, new JsonSerializerOptions { WriteIndented = true }));
            if (mode == "report-graph" && Environment.GetEnvironmentVariable("ATTACKMAP_DIAGRAM_QA_KEEP_OPEN") == "1")
                Title = failure == null ? "AttackMap — integrované diagramy" : "AttackMap — diagramy: test selhal";
            else if (mode == "diagrams" && failure == null && Environment.GetEnvironmentVariable("ATTACKMAP_DIAGRAM_QA_KEEP_OPEN") == "1")
                Title = Environment.GetEnvironmentVariable("ATTACKMAP_DIAGRAM_QA_CAPTURE") == "none"
                    ? "AttackMap — bez snímání (test)" : "AttackMap — Diagrams render fix (test)";
            else Close();
        }
    }
}
