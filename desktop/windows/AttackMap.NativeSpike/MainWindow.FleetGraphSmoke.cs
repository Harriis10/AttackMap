using System.Text.Json;
using AttackMap.GraphExplorer;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AttackMap.NativeSpike;

// Explicit caller-owned QA entry point. Startup wiring/settings isolation belong to the host.
public sealed partial class MainWindow
{
    private async void FleetGraphSmokeLoaded(object sender, RoutedEventArgs args)
    {
        var root = (FrameworkElement)Content;
        root.Loaded -= FleetGraphSmokeLoaded;
        string[] arguments = Environment.GetCommandLineArgs();
        string? directory = null, failure = null;
        bool claimedDirectory = false;
        object? result = null;
        var checks = new List<object>();
        var captures = new List<object>();
        var captureRetries = new List<string>();
        DateTimeOffset started = DateTimeOffset.UtcNow;
        void Check(string name, bool passed, object? detail = null)
        {
            checks.Add(new { name, passed, detail, at = DateTimeOffset.UtcNow });
            if (!passed) throw new InvalidDataException("Fleet graph smoke failed: " + name);
        }
        string Argument(string name)
        {
            int position = Array.IndexOf(arguments, name);
            if (position < 0 || position + 1 >= arguments.Length || arguments[position + 1].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException("Missing explicit " + name + " argument.");
            return arguments[position + 1];
        }
        try
        {
            directory = Path.GetFullPath(Argument("--fleet-graph-smoke"));
            if (!Directory.Exists(directory)) throw new DirectoryNotFoundException("Create a fresh caller-owned fleet graph QA directory first.");
            ExportSelection.EnsureDestinationPath(Path.Combine(directory, "fleet-graph-smoke.json"));
            // The isolated constructor may already have created settings/recent/window files.
            if (File.Exists(Path.Combine(directory, "fleet-graph-smoke.json")) || Directory.Exists(Path.Combine(directory, "reports")) ||
                Directory.Exists(Path.Combine(directory, "captures"))) throw new IOException("Fleet graph QA output must be fresh.");
            using (var claim = new FileStream(Path.Combine(directory, "fleet-graph-smoke.started"), FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { }
            claimedDirectory = true;
            string enginePath = Path.GetFullPath(Argument("--engine"));
            Check("explicit_frozen_executable_exists", File.Exists(enginePath) && string.Equals(Path.GetExtension(enginePath), ".exe", StringComparison.OrdinalIgnoreCase));
            string rootsPath = Path.GetFullPath(Argument("--roots-json"));
            byte[] manifestBytes = await ReadFleetBytes(rootsPath, 1024 * 1024);
            using var manifest = JsonDocument.Parse(manifestBytes);
            var corpus = manifest.RootElement;
            Check("owned_synthetic_corpus_manifest", corpus.GetProperty("kind").GetString() == "owned_synthetic_on_disk_repositories" && corpus.GetProperty("count").GetInt32() == 16);
            var entries = corpus.GetProperty("repositories").EnumerateArray().ToArray();
            Check("exactly_16_explicit_roots", entries.Length == 16);
            Check("empty_initial_fleet", Fleet.Workspace.Repositories.Count == 0 && !Fleet.Workspace.IsRunning);
            foreach (var entry in entries)
            {
                string path = Path.GetFullPath(entry.GetProperty("root").GetString() ?? throw new InvalidDataException("Missing corpus root."));
                Check("owned_fixture_root_exists", entry.GetProperty("fixture").GetBoolean() && Directory.Exists(path), new { root = path });
                Check("outputs_outside_target", !FleetGraphSmokeWithin(directory, path));
                Fleet.Workspace.Add(Guid.NewGuid().ToString("N"), path);
            }
            Fleet.WatchRequested = false;
            Fleet.SetExecutionOptions(new FleetExecutionOptions(TimeoutSeconds: 1200, MaxWorkers: 2));
            Fleet.Refresh();
            var selectedRoots = Fleet.SelectedRoots.ToArray();
            var fleetDestination = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Fleet");
            Navigation.SelectedItem = fleetDestination;
            PythonPath.Text = enginePath;
            ApplyScanOptions(new NativeScanOptions(Cve: false, TimeoutSeconds: 1200), "");
            Check("no_provider_configured", !Provider.ReadConfiguration().EnableAi);
            await DiscoverEngineCapabilities();
            Check("engine_supports_fleet_1_4", capabilityCache.Current?.SchemaVersions.Contains("1.4") == true);
            // RunFleet uses the real native broker path with automatic available analyzers.
            await RunFleet(selectedRoots, verificationOutput: Path.Combine(directory, "reports"));
            Check("workspace_complete_current", Fleet.Workspace.IsCurrent && !Fleet.Workspace.IsRunning && Fleet.Workspace.Outcome == "succeeded", new { Fleet.Workspace.Outcome, Status.Text });
            Check("all_16_children_verified", Fleet.Workspace.Children.Count == 16 && Fleet.Workspace.Children.All(child => child.State == "completed" && child.ManifestPath != null && child.ManifestHash?.Length == 64));
            Check("broker_cleanup_settled", !scanning && !fleetRunning && !fleetSession.CleanupBlocked);
            var active = Fleet.Workspace.Active ?? throw new InvalidDataException("Completed fleet has no generation.");
            var context = Fleet.GraphContext ?? throw new InvalidDataException("Completed fleet has no bound graph.");
            Check("graph_context_matches_fleet", context.RunId == active.RunId && context.GenerationId == active.RunId && context.SelectionRevision == active.Generation &&
                fleetGraphSource?.Context == context && context.ReportHash == fleetGraphSource.SummaryHash, context);
            byte[] summaryBytes = await ReadFleetBytes(fleetGraphSource!.SummaryPath, 64 * 1024 * 1024);
            Check("graph_summary_hash_bound", ExportSelection.Hash(summaryBytes) == context.ReportHash);
            using (var summary = JsonDocument.Parse(summaryBytes))
            {
                var repositories = summary.RootElement.GetProperty("fleet_architecture").GetProperty("repositories").EnumerateArray().ToArray();
                Check("all_16_graph_repository_groups", repositories.Length == 16 && selectedRoots.All(selected => repositories.Count(repository =>
                    string.Equals(Path.GetFullPath(repository.GetProperty("root").GetString()!), selected.RepositoryPath, StringComparison.OrdinalIgnoreCase)) == 1));
            }
            Check("host_binds_all_16_transport_and_snapshot_ids", Fleet.GraphRepositories.Count == 16 && selectedRoots.All(selected => Fleet.GraphRepositories.Count(repository =>
                repository.RequestedId == selected.RepositoryId && !string.IsNullOrWhiteSpace(repository.SnapshotId) &&
                string.Equals(Path.GetFullPath(repository.Root), selected.RepositoryPath, StringComparison.OrdinalIgnoreCase)) == 1));
            IReadOnlyList<object>? evidenceJourney = arguments.Contains("--evidence-journey") ? await RunFleetEvidenceJourney(directory, Check) : null;
            if (arguments.Contains("--shared-datastore-journey"))
            {
                Check("shared_datastore_evidence_journey_completed", evidenceJourney?.Count >= 6);
                var explorer = FleetGraphSmokeChildren<AttackMap.GraphExplorer.Native.GraphExplorerView>(Fleet).Single();
                var projection = explorer.CurrentProjection ?? throw new InvalidDataException("Missing declared projection for export.");
                var layout = explorer.Snapshot ?? throw new InvalidDataException("Missing current native layout for export.");
                string jsonPath = Path.Combine(directory, "shared-datastore-graph.json");
                string svgPath = Path.Combine(directory, "shared-datastore-graph.svg");
                await File.WriteAllTextAsync(jsonPath, AttackMap.GraphExplorer.GraphExporter.JsonWithMetadata(fleetGraphSource!.Graph, projection));
                await File.WriteAllTextAsync(svgPath, AttackMap.GraphExplorer.GraphExporter.Svg(projection, layout));
                Check("declared_graph_exports_written", File.Exists(jsonPath) && File.Exists(svgPath));
                result = new { passed = true, source = "actual native RunFleet broker and declared datastore evidence journey",
                    engine = enginePath, rootsManifest = rootsPath, rootsManifestSha256 = ExportSelection.Hash(manifestBytes),
                    selectedRoots, active, context, children = Fleet.Workspace.Children, evidenceJourney,
                    exports = new { jsonPath, svgPath }, automaticAvailableAnalyzers = true,
                    liveProviderCalls = 0, acceptedManualUi = false, acceptedOsAppearance = false,
                    scope = "Declared-filter native mapping, both source locations, back and exports; no observed runtime connectivity or whole-renderer qualification" };
                return;
            }
            var opened = new List<object>();
            foreach (var selected in new[] { selectedRoots[0], selectedRoots[^1] })
            {
                var request = Fleet.Workspace.Open(selected.RepositoryId) ?? throw new InvalidDataException("Completed child cannot be opened.");
                await OpenFleetChild(request);
                Check("child_display_and_export_identity", exportSelection?.Verified == true && exportSelection.RunId == FleetSession.ChildRunId(active, selected.RepositoryId) &&
                    string.Equals(displayedRepository, selected.RepositoryPath, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(exportSelection.ManifestPath, request.ManifestPath, StringComparison.OrdinalIgnoreCase) && exportSelection.ManifestHash == request.ManifestHash,
                    new { selected.RepositoryId, selected.RepositoryPath, displayedRepository, displayedRun, displayedReportPath });
                Check("child_navigation_reaches_findings", Heading.Text == "Findings" && !ReferenceEquals(Navigation.SelectedItem, fleetDestination));
                Check("history_back_targets_fleet", navigationBack.Count > 0 && ReferenceEquals(navigationBack.Peek(), fleetDestination));
                // Exercise the host BackRequested state transition in-process, without OS input dispatch.
                navigatingBack = true;
                try { Navigation.SelectedItem = navigationBack.Pop(); }
                finally { navigatingBack = false; Navigation.IsBackEnabled = navigationBack.Count > 0; }
                await ReadinessRenderBarrier();
                Check("back_to_fleet_retains_graph_context", ReferenceEquals(Navigation.SelectedItem, fleetDestination) && Heading.Text == "Fleet" &&
                    Fleet.GraphContext == context && Fleet.Workspace.Active == active && Fleet.Workspace.IsCurrent);
                opened.Add(new { selected.RepositoryId, selected.RepositoryPath, runId = exportSelection!.RunId, manifestHash = request.ManifestHash, returnedContext = Fleet.GraphContext });
            }
            string captureDirectory = Path.Combine(directory, "captures");
            Directory.CreateDirectory(captureDirectory);
            // Switch to the same-context native surface without awaiting its worker. Navigation
            // may unload the view; returning must settle the current layout rather than an old task.
            Task initialVectorTransition = Fleet.SelectGraphSurface(true);
            Check("vector_navigation_regression_context_before_child", Fleet.GraphContext == context && Fleet.Workspace.Active == active);
            bool vectorWasPending = !Fleet.HasGraphNativeLayout;
            var interruptedChild = Fleet.Workspace.Open(selectedRoots[0].RepositoryId) ?? throw new InvalidDataException("Native navigation regression child unavailable.");
            await OpenFleetChild(interruptedChild);
            Check("vector_navigation_regression_child_opened", Heading.Text == "Findings" && exportSelection?.RunId == FleetSession.ChildRunId(active, selectedRoots[0].RepositoryId));
            Check("vector_navigation_regression_back_targets_fleet", navigationBack.Count > 0 && ReferenceEquals(navigationBack.Peek(), fleetDestination));
            navigatingBack = true;
            try { Navigation.SelectedItem = navigationBack.Pop(); }
            finally { navigatingBack = false; Navigation.IsBackEnabled = navigationBack.Count > 0; }
            await ReadinessRenderBarrier();
            await initialVectorTransition;
            DateTimeOffset nativeReturnExpires = DateTimeOffset.UtcNow.AddSeconds(20);
            while (!Fleet.HasGraphNativeLayout && DateTimeOffset.UtcNow < nativeReturnExpires)
                await Task.Delay(100);
            Check("vector_navigation_regression_current_layout_settled", ReferenceEquals(Navigation.SelectedItem, fleetDestination) &&
                Fleet.GraphContext == context && Fleet.Workspace.Active == active && Fleet.HasGraphNativeLayout,
                new { vectorWasPending, source = "Pending surface transition plus real host child navigation/back; current layout polled after old task." });
            foreach (bool vector in new[] { true, false })
            {
                await Fleet.SelectGraphSurface(vector);
                if (vector) Check("native_vector_layout_complete", Fleet.HasGraphNativeLayout);
                else
                {
                    DateTimeOffset expires = DateTimeOffset.UtcNow.AddSeconds(30);
                    while (!Fleet.HasInteractiveGraphLayoutAcknowledgement && DateTimeOffset.UtcNow < expires)
                        await Task.Delay(100);
                    Check("interactive_context_layout_message_acknowledged", Fleet.HasInteractiveGraphLayoutAcknowledgement);
                }
                foreach (var size in new[] { (Width: 1024, Height: 700), (Width: 1600, Height: 1000) })
                foreach (var theme in new[] { ElementTheme.Light, ElementTheme.Dark })
                {
                    root.RequestedTheme = theme;
                    double scale = root.XamlRoot.RasterizationScale;
                    AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(size.Width * scale), (int)Math.Round(size.Height * scale)));
                    await ReadinessRenderBarrier();
                    root.UpdateLayout();
                    var pane = FleetGraphSmokeChildren<FleetGraphPane>(Fleet).Single();
                    pane.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false, VerticalAlignmentRatio = 0 });
                    await ReadinessRenderBarrier();
                    Check("capture_context_still_current", Fleet.GraphContext == context && Fleet.Workspace.Active == active && Fleet.Workspace.IsCurrent);
                    string surface = vector ? "vector" : "interactive";
                    string image = Path.Combine(captureDirectory, $"{size.Width}x{size.Height}-{theme}-{surface}-Fleet.png");
                    CaptureMetadata capture = await CaptureFleetGraphSmoke(root, image, captureRetries);
                    Check("capture_completed_same_context", Fleet.GraphContext == context && Fleet.Workspace.Active == active);
                    captures.Add(new { requestedWindowDip = new { size.Width, size.Height }, surface, capture,
                        nativeVectorLayoutComplete = Fleet.HasGraphNativeLayout,
                        interactiveLayoutMessageAcknowledged = Fleet.HasInteractiveGraphLayoutAcknowledgement,
                        provesInteractivePixels = false, provesOsAppearance = false });
                }
            }
            result = new { passed = true, source = "actual native RunFleet broker workflow with caller-selected frozen engine", engine = enginePath,
                rootsManifest = rootsPath, rootsManifestSha256 = ExportSelection.Hash(manifestBytes), selectedRoots, active, context,
                execution = Fleet.ExecutionOptions, automaticAvailableAnalyzers = true, children = Fleet.Workspace.Children, opened, evidenceJourney,
                navigationScope = "In-process host navigation history state transition; no OS back-button input", captures, captureRetries,
                clientRenderScope = NativeCaptureProbe.Scope, interactiveProof = "Current runtime/page/session/context layout completion message; not pixel proof",
                personalSettingsRead = false, providerConfigured = false, liveProviderCalls = 0, acceptedManualUi = false, acceptedOsAppearance = false };
        }
        catch (Exception error)
        {
            failure = error.ToString();
            checks.Add(new { name = "unhandled_smoke_failure", passed = false, detail = failure, at = DateTimeOffset.UtcNow });
            Environment.ExitCode = 1;
        }
        finally
        {
            try
            {
                if (claimedDirectory && directory != null)
                {
                    // CreateNew prevents a failed retry from replacing earlier QA proof.
                    using var output = new FileStream(Path.Combine(directory, "fleet-graph-smoke.json"), FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    JsonSerializer.Serialize(output, new { passed = failure == null && result != null, started, ended = DateTimeOffset.UtcNow, result, failure, checks, captures, captureRetries },
                        new JsonSerializerOptions { WriteIndented = true });
                    output.Flush(flushToDisk: true);
                }
                else if (failure != null) Console.Error.WriteLine(failure);
            }
            finally { if (!arguments.Contains("--keep-open")) Close(); }
        }
    }

    private async Task<CaptureMetadata> CaptureFleetGraphSmoke(FrameworkElement root, string path, List<string> retries)
    {
        Activate();
        await Task.Delay(650);
        return await CaptureStrict(root, path, requireVisibleContent: true);
    }

    private static bool FleetGraphSmokeWithin(string path, string directory)
    {
        string relative = Path.GetRelativePath(directory, path);
        return !Path.IsPathFullyQualified(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

    private static IEnumerable<T> FleetGraphSmokeChildren<T>(DependencyObject parent) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) yield return match;
            foreach (var descendant in FleetGraphSmokeChildren<T>(child)) yield return descendant;
        }
    }
}
