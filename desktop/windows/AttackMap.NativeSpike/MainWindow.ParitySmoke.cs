using System.Text.Json;
using Microsoft.UI.Xaml;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private async void ParitySmokeLoaded(object sender, RoutedEventArgs args)
    {
        ((FrameworkElement)Content).Loaded -= ParitySmokeLoaded;
        string[] arguments = Environment.GetCommandLineArgs();
        int index = Array.IndexOf(arguments, "--parity-smoke");
        string directory = Path.GetFullPath(arguments[index + 2]);
        recentStore = new HistoryPrep.RecentRepositoriesStore(Path.Combine(directory, "recent-repositories.json"));
        object? result = null;
        string? failure = null;
        try
        {
            if (!Directory.Exists(directory) || File.Exists(Path.Combine(directory, "parity-smoke.json"))) throw new IOException("Create a fresh caller-owned verification directory.");
            string reportPath = Path.GetFullPath(arguments[index + 1]);
            bool loaded = await LoadReport(reportPath);
            if (!loaded) throw new InvalidDataException(Status.Text);
            var options = new NativeScanOptions(Recall: true, StrictAnalyzers: true, Baseline: reportPath,
                SuppressFile: Path.Combine(directory, "selected.yaml"), FailOnNewHigh: true, FailOnNewSuppression: true,
                StrictSuppressions: true, IsolatedAnalyzers: true, TimeBudgetSeconds: 60, TimeoutSeconds: 120,
                Provider: new ProviderConfiguration() with { Mode = "hunt_verify", JuryVotes = 3, Effort = "high", Speed = "standard", Backend = "api" });
            ApplyScanOptions(options, "javascript-web,config");
            string before = JsonSerializer.Serialize(ReadScanOptions());
            SaveLocalSettings(this, new RoutedEventArgs());
            var restored = settings.Load(); ApplyScanOptions(restored.EffectiveOptions, restored.Modules);
            bool roundTrip = before == JsonSerializer.Serialize(ReadScanOptions());
            bool aiOffPreferencesRetained = Provider.ReadConfiguration() is { EnableAi: false, Mode: "hunt_verify", JuryVotes: 3, Effort: "high" };
            var destinations = new List<string>();
            foreach (var destination in Navigation.MenuItems.Cast<object>().Append(Navigation.SettingsItem))
            {
                Navigation.SelectedItem = destination;
                var settled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low,()=>settled.TrySetResult());
                await settled.Task.WaitAsync(TimeSpan.FromSeconds(5));
                ((FrameworkElement)Content).UpdateLayout();
                destinations.Add(Heading.Text);
            }
            int engineIndex = Array.IndexOf(arguments, "--engine");
            int requestedModeIndex = Array.IndexOf(arguments, "--ai-mode");
            string? requestedMode = requestedModeIndex < 0 ? null : arguments[requestedModeIndex + 1];
            bool requestedScan = arguments.Contains("--native-scan");
            bool requestedFleetWatch = arguments.Contains("--fleet-watch");
            bool requestedSingleWatch = arguments.Contains("--single-watch");
            if (((requestedScan || requestedFleetWatch || requestedSingleWatch) && engineIndex < 0) || (requestedMode != null && !requestedScan)) throw new ArgumentException("A live journey requires an explicit selected engine; AI also requires a native scan.");
            bool capabilitiesChecked = false, scanCompleted = false, modelCompleted = false;
            object? aiDisplay = null, fleetWatchResult = null, singleWatchResult = null;
            if (engineIndex >= 0)
            {
                PythonPath.Text = Path.GetFullPath(arguments[engineIndex + 1]);
                await DiscoverEngineCapabilities(); capabilitiesChecked = capabilityCache.Current?.Compatible == true;
                if (arguments.Contains("--fleet-watch")) fleetWatchResult = await RunFleetWatchSmoke(directory);
                ApplyScanOptions(new NativeScanOptions(TimeoutSeconds: 1200), "");
                if (requestedSingleWatch) singleWatchResult = await RunSingleWatchSmoke(directory);
                if (arguments.Contains("--native-scan"))
                {
                    int repositoryIndex = Array.IndexOf(arguments, "--repository");
                    if (repositoryIndex < 0) throw new ArgumentException("Native scan requires an explicit verification repository.");
                    repositoryPath = Path.GetFullPath(arguments[repositoryIndex + 1]); presentation.SelectRepository(repositoryPath);
                    int modeIndex = Array.IndexOf(arguments, "--ai-mode");
                    if (modeIndex >= 0)
                        Provider.ApplyConfiguration(new ProviderConfiguration(EnableAi: true, TimeoutSeconds: 900) with { Mode = arguments[modeIndex + 1], Backend = "api", Speed = "standard" });
                    await RunSelectedRepository(Path.Combine(directory, "reports"));
                    scanCompleted = scanProgress.State == "completed" && scanProgress.Terminal && exportSelection?.Verified == true && displayedRepository == repositoryPath;
                    if (!scanCompleted) throw new InvalidDataException("Integrated native scan did not publish a verified result: " + Status.Text);
                    if (requestedMode != null)
                    {
                        await parityViewBinding;
                        var page = await AiArtifacts.SelectMode(requestedMode);
                        if (page == null || page.Mode != requestedMode) throw new InvalidDataException("Requested AI section was not bound to the selected generation.");
                        Navigation.SelectedItem = Navigation.MenuItems[4];
                        AiArtifactsExpander.IsExpanded = true;
                        var selected = exportSelection!;
                        var records = await Task.Run(() => SelectedArtifacts.List(selected));
                        var artifact = records.SingleOrDefault(record => Path.GetFileName(record.FullPath) == page.ArtifactName);
                        if (artifact == null) throw new InvalidDataException("Requested AI mode artifact is missing.");
                        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(await SelectedArtifacts.ReadText(selected, artifact, 64 * 1024 * 1024));
                        if (ExportSelection.Hash(bytes) != artifact.Checksum) throw new InvalidDataException("AI export bytes do not match the captured artifact.");
                        string exportPath = Path.Combine(directory, page.ArtifactName);
                        await WriteSelectedBytes(exportPath, bytes);
                        ((FrameworkElement)Content).UpdateLayout();
                        AiArtifactsExpander.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false, VerticalAlignmentRatio = 0 });
                        var capture = await NativeCaptureProbe.Capture((FrameworkElement)Content, Path.Combine(directory, "AI-mode.png"));
                        aiDisplay = new { mode = page.Mode, state = page.State, artifact = artifact.FullPath, artifactSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant(), exportPath, capture, metadata = page.Metadata };
                        modelCompleted = page.State == "completed";
                    }
                }
            }
            result = new { passed = (!(requestedFleetWatch || requestedSingleWatch) || capabilitiesChecked) && (!requestedScan || (capabilitiesChecked && scanCompleted)) && (requestedMode == null || modelCompleted) && loaded && roundTrip && aiOffPreferencesRetained && destinations.Contains("Risk and paths") && destinations.Contains("Reports"),
                loaded, roundTrip, aiOffPreferencesRetained, destinations, capabilitiesChecked, scanCompleted,
                outputRoot = Path.Combine(directory, "reports"), isolatedOutput = true, aiDisplay, fleetWatchResult, singleWatchResult,
                report = displayedReportPath, reportHash = displayedReadHash, run = displayedRun,
                progressState = scanProgress.State, progressTerminal = scanProgress.Terminal, status = Status.Text,
                acceptedManualUi = false, acceptedAccessibility = false, personalSettingsRead = false };
        }
        catch (Exception error) { failure = error.ToString(); }
        finally
        {
            try { File.WriteAllText(Path.Combine(directory, "parity-smoke.json"), JsonSerializer.Serialize(new { result, failure }, new JsonSerializerOptions { WriteIndented = true })); }
            finally { Close(); }
        }
    }

    private async Task<object> RunFleetWatchSmoke(string directory)
    {
        string fixture = Path.Combine(directory, "fleet-fixtures");
        if (Directory.Exists(fixture)) throw new IOException("Fleet verification fixture must be new.");
        string[] roots = Enumerable.Range(1, 4).Select(number => Path.Combine(fixture, "repository-" + number)).ToArray();
        foreach (string root in roots)
        {
            Directory.CreateDirectory(root);
            File.WriteAllText(Path.Combine(root, "app.py"), "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/status')\ndef status():\n    return {'status': 'ok'}\n");
        }
        var observed = new System.Collections.Concurrent.ConcurrentQueue<FleetRepositoryWatchRequest>();
        void Observed(FleetRepositoryWatchRequest request) => observed.Enqueue(request);
        fleetWatch.ScanRequested += Observed;
        fleetWatchVerificationOutput = Path.Combine(directory, "fleet-reports");
        string ignoredOutput = Path.Combine(roots[1], ".owned-fleet-output-canary");
        bool defaultOff = !Fleet.WatchRequested && !fleetWatch.Enabled;
        string? retainedRun = displayedRun, retainedHash = displayedReadHash;
        try
        {
            for (int n = 0; n < 3; n++) Fleet.AddRepository("qa-" + n, roots[n]);
            Fleet.WatchRequested = true;
            RestartFleetWatch(new[] { ignoredOutput });
            if (!fleetWatch.Enabled || fleetWatch.WatchedRoots.Count != 3) throw new InvalidDataException("Full native fleet did not install three watchers.");
            await Task.Delay(1400);
            bool explicitOptInIdle = !fleetRunning && Fleet.Workspace.Active == null && observed.IsEmpty;
            File.AppendAllText(Path.Combine(roots[1], "app.py"), "\n# second repository changed\n");
            await WaitForFleetSmoke(() => Fleet.Workspace.Active != null && !fleetRunning, TimeSpan.FromMinutes(8));
            var first = Fleet.Workspace.Active!;
            bool secondRootFullRescan = Fleet.Workspace.IsCurrent && Fleet.Workspace.Children.Count == 3 && Fleet.Workspace.Children.All(child => child.State == "completed")
                && observed.Any(request => request.RepositoryRoots.Count == 3 && request.ChangedRepositoryRoots.Contains(roots[1], StringComparer.OrdinalIgnoreCase));
            if (!secondRootFullRescan) throw new InvalidDataException("Second-root edit did not complete a full native fleet: " + Status.Text);
            Directory.CreateDirectory(ignoredOutput);
            File.WriteAllText(Path.Combine(ignoredOutput, "ignored-output.txt"), "QA canary: this write must not request another scan; actual reports are outside all fixture roots.");
            await Task.Delay(1800);
            bool ownedOutputIgnored = !fleetRunning && Fleet.Workspace.Active == first && observed.Count == 1 && !fleetWatch.Pending;
            File.AppendAllText(Path.Combine(roots[2], "app.py"), "\n# third repository changed\n");
            await WaitForFleetSmoke(() => Fleet.Workspace.Active != first && !fleetRunning, TimeSpan.FromMinutes(8));
            var second = Fleet.Workspace.Active!;
            bool thirdRootFullRescan = Fleet.Workspace.IsCurrent && Fleet.Workspace.Children.Count == 3 && observed.Count == 2
                && observed.Last().ChangedRepositoryRoots.Contains(roots[2], StringComparer.OrdinalIgnoreCase);
            Navigation.SelectedItem = Navigation.MenuItems[10];
            Activate();
            await Task.Delay(650);
            await ReadinessRenderBarrier();
            var renderedPaths = Descendants(Fleet).OfType<Microsoft.UI.Xaml.Controls.TextBlock>()
                .Where(block => block.Name == "FleetRepositoryPath").Select(block => block.Text).ToArray();
            bool repositoryRowsReadable = roots.Take(3).SequenceEqual(renderedPaths);
            if (!repositoryRowsReadable) throw new InvalidDataException("Rendered fleet repository rows do not match the selected paths.");
            var capture = await NativeCaptureProbe.Capture((FrameworkElement)Content, Path.Combine(directory, "Fleet-watch.png"));
            var captures = await CaptureWatchView(directory, "Fleet-watch", 10);
            Fleet.RemoveRepository("qa-0"); Fleet.AddRepository("qa-3", roots[3]);
            long switchedEpoch = fleetWatch.Epoch;
            File.AppendAllText(Path.Combine(roots[0], "app.py"), "\n# removed root must remain silent\n");
            await Task.Delay(1600);
            bool oldRootIgnored = !fleetRunning && observed.Count == 2 && !fleetWatch.Pending && fleetWatch.Epoch == switchedEpoch;
            Fleet.WatchRequested = false;
            File.AppendAllText(Path.Combine(roots[2], "app.py"), "\n# stopped watch must remain silent\n");
            await Task.Delay(1600);
            bool stopped = !fleetWatch.Enabled && !fleetRunning && observed.Count == 2;
            Task cancelRun = RunFleet(Fleet.SelectedRoots);
            await WaitForFleetSmoke(() => Fleet.Workspace.IsRunning || cancelRun.IsCompleted, TimeSpan.FromMinutes(2));
            if (!Fleet.Workspace.IsRunning) throw new InvalidDataException("Fleet cancel test did not reach an admitted worker: " + Status.Text);
            CancelScan(this, new RoutedEventArgs());
            await cancelRun.WaitAsync(TimeSpan.FromMinutes(2));
            bool cancelledSettled = !Fleet.Workspace.IsRunning && !fleetRunning && !scanning && Fleet.Workspace.Outcome == "cancelled"
                && !fleetSession.CleanupBlocked && !engine.CleanupBlocked && !DesktopActionRunner.CleanupBlocked;
            bool singleReportPreserved = displayedRun == retainedRun && displayedReadHash == retainedHash;
            if (!(defaultOff && explicitOptInIdle && ownedOutputIgnored && thirdRootFullRescan && oldRootIgnored && stopped && cancelledSettled && singleReportPreserved)) throw new InvalidDataException("Native fleet-watch/cancel isolation assertion failed: " + Status.Text);
            return new { passed = true, defaultOff, explicitOptInIdle, secondRootFullRescan, thirdRootFullRescan, ownedOutputIgnored, oldRootIgnored, stopped,
                cancelledSettled, cancelOutcome = Fleet.Workspace.Outcome, singleReportPreserved, repositoryRowsReadable, renderedPaths,
                first, second, observed = observed.ToArray(), outputRoot = fleetWatchVerificationOutput, capture, captures, actualEngine = true, providerCallsRequested = false, acceptedManualUi = false };
        }
        finally { StopFleetWatch(); fleetWatch.ScanRequested -= Observed; fleetWatchVerificationOutput = null; }

        static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
        {
            for (int n = 0; n < Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChildrenCount(parent); n++)
            {
                var child = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChild(parent, n);
                yield return child;
                foreach (var descendant in Descendants(child)) yield return descendant;
            }
        }
    }
    private async Task WaitForFleetSmoke(Func<bool> completed, TimeSpan timeout)
    {
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        while (!completed())
        {
            if (elapsed.Elapsed > timeout || actionLifetime.IsCancellationRequested) throw new TimeoutException("Native fleet-watch journey did not settle: " + Status.Text);
            await Task.Delay(100);
        }
    }
}
