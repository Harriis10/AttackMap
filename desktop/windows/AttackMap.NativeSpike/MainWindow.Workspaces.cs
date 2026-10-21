using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private readonly RepositoryWatchCoordinator repositoryWatch = new();
    private readonly FleetSession fleetSession = new();
    private bool fleetRunning;
    private CancellationTokenSource? scanAdmission;
    private SuppressionWorkspaceModel? suppressionWorkspace;
    private HistoryPrep.RecentRepositoriesStore recentStore = new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", "recent-repositories.json"));

    private void InitializeWorkspaceServices()
    {
        repositoryWatch.ScanRequested += request => {
            if (actionLifetime.IsCancellationRequested) return;
            bool queued = DispatcherQueue.TryEnqueue(async () => {
                if (actionLifetime.IsCancellationRequested || !repositoryWatch.IsCurrent(request)) return;
                if (scanning || actionRunning || repositoryPath != request.RepositoryRoot || engine.CleanupBlocked || fleetSession.CleanupBlocked || DesktopActionRunner.CleanupBlocked)
                { repositoryWatch.Requeue(request); return; }
                await RunSelectedRepository();
            });
            if (!queued) repositoryWatch.Requeue(request);
        };
        repositoryWatch.NoticeChanged += notice => DispatcherQueue.TryEnqueue(() => { if (!actionLifetime.IsCancellationRequested) WatchStatus.Text = notice; });
        RecentRepositories.RepositoryRequested += entry => SelectRepositoryPath(entry.Root);
        Fleet.AddRepositoryRequested += async () => {
            try
            {
                var picker = new Windows.Storage.Pickers.FolderPicker(); picker.FileTypeFilter.Add("*");
                WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
                var folder = await picker.PickSingleFolderAsync();
                if (folder != null && !actionLifetime.IsCancellationRequested) Fleet.AddRepository(Guid.NewGuid().ToString("N"), folder.Path);
            }
            catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Fleet folder picker unavailable; existing repository set preserved."; }
        };
        Fleet.ScanRequested += async repositories => await RunFleet(repositories);
        Fleet.CancelRequested += () => fleetSession.Cancel();
        Fleet.OpenRepositoryRequested += async request => await OpenFleetChild(request);
        SuppressionWorkspace.SetSelectionOnly(true);
        SuppressionWorkspace.ChooseBaselineRequested += async ticket => {
            var model = suppressionWorkspace;
            await ChooseOptionFile(SuppressFileOption, new[] { ".yaml", ".yml" });
            if (model == null || model != suppressionWorkspace || BlankOption(SuppressFileOption.Text) is not string path) return;
            try
            {
                using var stream = File.OpenRead(path);
                if (stream.Length > 4 * 1024 * 1024) throw new InvalidDataException("Suppression file exceeds 4 MiB.");
                string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
                model.CompleteBaselineSelection(ticket, path, hash); SuppressionWorkspace.Refresh();
            }
            catch (Exception) { model.CompleteBaselineSelection(ticket, path, null); SuppressionWorkspace.Refresh(); }
        };
        SuppressionWorkspace.ClearBaselineRequested += () => SuppressFileOption.Text = "";
        SuppressionWorkspace.NoSuppressChanged += value => {
            NoSuppressOption.IsChecked = value;
            if (value) { SuppressFileOption.Text = ""; StrictSuppressionsOption.IsChecked = false; }
            else if (suppressionWorkspace?.Baseline is { } baseline) SuppressFileOption.Text = baseline.Path;
        };
        Closed += (_, _) => { scanAdmission?.Cancel(); repositoryWatch.Dispose(); fleetSession.Disconnect(); };
    }

    private void SelectRepositoryPath(string path)
    {
        if (!Directory.Exists(path)) { Status.Text = "Repository is unavailable. Choose its current folder; the retained report remains open."; return; }
        StopRepositoryWatch();
        scanAdmission?.Cancel();
        if (scanning) { engine.Cancel(); fleetSession.Cancel(); }
        ++generation; ResetAiReview(); repositoryPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        presentation.SelectRepository(repositoryPath); UpdateRunSummary(); RememberRepository(repositoryPath);
        Status.Text = $"Repository selected: {repositoryPath}. No scan started.";
    }
    private void RememberRepository(string path, ExportSelection? selected = null)
    {
        try { recentStore.Remember(path, selected?.RunId, selected?.Verified == true ? selected.ReportHash : null); RecentRepositories.SetRepositories(recentStore.Load()); }
        catch (Exception) { Status.Text = "Recent repository history could not be updated; original saved history preserved."; }
    }
    private void RestoreRecentRepositories()
    {
        try { RecentRepositories.SetRepositories(recentStore.Load()); }
        catch (Exception) { Status.Text = "Saved recent repositories are unavailable; original history preserved. Choose a repository explicitly."; }
    }
    private void WatchChanged(object sender, RoutedEventArgs args)
    {
        if (!ready) return;
        if (WatchOption.IsChecked != true) { repositoryWatch.Stop(); WatchStatus.Text = repositoryWatch.Notice; return; }
        if (repositoryPath == null || fleetRunning || !repositoryWatch.Start(repositoryPath,
            new[] { ScanLocations.ReportsBase(repositoryPath), DesktopActionRunner.ActionDirectory }, scanRunning: scanning)) WatchOption.IsChecked = false;
        WatchStatus.Text = repositoryWatch.Notice;
    }
    private void StopRepositoryWatch() { repositoryWatch.Stop(); WatchOption.IsChecked = false; WatchStatus.Text = repositoryWatch.Notice; }
    private void UseDisplayedBaseline(object sender, RoutedEventArgs args)
    {
        if (displayedReportPath == null) { NextBaselineStatus.Text = "Open a report first."; return; }
        BaselineOption.Text = displayedReportPath; NextBaselineStatus.Text = $"Next scan baseline snapshot: {displayedReportPath}\nSHA-256: {displayedReadHash}. It does not advance automatically.";
    }
    private void ClearScanBaseline(object sender, RoutedEventArgs args)
    {
        BaselineOption.Text = ""; FailNewHighOption.IsChecked = FailNewSuppressionOption.IsChecked = false;
        NextBaselineStatus.Text = "No next scan baseline; baseline policies cleared.";
    }
    private async void UsePreviousBaseline(object sender, RoutedEventArgs args)
    {
        if (repositoryPath == null || scanning || actionRunning) { NextBaselineStatus.Text = "Choose a repository and wait for active operations."; return; }
        string repository = repositoryPath; actionRunning = true;
        try
        {
            var result = await DesktopActionRunner.Run(PythonPath.Text.Trim(), "diagnostics_preview", new { output_base = ScanLocations.ReportsBase(repository) }, cancellationToken: actionLifetime.Token);
            if (repositoryPath != repository || actionLifetime.IsCancellationRequested) return;
            var rows = result.GetProperty("generations").EnumerateArray().Where(row => row.GetProperty("status").GetString() == "succeeded" && row.GetProperty("run_id").GetString() != displayedRun).ToArray();
            foreach (var row in rows)
            {
                string run = row.GetProperty("run_id").GetString()!;
                if (run != ExportSelection.SafeName(run)) continue;
                string path = Path.Combine(ScanLocations.ReportsBase(repository), run, "attackmap-report.json");
                if (!File.Exists(path)) continue;
                var report = await ReportAdapter.Load(path);
                var selected = ExportSelection.CaptureSavedGeneration(path, report.ReadHash, report.Repository);
                if (!selected.Verified || report.Repository != repository) continue;
                BaselineOption.Text = path; NextBaselineStatus.Text = $"Previous retained baseline snapshot: {selected.RunId}; SHA-256 {selected.ReportHash}. It does not advance automatically."; return;
            }
            NextBaselineStatus.Text = "No other verified completed report is retained for this repository.";
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) NextBaselineStatus.Text = "Previous baseline unavailable. Existing selection preserved."; }
        finally { actionRunning = DesktopActionRunner.CleanupBlocked; }
    }

    private async Task RunFleet(IReadOnlyList<FleetRoot> repositories)
    {
        if (scanning || actionRunning || engine.CleanupBlocked || fleetSession.CleanupBlocked || DesktopActionRunner.CleanupBlocked) { Status.Text = "Wait for the active operation and verified cleanup."; return; }
        StopRepositoryWatch(); scanning = fleetRunning = true; ScanButton.IsEnabled = false; CancelButton.IsEnabled = true;
        long requestedGeneration = ++generation;
        using var admission = CancellationTokenSource.CreateLinkedTokenSource(actionLifetime.Token); scanAdmission = admission;
        Fleet.IsEnabled = ScanOptionsPanel.IsEnabled = Provider.IsEnabled = false;
        FleetGeneration? identity = null;
        try
        {
            string executable = EngineCapabilities.ResolveEngine(PythonPath.Text, AppContext.BaseDirectory);
            await DiscoverEngineCapabilities(admission.Token);
            admission.Token.ThrowIfCancellationRequested();
            if (generation != requestedGeneration || EngineCapabilities.ResolveEngine(PythonPath.Text, AppContext.BaseDirectory) != executable) throw new OperationCanceledException("Fleet selection changed before launch.");
            if (!capabilityCache.Current!.SchemaVersions.Contains("1.4")) throw new InvalidDataException("Selected engine does not support fleet schema 1.4.");
            string output = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", "fleet");
            await fleetSession.Run(executable, repositories, output, requestedGeneration,
                run => { identity = run; Fleet.Workspace.Begin(run); Fleet.IsEnabled = true; Fleet.Refresh(); },
                child => { if (!actionLifetime.IsCancellationRequested && identity != null) { Fleet.Workspace.ApplyChild(identity, child); Fleet.Refresh(); } },
                async result => {
                    if (actionLifetime.IsCancellationRequested || Fleet.Workspace.Active != result.Generation) return;
                    foreach (var child in result.Children) Fleet.Workspace.ApplyChild(result.Generation, child);
                    if (!Fleet.Workspace.Finish(result.Generation, result.Outcome)) throw new InvalidDataException("Fleet terminal did not match the selected children.");
                    Fleet.Refresh(); Status.Text = $"Fleet {result.Outcome}. Previous single-repository report remains selected until you explicitly open a child.";
                    if (result.IndexPath != null) await LoadFleetSummary(result);
                });
        }
        catch (Exception error)
        {
            if (identity != null && Fleet.Workspace.IsRunning)
            {
                foreach (var root in repositories.Where(root => !Fleet.Workspace.Children.Any(child => child.RepositoryId == root.RepositoryId && child.State is "completed" or "failed" or "cancelled" or "skipped")))
                    Fleet.Workspace.ApplyChild(identity, new(root.RepositoryId, root.RepositoryPath, "failed", null, null));
                int completed = Fleet.Workspace.Children.Count(child => child.State == "completed");
                Fleet.Workspace.Finish(identity, completed > 0 && completed < repositories.Count ? "partial" : "failed"); Fleet.Refresh();
            }
            if (!actionLifetime.IsCancellationRequested) Status.Text = "Fleet unavailable: " + error.Message;
        }
        finally { scanAdmission = null; scanning = fleetRunning = false; if (!actionLifetime.IsCancellationRequested) { ScanButton.IsEnabled = !engine.CleanupBlocked && !fleetSession.CleanupBlocked && !DesktopActionRunner.CleanupBlocked; Fleet.IsEnabled = ScanOptionsPanel.IsEnabled = Provider.IsEnabled = ScanButton.IsEnabled; CancelButton.IsEnabled = false; } }
    }

    private async Task LoadFleetSummary(FleetSessionResult result)
    {
        string folder = Path.GetDirectoryName(result.IndexPath!)!;
        string manifest = Path.Combine(folder, "artifact-manifest.json");
        if (!File.Exists(manifest)) return; // Partial generations can lack a complete rollup.
        byte[] manifestBytes = await ReadFleetBytes(manifest, 1024 * 1024);
        using var document = JsonDocument.Parse(manifestBytes);
        var root = document.RootElement;
        if (root.GetProperty("generation_profile").GetString() != "fleet" || root.GetProperty("generation_id").GetString() != result.Generation.RunId || root.GetProperty("exit_state").GetProperty("status").GetString() != "succeeded" || result.Outcome != "succeeded") throw new InvalidDataException("Fleet summary generation is not complete.");
        var sections = root.GetProperty("sections").EnumerateArray().ToArray();
        var index = sections.Single(row => row.GetProperty("path").GetString() == "desktop-fleet.json");
        if (index.GetProperty("checksum").GetString() != result.IndexHash) throw new InvalidDataException("Fleet manifest does not bind the broker index.");
        var children = root.GetProperty("children").EnumerateArray().ToArray();
        if (children.Length != result.Children.Count) throw new InvalidDataException("Fleet manifest child set differs.");
        foreach (var child in result.Children)
        {
            string relativeChild = Path.GetRelativePath(folder, Path.GetDirectoryName(child.ManifestPath!)!).Replace('\\', '/');
            if (children.Count(row => row.GetProperty("path").GetString() == relativeChild && row.GetProperty("manifest_sha256").GetString() == child.ManifestHash) != 1) throw new InvalidDataException("Fleet manifest child identity differs.");
        }
        var entry = sections.SingleOrDefault(row => row.GetProperty("name").GetString() == "fleet-summary.json");
        if (entry.ValueKind == JsonValueKind.Undefined) return;
        string relative = entry.GetProperty("path").GetString()!;
        if (Path.GetFileName(relative) != relative) throw new InvalidDataException("Invalid fleet summary path.");
        byte[] bytes = await ReadFleetBytes(Path.Combine(folder, relative), 64 * 1024 * 1024);
        if (ExportSelection.Hash(bytes) != entry.GetProperty("checksum").GetString() || ExportSelection.Hash(await ReadFleetBytes(manifest, 1024 * 1024)) != ExportSelection.Hash(manifestBytes)) throw new InvalidDataException("Fleet summary or manifest changed.");
        using var summary = JsonDocument.Parse(bytes);
        if (!actionLifetime.IsCancellationRequested && Fleet.Workspace.Active == result.Generation) Fleet.ShowSummary(result.Generation, FleetAdapter.Read(summary.RootElement));
    }
    private async Task OpenFleetChild(FleetOpenRepository request)
    {
        if (scanning || Fleet.Workspace.Active != request.Generation) return;
        try
        {
            byte[] manifest = await ReadFleetBytes(request.ManifestPath, 1024 * 1024);
            if (ExportSelection.Hash(manifest) != request.ManifestHash) throw new InvalidDataException("Fleet child manifest changed.");
            using var document = JsonDocument.Parse(manifest);
            string childRun = FleetSession.ChildRunId(request.Generation, request.Repository.RepositoryId);
            if (document.RootElement.GetProperty("generation_id").GetString() != childRun || document.RootElement.GetProperty("run_identity").GetProperty("repo_root").GetString() != request.Repository.RepositoryPath) throw new InvalidDataException("Fleet child identity mismatch.");
            string path = Path.Combine(Path.GetDirectoryName(request.ManifestPath)!, "attackmap-report.json");
            if (actionLifetime.IsCancellationRequested || Fleet.Workspace.Active != request.Generation) return;
            await LoadReport(path, new RunIdentity(childRun, request.Repository.RepositoryPath, request.Generation.Generation, DateTimeOffset.UtcNow));
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Fleet child unavailable or changed. Previous report preserved."; }
    }
    private static async Task<byte[]> ReadFleetBytes(string path, int limit)
    {
        for (FileSystemInfo? part = new FileInfo(path); part != null; part = part is FileInfo file ? file.Directory : ((DirectoryInfo)part).Parent)
            if ((part.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Redirected fleet artifact rejected.");
        await using var stream = File.OpenRead(path);
        if (stream.Length > limit) throw new InvalidDataException("Fleet artifact exceeds the preview limit.");
        byte[] bytes = new byte[(int)stream.Length]; await stream.ReadExactlyAsync(bytes);
        if (await stream.ReadAsync(new byte[1]) != 0) throw new InvalidDataException("Fleet artifact changed while reading.");
        return bytes;
    }
}
