using System.Text;
using System.Text.Json;
using AttackMap.GraphExplorer;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private sealed record FleetGraphSource(GraphContext Context, string SummaryPath, string SummaryHash, string IntegrityPath, string IntegrityHash, IReadOnlyList<FleetChildStatus> Children, GraphDocument Graph);
    private FleetGraphSource? fleetGraphSource;
    private bool fleetSourceInspecting;
    private ContentDialog? fleetSourceDialog;
    private SourceLocationResult? fleetInspectedSource;

    private async Task BindFleetGraph(FleetSessionResult result, JsonElement summary, byte[] bytes, string summaryPath, string integrityPath, string integrityHash)
    {
        if (!summary.TryGetProperty("fleet_architecture", out var architecture)) return; // Older engines retain the text view.
        var snapshots = new List<FleetSnapshotBinding>();
        foreach (var child in result.Children.Where(child => child.State == "completed"))
        {
            byte[] manifest = await ReadFleetBytes(child.ManifestPath!, 1024 * 1024);
            if (ExportSelection.Hash(manifest) != child.ManifestHash) throw new InvalidDataException("Fleet child manifest changed before graph binding.");
            using var document = JsonDocument.Parse(manifest);
            var root = document.RootElement;
            if (root.GetProperty("generation_id").GetString() != FleetSession.ChildRunId(result.Generation, child.RepositoryId) ||
                !string.Equals(Path.GetFullPath(root.GetProperty("run_identity").GetProperty("repo_root").GetString()!), Path.GetFullPath(child.RepositoryPath), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Fleet graph child identity mismatch.");
            string? snapshotId = root.GetProperty("run_identity").TryGetProperty("snapshot", out var snapshot) && snapshot.TryGetProperty("snapshot_id", out var id) ? id.GetString() : null;
            snapshots.Add(new(child.RepositoryId, child.ManifestHash!, snapshotId, root.TryGetProperty("created_at", out var captured) ? captured.GetString() : null));
        }
        var context = new GraphContext(result.Generation.RunId, result.Generation.RunId, ExportSelection.Hash(bytes), result.Generation.Generation);
        var graph = FleetGraphBinding.Bind(Encoding.UTF8.GetBytes(architecture.GetRawText()), context, Fleet.Workspace, snapshots);
        if (actionLifetime.IsCancellationRequested || Fleet.Workspace.Active != result.Generation) return;
        if (ExportSelection.Hash(await ReadFleetBytes(summaryPath, 64 * 1024 * 1024)) != context.ReportHash ||
            ExportSelection.Hash(await ReadFleetBytes(integrityPath, 1024 * 1024)) != integrityHash)
            throw new InvalidDataException("Fleet graph source changed during binding.");
        if (actionLifetime.IsCancellationRequested || Fleet.Workspace.Active != result.Generation || Fleet.Workspace.IsRunning) return;
        fleetGraphSource = new(context, summaryPath, context.ReportHash, integrityPath, integrityHash, result.Children.ToArray(), graph);
        await Fleet.ShowArchitecture(result.Generation, graph);
    }

    private bool FleetSourceIsCurrent(FleetGraphSourceRequest request, FleetGraphSource source) =>
        !actionLifetime.IsCancellationRequested && !scanning && !fleetRunning && fleetGraphSource == source &&
        Fleet.GraphContext == request.Context && source.Context == request.Context &&
        Fleet.VerifyGraphSourceRequest(request) &&
        FleetGraphEvidenceNavigation.TryValidate(source.Graph, request.Context, request, out _);

    private async Task<FleetOpenRepository> VerifyFleetGraphSource(FleetGraphSourceRequest request, FleetGraphSource source)
    {
        if (!FleetSourceIsCurrent(request, source)) throw new InvalidDataException("The selected graph evidence changed.");
        var child = Fleet.Workspace.Open(request.RequestedRepositoryId)
            ?? throw new InvalidDataException("The evidence has no completed verified child result.");
        var bound = source.Children.SingleOrDefault(item => item.RepositoryId == request.RequestedRepositoryId && item.State == "completed");
        if (bound == null || bound.ManifestPath != child.ManifestPath || bound.ManifestHash != child.ManifestHash ||
            !string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(child.Repository.RepositoryPath)), request.RepositoryRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The evidence repository identity differs from the captured fleet.");
        if (ExportSelection.Hash(await ReadFleetBytes(source.SummaryPath, 64 * 1024 * 1024)) != source.SummaryHash ||
            ExportSelection.Hash(await ReadFleetBytes(source.IntegrityPath, 1024 * 1024)) != source.IntegrityHash)
            throw new InvalidDataException("The captured fleet evidence changed; reopen the result.");
        byte[] bytes = await ReadFleetBytes(child.ManifestPath, 1024 * 1024);
        if (ExportSelection.Hash(bytes) != child.ManifestHash) throw new InvalidDataException("The evidence child manifest changed.");
        using var manifest = JsonDocument.Parse(bytes);
        var root = manifest.RootElement;
        var identity = root.GetProperty("run_identity");
        string? snapshotId = identity.TryGetProperty("snapshot", out var snapshot) && snapshot.TryGetProperty("snapshot_id", out var id) ? id.GetString() : null;
        string? snapshotAt = root.TryGetProperty("created_at", out var captured) ? captured.GetString() : null;
        if (root.GetProperty("generation_id").GetString() != FleetSession.ChildRunId(child.Generation, child.Repository.RepositoryId) ||
            !string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(identity.GetProperty("repo_root").GetString()!)), request.RepositoryRoot, StringComparison.OrdinalIgnoreCase) ||
            snapshotId != request.SnapshotId || snapshotAt != request.SnapshotAt || !FleetSourceIsCurrent(request, source))
            throw new InvalidDataException("The source request does not match the verified child snapshot.");
        return child;
    }

    private async Task InspectFleetGraphSource(FleetGraphSourceRequest request)
    {
        var source = fleetGraphSource;
        if (fleetSourceInspecting || source == null || !FleetSourceIsCurrent(request, source)) return;
        fleetSourceInspecting = true; fleetInspectedSource = null;
        ContentDialog? dialog = null;
        try
        {
            await VerifyFleetGraphSource(request, source);
            string json = JsonSerializer.Serialize(new { locations = new[] { new { file = request.RelativePath, line = request.Line } } });
            var locations = await Task.Run(() => SourceLocation.Inspect(request.RepositoryRoot, json));
            if (!FleetSourceIsCurrent(request, source)) return;
            var location = locations.SingleOrDefault();
            fleetInspectedSource = location;
            var content = new StackPanel { Spacing = 8, MaxWidth = 560 };
            content.Children.Add(new TextBlock { Text = $"Repository: {request.RepositoryRoot}\nSource: {request.RelativePath}\nLine: {request.Line?.ToString() ?? "unknown"}", TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            content.Children.Add(new TextBlock { Text = $"Captured snapshot: {request.SnapshotId ?? "unknown"}\nCaptured at: {request.SnapshotAt ?? "unknown"}", TextWrapping = TextWrapping.Wrap });
            content.Children.Add(new TextBlock { Text = location?.Warning ?? "Source is unavailable.", TextWrapping = TextWrapping.Wrap });
            content.Children.Add(new TextBlock { Text = $"Live file inspection: {location?.Status ?? "unavailable"}. This check does not verify a relationship or runtime behavior.", TextWrapping = TextWrapping.Wrap });
            dialog = new ContentDialog { XamlRoot = ((FrameworkElement)Content).XamlRoot,
                Title = "Fleet evidence source location", Content = new ScrollViewer { Content = content, MaxHeight = 380 }, CloseButtonText = "Back to graph" };
            if (location is { Status: "valid", FullPath: not null }) dialog.PrimaryButtonText = "Show folder";
            fleetSourceDialog = dialog;
            using var registration = actionLifetime.Token.Register(() => DispatcherQueue.TryEnqueue(() => dialog.Hide()));
            var result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary && location is { Status: "valid", FullPath: not null })
            {
                await VerifyFleetGraphSource(request, source);
                var current = (await Task.Run(() => SourceLocation.Inspect(request.RepositoryRoot, json))).SingleOrDefault();
                if (current is not { Status: "valid", FullPath: not null } || current.FullPath != location.FullPath || !FleetSourceIsCurrent(request, source)) return;
                var folder = await Windows.Storage.StorageFolder.GetFolderFromPathAsync(Path.GetDirectoryName(current.FullPath)!);
                if (FleetSourceIsCurrent(request, source)) await Windows.System.Launcher.LaunchFolderAsync(folder);
            }
            if (FleetSourceIsCurrent(request, source)) Fleet.BackToGraphSelection(request);
        }
        catch (Exception error) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Fleet source inspection unavailable: " + error.Message; }
        finally { if (ReferenceEquals(fleetSourceDialog, dialog)) fleetSourceDialog = null; fleetSourceInspecting = false; }
    }

    private async Task LoadPartialFleetSummary(FleetSessionResult result)
    {
        if (result.IndexPath == null || result.IndexHash == null || result.Outcome != "partial") return;
        byte[] indexBytes = await ReadFleetBytes(result.IndexPath, 1024 * 1024);
        if (ExportSelection.Hash(indexBytes) != result.IndexHash) throw new InvalidDataException("Partial fleet index changed.");
        using var index = JsonDocument.Parse(indexBytes);
        var root = index.RootElement;
        if (root.GetProperty("kind").GetString() != "fleet_index" || root.GetProperty("run_id").GetString() != result.Generation.RunId ||
            root.GetProperty("repository_id").GetString() != result.Generation.RepositorySetId || root.GetProperty("generation").GetInt64() != result.Generation.Generation)
            throw new InvalidDataException("Partial graph does not match the selected fleet.");
        var rows = root.GetProperty("children").EnumerateArray().ToArray();
        if (rows.Length != result.Children.Count) throw new InvalidDataException("Partial graph child set differs.");
        foreach (var child in result.Children)
            if (rows.Count(row => row.GetProperty("child_repository_id").GetString() == child.RepositoryId &&
                row.GetProperty("child_repository_path").GetString() == child.RepositoryPath && row.GetProperty("state").GetString() == child.State &&
                row.GetProperty("manifest_sha256").GetString() == child.ManifestHash && row.GetProperty("manifest_path").GetString() == child.ManifestPath) != 1)
                throw new InvalidDataException("Partial graph child proof differs.");
        if (!root.TryGetProperty("fleet_summary", out var reference)) return;
        if (reference.GetProperty("path").GetString() != "fleet-summary.json") throw new InvalidDataException("Invalid partial summary path.");
        string path = Path.Combine(Path.GetDirectoryName(result.IndexPath)!, "fleet-summary.json");
        byte[] bytes = await ReadFleetBytes(path, 64 * 1024 * 1024);
        if (ExportSelection.Hash(bytes) != reference.GetProperty("sha256").GetString()) throw new InvalidDataException("Partial summary changed.");
        using var summary = JsonDocument.Parse(bytes);
        if (actionLifetime.IsCancellationRequested || Fleet.Workspace.Active != result.Generation) return;
        Fleet.ShowSummary(result.Generation, FleetAdapter.Read(summary.RootElement));
        await BindFleetGraph(result, summary.RootElement, bytes, path, result.IndexPath, result.IndexHash);
        if (!actionLifetime.IsCancellationRequested && Fleet.Workspace.Active == result.Generation && !Fleet.Workspace.IsRunning)
            Status.Text = "Partial fleet diagnostic: successful child results retained; this is not a complete published fleet.";
    }

    private async Task ExportFleetGraph(FleetGraphExport request)
    {
        var selected = fleetGraphSource;
        if (selected == null || selected.Context != request.Context || Fleet.GraphContext != request.Context || Fleet.Workspace.IsRunning ||
            Fleet.Workspace.Active?.RunId != request.Context.RunId || request.Extension is not (".json" or ".svg")) return;
        try
        {
            var picker = new Windows.Storage.Pickers.FileSavePicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.SuggestedFileName = "attackmap-fleet-" + ExportSelection.SafeName(request.Context.RunId);
            picker.FileTypeChoices.Add(request.Extension == ".svg" ? "Entire fleet diagram SVG" : "Complete captured fleet graph JSON", new List<string> { request.Extension });
            var destination = await picker.PickSaveFileAsync();
            if (destination == null || actionLifetime.IsCancellationRequested || Fleet.GraphContext != request.Context || fleetGraphSource != selected || Fleet.Workspace.IsRunning) return;
            if (ExportSelection.Hash(await ReadFleetBytes(selected.SummaryPath, 64 * 1024 * 1024)) != selected.SummaryHash ||
                ExportSelection.Hash(await ReadFleetBytes(selected.IntegrityPath, 1024 * 1024)) != selected.IntegrityHash)
                throw new InvalidDataException("Selected fleet source changed; reopen before exporting.");
            foreach (var child in selected.Children.Where(child => child.State == "completed"))
                if (ExportSelection.Hash(await ReadFleetBytes(child.ManifestPath!, 1024 * 1024)) != child.ManifestHash)
                    throw new InvalidDataException("Selected fleet child changed; reopen before exporting.");
            string folder = Path.GetDirectoryName(selected.SummaryPath)!;
            string relative = Path.GetRelativePath(folder, destination.Path);
            if (!Path.IsPathFullyQualified(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar))
                throw new InvalidDataException("Export outside the captured generation directory.");
            ExportSelection.EnsureDestinationPath(destination.Path);
            string temporary = destination.Path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                await File.WriteAllTextAsync(temporary, request.Content, new UTF8Encoding(false));
                if (actionLifetime.IsCancellationRequested || Fleet.GraphContext != request.Context || fleetGraphSource != selected) return;
                ExportSelection.EnsureDestinationPath(destination.Path); File.Move(temporary, destination.Path, overwrite: true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            if (!actionLifetime.IsCancellationRequested) Status.Text = "Exported the entire selected fleet diagram/model with context and coverage metadata.";
        }
        catch (Exception error) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Fleet graph export unavailable: " + error.Message; }
    }
}
