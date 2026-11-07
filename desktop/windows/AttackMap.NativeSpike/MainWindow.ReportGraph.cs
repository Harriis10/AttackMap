using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AttackMap.GraphExplorer;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private long reportGraphRevision;
    private readonly SemaphoreSlim reportGraphGate = new(1, 1);

    private async Task<GraphDocument> LoadReportGraph(ExportSelection selected)
    {
        await reportGraphGate.WaitAsync(actionLifetime.Token);
        try { return await LoadReportGraphCore(selected); }
        finally { reportGraphGate.Release(); }
    }

    private async Task<GraphDocument> LoadReportGraphCore(ExportSelection selected)
    {
        if (!selected.Verified || exportSelection != selected || paritySections == null)
            throw new InvalidDataException("A verified displayed report is required.");
        string repository = paritySections.Repository;
        _ = SelectedArtifacts.List(selected);
        string executable = EngineCapabilities.ResolveEngine(PythonPath.Text, AppContext.BaseDirectory);
        var result = await DesktopActionRunner.Run(executable, "report_graph", new {
            report_path = selected.ReportPath, report_sha256 = selected.ReportHash,
            run_id = selected.RunId, repository_root = repository
        }, outputBase: providerRenderActionDirectory, cancellationToken: actionLifetime.Token);
        if (actionLifetime.IsCancellationRequested || exportSelection != selected || paritySections?.Repository != repository)
            throw new InvalidDataException("The displayed report changed while loading its graph.");
        _ = SelectedArtifacts.List(selected);
        if (result.GetProperty("report_sha256").GetString() != selected.ReportHash || result.GetProperty("run_id").GetString() != selected.RunId ||
            !string.Equals(Path.GetFullPath(result.GetProperty("repository_root").GetString()!), Path.GetFullPath(repository), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Graph identity differs from the selected report.");
        var context = new GraphContext(selected.RunId!, selected.RunId!, selected.ReportHash, ++reportGraphRevision);
        var graph = JsonNode.Parse(result.GetProperty("graph").GetRawText())!.AsObject();
        byte[] manifestBytes = await ReadFleetBytes(selected.ManifestPath!, 1024 * 1024);
        if (exportSelection != selected || ExportSelection.Hash(manifestBytes) != selected.ManifestHash)
            throw new InvalidDataException("The captured manifest changed while binding the graph.");
        using var manifest = JsonDocument.Parse(manifestBytes);
        string? snapshotId = null, snapshotAt = null;
        var identity = manifest.RootElement.GetProperty("run_identity");
        if (identity.TryGetProperty("snapshot", out var snapshot) && snapshot.TryGetProperty("snapshot_id", out var id)) snapshotId = id.GetString();
        if (manifest.RootElement.TryGetProperty("created_at", out var created)) snapshotAt = created.GetString();
        var repositories = graph["repositories"]!.AsArray();
        if (repositories.Count != 1 || !string.Equals(Path.GetFullPath(repositories[0]!["root"]!.GetValue<string>()), Path.GetFullPath(repository), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Single-report graph contains a different repository set.");
        var row = repositories[0]!.AsObject();
        row["requested_id"] = "single-report"; row["snapshot_id"] = snapshotId; row["snapshot_at"] = snapshotAt;
        row["host_binding"] = JsonSerializer.SerializeToNode(new { report_sha256 = selected.ReportHash, manifest_sha256 = selected.ManifestHash });
        graph["host_binding"] = JsonSerializer.SerializeToNode(new { run_id = selected.RunId, report_sha256 = selected.ReportHash, manifest_sha256 = selected.ManifestHash, single_report = true });
        return GraphReader.Read(Encoding.UTF8.GetBytes(graph.ToJsonString()), context);
    }

    private async Task InspectReportGraphSource(FleetGraphSourceRequest request)
    {
        var selected = exportSelection;
        if (selected?.Verified != true || Diagrams.CurrentGraph?.Context != request.Context || !Diagrams.GraphPane.VerifySourceRequest(request)) return;
        try
        {
            _ = SelectedArtifacts.List(selected);
            if (!string.Equals(Path.GetFullPath(request.RepositoryRoot), Path.GetFullPath(paritySections!.Repository), StringComparison.OrdinalIgnoreCase)) return;
            await InspectParitySource(request.RelativePath, request.Line);
            if (exportSelection == selected && Diagrams.CurrentGraph?.Context == request.Context)
                Diagrams.GraphPane.BackToSelection(request);
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Selected graph source is no longer available; reopen the report."; }
    }

    private async Task ExportReportGraph(FleetGraphExport request)
    {
        var selected = exportSelection;
        if (selected?.Verified != true || Diagrams.CurrentGraph?.Context != request.Context || request.Extension is not (".json" or ".svg")) return;
        try
        {
            var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = "attackmap-architecture-" + ExportSelection.SafeName(selected.RunId!) };
            picker.FileTypeChoices.Add(request.Extension == ".svg" ? "Entire architecture diagram SVG" : "Complete captured graph JSON", new List<string> { request.Extension });
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            var file = await picker.PickSaveFileAsync();
            if (file == null || actionLifetime.IsCancellationRequested || exportSelection != selected || Diagrams.CurrentGraph?.Context != request.Context) return;
            _ = SelectedArtifacts.List(selected);
            selected.EnsureExportDestination(file.Path, selected.ReportPath);
            await WriteSelectedBytes(file.Path, Encoding.UTF8.GetBytes(request.Content));
            Status.Text = "Exported the complete selected architecture projection. " + selected.Disclosure;
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Architecture export unavailable or the selected report changed; reopen and retry."; }
    }
}
