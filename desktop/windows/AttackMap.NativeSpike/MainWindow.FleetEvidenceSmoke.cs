using AttackMap.GraphExplorer;
using AttackMap.GraphExplorer.Native;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    // Explicitly requested by --evidence-journey in the isolated actual-fleet QA entry point.
    private async Task<IReadOnlyList<object>> RunFleetEvidenceJourney(string directory, Action<string, bool, object?> check)
    {
        var source = fleetGraphSource ?? throw new InvalidDataException("Missing verified fleet graph.");
        await Fleet.SelectGraphSurface(true);
        var pane = FleetGraphSmokeChildren<FleetGraphPane>(Fleet).Single();
        var explorer = FleetGraphSmokeChildren<GraphExplorerView>(pane).Single();
        bool datastoreJourney = Environment.GetCommandLineArgs().Contains("--shared-datastore-journey");
        if (datastoreJourney)
        {
            var filter = FleetGraphSmokeChildren<CommandBar>(explorer)
                .Select(bar => bar.Content).OfType<ComboBox>().Single(control =>
                Microsoft.UI.Xaml.Automation.AutomationProperties.GetName(control) == "Relationship resolution filter");
            check("declared_filter_available", filter.Items.Contains("Declared"), null);
            filter.SelectedItem = "Declared";
            await ReadinessRenderBarrier();
            DateTimeOffset expires = DateTimeOffset.UtcNow.AddSeconds(20);
            bool CurrentDeclaredProjection() => explorer.Snapshot?.Context == source.Context &&
                explorer.CurrentProjection is { } current && ReferenceEquals(current.Document, source.Graph) &&
                current.Filter.Resolution == GraphResolutionFilter.Declared && current.Edges.Length > 0 &&
                current.Edges.All(edge => edge.Resolution == "declared");
            while (!CurrentDeclaredProjection() && DateTimeOffset.UtcNow < expires)
                await Task.Delay(50);
            check("declared_filter_current_projection", filter.SelectedItem?.ToString() == "Declared" &&
                CurrentDeclaredProjection(), null);
        }
        var projection = explorer.CurrentProjection ?? throw new InvalidDataException("Missing current graph projection.");
        var context = source.Context;
        var edge = projection.Edges.FirstOrDefault(candidate =>
        {
            if (datastoreJourney && (candidate.Kind != "shared_datastore" || candidate.Resolution != "declared" || candidate.Directed))
                return false;
            var selection = new FleetGraphSelection(context, candidate.Id, true, [], candidate.UnderlyingEdgeIds);
            return FleetGraphEvidenceNavigation.TryDescribe(source.Graph, context, selection, out var detail, out _) &&
                detail!.Items.Where(item => item.Record?.File != null && !item.EndpointOnly &&
                    FleetGraphEvidenceNavigation.BuildSourceRequest(source.Graph, context, selection, item.Id, out _) != null)
                    .Select(item => item.RepositoryId).Distinct().Count() >= 2;
        }) ?? throw new InvalidDataException("The actual fleet has no relationship with source evidence in two repositories.");
        explorer.Select(edge.Id, true);
        if (datastoreJourney)
            check("selected_datastore_is_declared_undirected", edge.Kind == "shared_datastore" &&
                edge.Resolution == "declared" && !edge.Directed, edge.UnderlyingEdgeIds);
        check("evidence_selected_original_relationship", pane.InspectSelectedEvidence(), edge.UnderlyingEdgeIds);
        var canonicalSelection = new FleetGraphSelection(context, edge.Id, true, [], edge.UnderlyingEdgeIds);
        FleetGraphEvidenceNavigation.TryDescribe(source.Graph, context, canonicalSelection, out var details, out _);
        var items = details!.Items.Where(item => item.Record?.File != null && !item.EndpointOnly &&
            FleetGraphEvidenceNavigation.BuildSourceRequest(source.Graph, context, canonicalSelection, item.Id, out _) != null)
            .GroupBy(item => item.RepositoryId).Select(group => group.First()).Take(2).ToArray();
        check("evidence_both_repository_sides_available", items.Length == 2, items.Select(item => new { item.Id, item.Side, item.RepositoryId }));
        var results = new List<object>();
        string captures = Path.Combine(directory, "evidence-journey"); Directory.CreateDirectory(captures);
        var retries = new List<string>();
        foreach (var item in items)
        {
            check("evidence_picker_selects_canonical_record", pane.InspectSelectedEvidence(item.Id), item.Id);
            var request = pane.SelectedSourceRequest ?? throw new InvalidDataException("Selected evidence has no safe source request.");
            check("evidence_request_current_and_qualified", Fleet.VerifyGraphSourceRequest(request) && request.Context == context,
                new { request.EvidenceId, request.GraphRepositoryId, request.RequestedRepositoryId, request.RepositoryRoot, request.RelativePath });
            check("evidence_tampered_root_rejected", !Fleet.VerifyGraphSourceRequest(request with { RepositoryRoot = request.RepositoryRoot + "-other" }), null);
            check("evidence_tampered_line_rejected", !Fleet.VerifyGraphSourceRequest(request with { Line = (request.Line ?? 1) + 1 }), null);
            check("evidence_old_context_rejected", !Fleet.VerifyGraphSourceRequest(request with { Context = context with { SelectionRevision = context.SelectionRevision + 1 } }), null);
            Task inspection = InspectFleetGraphSource(request);
            try
            {
                DateTimeOffset expires = DateTimeOffset.UtcNow.AddSeconds(15);
                while (fleetSourceDialog?.IsLoaded != true && !inspection.IsCompleted && DateTimeOffset.UtcNow < expires) await Task.Delay(50);
                var dialog = fleetSourceDialog ?? throw new InvalidDataException("Source dialog failed to open: " + Status.Text);
                await ReadinessRenderBarrier();
                check("evidence_live_source_inspected", fleetInspectedSource is { Status: "valid", LiveSha256.Length: 64 } &&
                    fleetInspectedSource.RelativePath == request.RelativePath && fleetInspectedSource.Line == request.Line, fleetInspectedSource);
                check("evidence_dialog_returns_to_graph", dialog.CloseButtonText == "Back to graph" && pane.VerifySourceRequest(request), null);
                string image = Path.Combine(captures, $"source-{results.Count + 1}.png");
                var content = (dialog.Content as ScrollViewer)?.Content as StackPanel
                    ?? throw new InvalidDataException("Source dialog has no evidence text panel.");
                var requiredText = content.Children.OfType<TextBlock>().Select((text, index) =>
                    NativeCaptureProbe.RequireTextRegion(dialog, text, $"source-detail-{index}")).ToArray();
                check("evidence_capture_requires_all_source_details", requiredText.Length == 4, requiredText.Length);
                Activate();
                await Task.Delay(650);
                var capture = await CaptureWithDiagnostics(dialog, image, requiredText);
                results.Add(new { request, inspection = fleetInspectedSource, capture,
                    sourceScope = "Current file location/hash inspection; no editor, source-content display, Explorer launch or runtime connectivity proof" });
            }
            finally { fleetSourceDialog?.Hide(); await inspection; }
            check("evidence_back_preserves_selected_record", !fleetSourceInspecting && fleetSourceDialog == null &&
                pane.VerifySourceRequest(request) && pane.SelectedSourceRequest?.EvidenceId == request.EvidenceId && Fleet.GraphContext == context, request.EvidenceId);
        }
        var root = (FrameworkElement)Content;
        foreach (var size in new[] { (Width: 1024, Height: 700), (Width: 1600, Height: 1000) })
        foreach (var theme in new[] { ElementTheme.Light, ElementTheme.Dark })
        {
            root.RequestedTheme = theme;
            double scale = root.XamlRoot.RasterizationScale;
            AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(size.Width * scale), (int)Math.Round(size.Height * scale)));
            await ReadinessRenderBarrier();
            pane.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false, VerticalAlignmentRatio = 0 });
            await ReadinessRenderBarrier();
            var capture = await CaptureFleetGraphSmoke(root, Path.Combine(captures, $"{size.Width}x{size.Height}-{theme}-evidence.png"), retries);
            results.Add(new { capture, provesOsAppearance = false, scope = "Native client render with selected relationship/evidence pane" });
        }
        var retained = pane.SelectedSourceRequest ?? throw new InvalidDataException("Evidence selection disappeared before back.");
        pane.CloseEvidenceInspector();
        await ReadinessRenderBarrier();
        check("evidence_inspector_back_restores_graph", !pane.IsInspectingEvidence && pane.VerifySourceRequest(retained) && explorer.Visibility == Visibility.Visible && explorer.ActualHeight > 150, null);
        return results;
    }
}
