using System.Text.Json;
using System.Text.Json.Nodes;
using AttackMap.GraphExplorer;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

// Explicit full-shell QA. Graph responses are locally controlled; no engine or provider is called.
public sealed partial class MainWindow
{
    private async void ActivationSmokeLoaded(object sender, RoutedEventArgs args)
    {
        var root = (FrameworkElement)Content;
        root.Loaded -= ActivationSmokeLoaded;
        string[] arguments = Environment.GetCommandLineArgs();
        string directory = Path.GetFullPath(arguments[3]);
        string? failure = null;
        var checks = new List<object>();
        DateTimeOffset started = DateTimeOffset.UtcNow;
        object? result = null;
        void Check(string name, bool passed, object? detail = null)
        {
            checks.Add(new { name, passed, detail, at = DateTimeOffset.UtcNow });
            if (!passed) throw new InvalidDataException("Activation smoke failed: " + name);
        }
        async Task WaitFor(string name, Func<bool> predicate, Func<object?>? detail = null)
        {
            DateTimeOffset expires = DateTimeOffset.UtcNow.AddSeconds(20);
            while (!predicate() && DateTimeOffset.UtcNow < expires) await Task.Delay(50);
            Check(name, predicate(), detail?.Invoke());
        }
        try
        {
            ExportSelection.EnsureDestinationPath(Path.Combine(directory, "activation-smoke.json"));
            using (var claim = new FileStream(Path.Combine(directory, "activation-smoke.started"), FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
            string report = Path.GetFullPath(arguments[2]);
            Check("load_report_while_diagrams_hidden", await LoadReport(report) && Diagrams.Visibility == Visibility.Collapsed);
            Check("hidden_markdown_and_overview_builds_zero",
                ReviewText.RenderCount == 0 && AiReviewText.RenderCount == 0 && EvidenceOverview.BuildCount == 0,
                new { review = ReviewText.RenderCount, aiReview = AiReviewText.RenderCount, overview = EvidenceOverview.BuildCount });
            Check("hidden_raw_review_and_overview_model_retained",
                ReviewText.Text.Length > 0 && EvidenceOverview.Current?.ReadHash == displayedReadHash,
                new { reviewCharacters = ReviewText.Text.Length, overviewHash = EvidenceOverview.Current?.ReadHash, displayedReadHash });
            Check("hidden_graph_load_count_zero", Diagrams.GraphLoadCount == 0, Diagrams.GraphLoadCount);
            Check("hidden_legacy_selection_load_count_zero", Diagrams.LegacySelectionLoadCount == 0, Diagrams.LegacySelectionLoadCount);
            Check("hidden_interactive_initialization_attempts_zero", Diagrams.InteractiveInitializationAttemptCount == 0, Diagrams.InteractiveInitializationAttemptCount);
            Check("hidden_initialized_webview_cores_zero", renderDiagnosticsCores.Count == 0, renderDiagnosticsCores.Count);

            var selected = exportSelection ?? throw new InvalidDataException("Verified report selection is unavailable.");
            var gates = new Queue<TaskCompletionSource>();
            int loaderCalls = 0;
            TaskCompletionSource QueueGate()
            {
                var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                gates.Enqueue(gate);
                return gate;
            }
            Diagrams.GraphLoader = current =>
            {
                int call = ++loaderCalls;
                if (call == 1) _ = Diagrams.ActivateInteractive();
                var document = ActivationSmokeGraph(current, call);
                if (gates.Count == 0) return Task.FromResult(document);
                return AwaitControlled(gates.Dequeue(), document);
                static async Task<GraphDocument> AwaitControlled(TaskCompletionSource gate, GraphDocument graph)
                {
                    await gate.Task;
                    return graph;
                }
            };

            var initialGate = QueueGate();
            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Diagrams");
            await WaitFor("visible_graph_load_started_once", () => Diagrams.GraphLoadCount == 1 && loaderCalls == 1,
                () => new { Diagrams.GraphLoadCount, loaderCalls, activation = Diagrams.ActivationDiagnostics });
            await ReadinessRenderBarrier();
            Check("in_flight_graph_activation_is_coalesced", Diagrams.GraphLoadCount == 1 && loaderCalls == 1,
                new { Diagrams.GraphLoadCount, loaderCalls });
            Check("delayed_graph_is_not_bound_before_response", Diagrams.CurrentGraph == null);
            initialGate.SetResult();
            await WaitFor("visible_delayed_graph_bound_once", () => Diagrams.CurrentGraph != null && Diagrams.InteractiveInitializationAttemptCount == 1,
                () => new { Diagrams.GraphLoadCount, loaderCalls, hasGraph = Diagrams.CurrentGraph != null });
            await ReadinessRenderBarrier();
            Check("visible_graph_load_remains_once", Diagrams.GraphLoadCount == 1 && loaderCalls == 1, Diagrams.GraphLoadCount);
            Check("visible_interactive_initialization_attempt_once", Diagrams.InteractiveInitializationAttemptCount == 1, Diagrams.InteractiveInitializationAttemptCount);

            Navigation.SelectedItem = Navigation.MenuItems[1];
            await ReadinessRenderBarrier();
            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Diagrams");
            await ReadinessRenderBarrier();
            Check("repeated_navigation_does_not_duplicate_graph_load", Diagrams.GraphLoadCount == 1, Diagrams.GraphLoadCount);

            Diagrams.SelectLegacyView();
            await ReadinessRenderBarrier();
            Check("legacy_selection_loaded_once", Diagrams.LegacySelectionLoadCount == 1, Diagrams.LegacySelectionLoadCount);
            Diagrams.SelectInteractiveView();
            await ReadinessRenderBarrier();
            Diagrams.SelectLegacyView();
            await ReadinessRenderBarrier();
            Check("unchanged_legacy_selection_not_reloaded", Diagrams.LegacySelectionLoadCount == 1, Diagrams.LegacySelectionLoadCount);
            Diagrams.SelectInteractiveView();
            await ReadinessRenderBarrier();

            var delayedGate = QueueGate();
            Task delayedBinding = Diagrams.SetSelection(selected);
            await WaitFor("controlled_delayed_graph_started", () => loaderCalls == 2);
            Navigation.SelectedItem = Navigation.MenuItems[1];
            await ReadinessRenderBarrier();
            long attemptsBeforeRelease = Diagrams.InteractiveInitializationAttemptCount;
            delayedGate.SetResult();
            await delayedBinding;
            await ReadinessRenderBarrier();
            Check("hidden_delayed_load_does_not_initialize_interactive", Diagrams.InteractiveInitializationAttemptCount == attemptsBeforeRelease,
                new { attemptsBeforeRelease, after = Diagrams.InteractiveInitializationAttemptCount });
            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Diagrams");
            await ReadinessRenderBarrier();
            Check("return_binds_current_delayed_graph", Diagrams.CurrentGraph?.Context.SelectionRevision == 2, Diagrams.CurrentGraph?.Context);

            var staleGate = QueueGate();
            Task staleA = Diagrams.SetSelection(selected);
            await WaitFor("stale_load_a_started", () => loaderCalls == 3);
            var currentGate = QueueGate();
            Task currentB = Diagrams.SetSelection(selected);
            await WaitFor("current_load_b_started", () => loaderCalls == 4);
            currentGate.SetResult();
            await currentB;
            var expectedCurrent = Diagrams.CurrentGraph?.Context;
            Check("current_load_b_bound", expectedCurrent?.SelectionRevision == 4, expectedCurrent);
            staleGate.SetResult();
            await staleA;
            await ReadinessRenderBarrier();
            Check("stale_load_a_cannot_replace_b", Diagrams.CurrentGraph?.Context == expectedCurrent,
                new { expected = expectedCurrent, actual = Diagrams.CurrentGraph?.Context });

            string expectedReview = ReviewText.Text;
            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Reports");
            await ReadinessRenderBarrier();
            Check("visible_report_markdown_builds_once", ReviewText.RenderCount == 1 && ReviewText.Text == expectedReview && AiReviewText.RenderCount == 0,
                new { review = ReviewText.RenderCount, aiReview = AiReviewText.RenderCount });
            root.UpdateLayout();
            Navigation.SelectedItem = Navigation.MenuItems[1];
            await ReadinessRenderBarrier();
            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Reports");
            await ReadinessRenderBarrier();
            Check("repeated_report_activation_does_not_rebuild", ReviewText.RenderCount == 1 && AiReviewText.RenderCount == 0,
                new { review = ReviewText.RenderCount, aiReview = AiReviewText.RenderCount });
            Navigation.SelectedItem = Navigation.MenuItems[1];
            await ReadinessRenderBarrier();
            Check("reload_report_while_reports_hidden", await LoadReport(report));
            Check("hidden_reload_retains_content_without_builds",
                ReviewText.RenderCount == 1 && ReviewText.Text == expectedReview && EvidenceOverview.BuildCount == 0 && EvidenceOverview.Current?.ReadHash == displayedReadHash,
                new { review = ReviewText.RenderCount, overview = EvidenceOverview.BuildCount, overviewHash = EvidenceOverview.Current?.ReadHash });
            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Reports");
            await ReadinessRenderBarrier();
            Check("return_to_reports_builds_newest_once", ReviewText.RenderCount == 2 && ReviewText.Text == expectedReview, ReviewText.RenderCount);
            Navigation.SelectedItem = Navigation.MenuItems[0];
            EvidenceOverviewExpander.IsExpanded = true;
            await ReadinessRenderBarrier();
            var currentOverview = EvidenceOverview.Current;
            Check("visible_overview_builds_once_with_supplied_model",
                EvidenceOverview.BuildCount == 1 && currentOverview?.ReadHash == displayedReadHash && currentOverview.Counts.Count > 0 &&
                currentOverview.Risks.Items.Count + currentOverview.Paths.Items.Count + currentOverview.Actions.Items.Count + currentOverview.Strengths.Items.Count > 0,
                new { builds = EvidenceOverview.BuildCount, counts = currentOverview?.Counts.Count });
            var overviewLink = currentOverview == null ? null : currentOverview.Risks.Items.Concat(currentOverview.Paths.Items).Concat(currentOverview.Actions.Items).Concat(currentOverview.Strengths.Items)
                .Select(item => item.Link).FirstOrDefault(link => link != null);
            if (overviewLink == null)
            {
                var finding = all.First();
                overviewLink = new OverviewLink("finding", finding.Id, displayedRun, displayedReadHash);
                var fixtureEntry = new OverviewEntry(-1, finding.Id, "QA current-identity link fixture", "In-memory only; retained report unchanged.", overviewLink);
                currentOverview = currentOverview! with { Risks = currentOverview.Risks with { Items = [fixtureEntry, .. currentOverview.Risks.Items] } };
                long buildsBeforeFixture = EvidenceOverview.BuildCount;
                EvidenceOverview.SetOverview(currentOverview);
                await ReadinessRenderBarrier();
                Check("overview_synthetic_link_fixture_builds_once", EvidenceOverview.BuildCount == buildsBeforeFixture + 1, EvidenceOverview.BuildCount);
            }
            Check("overview_link_has_current_identity", overviewLink.Generation == displayedRun && overviewLink.ReportHash == displayedReadHash, overviewLink);
            NavigateOverviewRecord(overviewLink);
            await ReadinessRenderBarrier();
            Check("overview_link_navigates_current_generation", Heading.Text != "Overview" && displayedReadHash == overviewLink!.ReportHash,
                new { destination = Heading.Text, overviewLink, displayedRun, displayedReadHash });

            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Diagrams");
            await ReadinessRenderBarrier();
            (string Kind, string View, long Revision, Exception? Error)? observedFailure = null;
            void ObserveFailure(string kind, string view, long revision, Exception? error)
            {
                if (kind == "activation-failed") observedFailure = (kind, view, revision, error);
            }
            Diagrams.ActivationEvent += ObserveFailure;
            Diagrams.GraphLoader = current =>
            {
                ++loaderCalls;
                return Task.FromException<GraphDocument>(new InvalidDataException("Controlled graph retry fixture."));
            };
            await Diagrams.SetSelection(selected);
            Check("controlled_graph_failure_clears_current_document", Diagrams.CurrentGraph == null);
            Check("controlled_graph_failure_emits_diagnostic",
                observedFailure?.View == "interactive" && observedFailure?.Error is InvalidDataException &&
                observedFailure?.Error?.Message == "Controlled graph retry fixture.",
                new { observedFailure?.Kind, observedFailure?.View, observedFailure?.Revision, errorType = observedFailure?.Error?.GetType().Name });
            Diagrams.ActivationEvent -= ObserveFailure;
            Navigation.SelectedItem = Navigation.MenuItems[1];
            await ReadinessRenderBarrier();
            var retryGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Diagrams.GraphLoader = async current =>
            {
                int call = ++loaderCalls;
                await retryGate.Task;
                return ActivationSmokeGraph(current, call);
            };
            int callsBeforeRetry = loaderCalls;
            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Diagrams");
            await WaitFor("delayed_retry_graph_started", () => loaderCalls >= callsBeforeRetry + 1);
            await ReadinessRenderBarrier();
            Check("navigation_retry_graph_activation_is_coalesced", loaderCalls == callsBeforeRetry + 1,
                new { callsBeforeRetry, loaderCalls, Diagrams.GraphLoadCount });
            retryGate.SetResult();
            await WaitFor("delayed_retry_graph_bound", () => Diagrams.CurrentGraph != null);

            long graphReadsAtStop = Diagrams.GraphLoadCount;
            long legacyReadsAtStop = Diagrams.LegacySelectionLoadCount;
            long initializationAtStop = Diagrams.InteractiveInitializationAttemptCount;
            Diagrams.Stop();
            await Diagrams.SetSelection(selected);
            await Diagrams.ActivateInteractive();
            Diagrams.SelectLegacyView();
            root.UpdateLayout();
            await ReadinessRenderBarrier();
            Check("stopped_workspace_performs_no_reads_or_initialization",
                Diagrams.GraphLoadCount == graphReadsAtStop && Diagrams.LegacySelectionLoadCount == legacyReadsAtStop &&
                Diagrams.InteractiveInitializationAttemptCount == initializationAtStop,
                new { Diagrams.GraphLoadCount, Diagrams.LegacySelectionLoadCount, Diagrams.InteractiveInitializationAttemptCount });

            result = new
            {
                graphLoadCount = Diagrams.GraphLoadCount,
                legacySelectionLoadCount = Diagrams.LegacySelectionLoadCount,
                interactiveInitializationAttemptCount = Diagrams.InteractiveInitializationAttemptCount,
                initializedWebView2CoreCount = renderDiagnosticsCores.Count,
                currentGeneration = generation,
                displayedRun,
                displayedReadHash,
                currentGraphContext = Diagrams.CurrentGraph?.Context,
                diagnosticsPath = Path.Combine(directory, "diagnostics", "render-diagnostics.jsonl"),
                visualAcceptance = "not-established",
                providerCalls = 0
            };
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
                using var output = new FileStream(Path.Combine(directory, "activation-smoke.json"), FileMode.CreateNew, FileAccess.Write, FileShare.None);
                JsonSerializer.Serialize(output, new
                {
                    passed = failure == null && result != null,
                    started,
                    ended = DateTimeOffset.UtcNow,
                    result,
                    failure,
                    checks,
                    visualAcceptance = "not-established",
                    providerCalls = 0
                }, new JsonSerializerOptions { WriteIndented = true });
                output.Flush(flushToDisk: true);
            }
            finally { Close(); }
        }
    }

    private GraphDocument ActivationSmokeGraph(ExportSelection selected, int call)
    {
        string run = selected.RunId ?? "activation-smoke";
        string repository = paritySections?.Repository ?? throw new InvalidDataException("Report repository projection is unavailable.");
        var source = new JsonObject
        {
            ["schema_version"] = "1.0",
            ["kind"] = "fleet_architecture",
            ["repositories"] = new JsonArray(new JsonObject
            {
                ["id"] = "repo:activation", ["repo_id"] = "activation", ["requested_id"] = "single-report",
                ["root"] = repository, ["label"] = "activation", ["status"] = "completed"
            }),
            ["nodes"] = new JsonArray(new JsonObject
            {
                ["id"] = "repo:activation", ["kind"] = "repository", ["repo_id"] = "repo:activation",
                ["parent_id"] = null, ["label"] = "Activation controlled graph", ["evidence_refs"] = new JsonArray()
            }),
            ["edges"] = new JsonArray(),
            ["evidence"] = new JsonArray(),
            ["coverage"] = new JsonObject { ["scope"] = "controlled activation smoke" },
            ["limitations"] = new JsonArray("Controlled local QA graph; not a scan result.")
        };
        var context = new GraphContext(run, run, selected.ReportHash, call);
        return GraphReader.Read(System.Text.Encoding.UTF8.GetBytes(source.ToJsonString()), context);
    }
}
