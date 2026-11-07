using System.Text.Json;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    // --fault-smoke <absolute childless fault broker> <canonical previous report> <fresh proof JSON>
    // Root must route this flag through the smoke startup branch, bypassing personal settings.
    internal async Task RunFaultSmoke(string[] arguments)
    {
        int index = Array.IndexOf(arguments, "--fault-smoke");
        if (index < 0 || index + 3 >= arguments.Length) throw new ArgumentException("Fault smoke requires broker, previous report and fresh output paths.");
        string broker = Path.GetFullPath(arguments[index + 1]);
        string previousPath = Path.GetFullPath(arguments[index + 2]);
        string proofPath = Path.GetFullPath(arguments[index + 3]);
        if (File.Exists(proofPath)) throw new IOException("Refusing to overwrite fault smoke evidence.");
        Directory.CreateDirectory(Path.GetDirectoryName(proofPath)!);
        string faultOutput = Path.Combine(Path.GetDirectoryName(proofPath)!, "fault-run-" + Guid.NewGuid().ToString("N"));
        var checks = new Dictionary<string, bool>();
        string? error = null;
        int callbacks = 0;
        string? beforeHash = null;
        string? beforeRun = null;
        try
        {
            if (!await LoadReport(previousPath)) throw new InvalidDataException("Previous canonical report failed to load.");
            string? beforePath = displayedReportPath;
            beforeHash = displayedReadHash;
            beforeRun = displayedRun;
            var beforeRows = all;
            var beforePresentation = presentation.Displayed;
            var beforeExport = exportSelection;
            long beforeRevision = findingRevision;
            repositoryPath = displayedRepository;
            presentation.SelectRepository(repositoryPath);
            long requestGeneration = ++generation;
            RunIdentity? identity = null;
            string status = "";
            bool rejected = false;
            scanning = true;
            ScanButton.IsEnabled = false;
            CancelButton.IsEnabled = true;
            lastScanOutput = faultOutput;
            DiagnosticPath.Text = $"Selected local run folder: {faultOutput}. A terminal diagnostic is available only if the broker writes one.";
            try
            {
                await engine.Run(broker, repositoryPath, faultOutput, requestGeneration,
                    text => { status = text; presentation.Update(text); UpdateRunSummary(); },
                    async path =>
                    {
                        callbacks++;
                        if (!await LoadReport(path, identity)) throw new InvalidDataException("Completed engine artifacts could not be imported or verified.");
                    },
                    run => { identity = run; presentation.Begin(run); UpdateRunSummary(); },
                    options: new NativeScanOptions(), modules: "completed_exit7");
            }
            catch (InvalidDataException failure)
            {
                rejected = true;
                status = $"Scan result unavailable: {failure.Message}. Previous report retained.";
                Status.Text = status;
            }
            finally
            {
                scanning = false;
                presentation.End(status.Length == 0 ? "Run failed before terminal confirmation; previous report retained" : status);
                UpdateRunSummary();
                ScanButton.IsEnabled = !DesktopActionRunner.CleanupBlocked && !engine.CleanupBlocked;
                CancelButton.IsEnabled = false;
            }
            checks["abnormalBrokerExitRejected"] = rejected;
            checks["completedArtifactCallbackNotInvoked"] = callbacks == 0;
            checks["displayedPathAndReadHashPreserved"] = displayedReportPath == beforePath && displayedReadHash == beforeHash;
            checks["findingRowsAndRevisionPreserved"] = ReferenceEquals(all, beforeRows) && findingRevision == beforeRevision;
            checks["displayedRunAndExportSelectionPreserved"] = displayedRun == beforeRun && ReferenceEquals(exportSelection, beforeExport);
            checks["presentationRetainsPreviousReportIdentity"] = ReferenceEquals(presentation.Displayed, beforePresentation) && presentation.PreviousResult && presentation.ActiveRun == null;
            checks["failureStatusAndPreviousReportLabelVisible"] = Status.Text.Contains("Scan result unavailable", StringComparison.Ordinal) && RunSummary.Text.Contains("PREVIOUS VALID REPORT", StringComparison.Ordinal);
            checks["selectedDiagnosticFolderExistsAndIsReported"] = Directory.Exists(lastScanOutput) && lastScanOutput == faultOutput && DiagnosticPath.Text.Contains(faultOutput, StringComparison.Ordinal);
            checks["cleanupConfirmedScanAdmissionAvailable"] = !engine.CleanupBlocked && !DesktopActionRunner.CleanupBlocked && !scanning && ScanButton.IsEnabled && !CancelButton.IsEnabled;
            var root = (FrameworkElement)Content;
            foreach (var expander in FaultSmokeElements(root).OfType<Expander>())
                if (expander.Header?.ToString() == "Run identity and report coverage") expander.IsExpanded = true;
            var settled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => settled.SetResult())) throw new InvalidOperationException("UI dispatcher stopped.");
            await settled.Task;
            root.UpdateLayout();
            var buttons = FaultSmokeElements(root).OfType<Button>().ToArray();
            checks["revealFolderAndRetryControlsAvailable"] = buttons.Any(button => button.Content?.ToString() == "Reveal last scan folder" && button.IsEnabled) &&
                buttons.Any(button => button.Content?.ToString() == "Retry scan with current settings" && button.IsEnabled);
        }
        catch (Exception failure) { error = failure.GetType().Name + ": " + failure.Message; }
        finally
        {
            File.WriteAllText(proofPath, JsonSerializer.Serialize(new
            {
                scope = "Loaded MainWindow abnormal completed broker exit with actual report adapter, session and presentation state; programmatic UI composition only",
                passed = error == null && checks.Count == 10 && checks.Values.All(value => value),
                broker, previousPath, proofPath, faultOutput, beforeHash, beforeRun, callbacks, checks, error,
                diagnosticFileCreatedByFake = false,
                limitations = new[] { "No manual keyboard, Narrator, popup/dialog, DPI or visual acceptance", "Diagnostic folder/retry controls inspected; Explorer launch and retry execution not invoked", "Childless controlled broker; no real analyzer failure or worker descendants" }
            }, new JsonSerializerOptions { WriteIndented = true }));
            Close();
        }
    }

    private static IEnumerable<DependencyObject> FaultSmokeElements(DependencyObject root)
    {
        var pending = new Stack<DependencyObject>();
        pending.Push(root);
        int visited = 0;
        while (pending.Count > 0 && visited++ < 4096)
        {
            var element = pending.Pop();
            yield return element;
            for (int child = VisualTreeHelper.GetChildrenCount(element) - 1; child >= 0; child--)
                pending.Push(VisualTreeHelper.GetChild(element, child));
        }
    }
}
