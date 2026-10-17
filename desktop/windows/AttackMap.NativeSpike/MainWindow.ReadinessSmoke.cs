using System.Diagnostics;
using System.Text.Json;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Media;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    // Route through isolated smoke startup before any personal settings restore.
    internal async Task RunReadinessSmoke(string[] arguments)
    {
        int index = Array.IndexOf(arguments, "--readiness-smoke");
        if (index < 0 || index + 1 >= arguments.Length || !Path.IsPathFullyQualified(arguments[index + 1]))
            throw new ArgumentException("Readiness smoke requires a fresh absolute proof JSON path.");
        string proofPath = Path.GetFullPath(arguments[index + 1]);
        if (File.Exists(proofPath)) throw new IOException("Refusing to overwrite readiness evidence.");
        Directory.CreateDirectory(Path.GetDirectoryName(proofPath)!);
        const string expectedOutcome = "Choose a repository and wait for verified cleanup of any current action first.";
        string beforeStatus = Status.Text;
        double? localInvokeLatencyMilliseconds = null;
        double? processStartToPrimaryResponseMilliseconds = null;
        bool passed = false;
        string? error = null;
        try
        {
            await ReadinessRenderBarrier();
            if (!ScanButton.IsLoaded || ScanButton.ActualWidth <= 0 || ScanButton.ActualHeight < 32)
                throw new InvalidOperationException("Primary control is not laid out at its supported size.");
            var beforeOptions = ReadScanOptions();
            if (repositoryPath != null || scanning || actionRunning || lastScanOutput != null ||
                engine.CleanupBlocked || DesktopActionRunner.CleanupBlocked || !ScanButton.IsEnabled ||
                beforeOptions.Cve || beforeOptions.Provider?.EnableAi == true)
                throw new InvalidOperationException("Fresh isolated primary-action preconditions were not met.");
            if (beforeStatus == expectedOutcome) throw new InvalidOperationException("Expected response already existed before invocation.");
            var peer = FrameworkElementAutomationPeer.FromElement(ScanButton) ?? FrameworkElementAutomationPeer.CreatePeerForElement(ScanButton);
            var invoke = peer?.GetPattern(PatternInterface.Invoke) as IInvokeProvider
                ?? throw new InvalidOperationException("Primary Start scan button exposes no Invoke automation pattern.");
            var watch = Stopwatch.StartNew();
            invoke.Invoke();
            var deadline = Stopwatch.StartNew();
            // Event queue synchronization only: no fixed sleep is counted as readiness.
            while (Status.Text != expectedOutcome && deadline.Elapsed < TimeSpan.FromSeconds(5))
            {
                var remaining = TimeSpan.FromSeconds(5) - deadline.Elapsed;
                if (remaining <= TimeSpan.Zero) break;
                await ReadinessQueueBarrier().WaitAsync(remaining);
            }
            if (Status.Text != expectedOutcome) throw new TimeoutException("Primary action did not produce the expected missing-repository response.");
            watch.Stop();
            localInvokeLatencyMilliseconds = watch.Elapsed.TotalMilliseconds;
            using var process = Process.GetCurrentProcess();
            processStartToPrimaryResponseMilliseconds = (DateTime.UtcNow - process.StartTime.ToUniversalTime()).TotalMilliseconds;
            var afterOptions = ReadScanOptions();
            passed = !scanning && !actionRunning && lastScanOutput == null && repositoryPath == null &&
                presentation.ActiveRun == null && activeScanOptions == null && !afterOptions.Cve &&
                afterOptions.Provider?.EnableAi != true && !CancelButton.IsEnabled && ScanButton.IsEnabled;
        }
        catch (Exception failure) { error = failure.GetType().Name + ": " + failure.Message; }
        finally
        {
            File.WriteAllText(proofPath, JsonSerializer.Serialize(new
            {
                scope = "Primary Start scan button AutomationPeer Invoke response with no repository configured; fresh isolated startup",
                passed, expectedOutcome, actualOutcome = Status.Text, beforeStatus,
                processStartToPrimaryResponseMilliseconds, localInvokeLatencyMilliseconds,
                automaticScan = scanning, selectedRunOutput = lastScanOutput, error,
                windowVisible = AppWindow.IsVisible,
                c26Accepted = false, manualAcceptance = false,
                os = Environment.OSVersion.VersionString,
                limitations = new[] { "Measures missing-repository response only; does not verify Choose repository OS picker", "No source/provider picker, network, analyzer or model request", "Single diagnostic sample; not the 30-launch C26 campaign or Windows 11 hardware acceptance", "No manual keyboard, Narrator, visual or task-completion acceptance" }
            }, new JsonSerializerOptions { WriteIndented = true }));
            Close();
        }
    }

    private Task ReadinessQueueBarrier()
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => completion.SetResult()))
            completion.SetException(new InvalidOperationException("Readiness UI dispatcher stopped."));
        return completion.Task;
    }

    private static async Task ReadinessRenderBarrier()
    {
        int frames = 0;
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Rendering(object? sender, object args) { if (++frames >= 2) completion.TrySetResult(); }
        CompositionTarget.Rendering += Rendering;
        try { await completion.Task.WaitAsync(TimeSpan.FromSeconds(5)); }
        finally { CompositionTarget.Rendering -= Rendering; }
    }
}
