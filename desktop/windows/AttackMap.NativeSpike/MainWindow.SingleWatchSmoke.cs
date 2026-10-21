using Microsoft.UI.Xaml;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private async Task<object> RunSingleWatchSmoke(string directory)
    {
        string fixture = Path.Combine(directory, "single-watch-fixtures");
        if (Directory.Exists(fixture)) throw new IOException("Repository-watch verification fixture must be new.");
        string[] roots = Enumerable.Range(1, 2).Select(n => Path.Combine(fixture, "repository-" + n)).ToArray();
        foreach (string root in roots)
        {
            Directory.CreateDirectory(root);
            File.WriteAllText(Path.Combine(root, "app.py"), "from flask import Flask\napp = Flask(__name__)\n@app.route('/status')\ndef status():\n    return {'status': 'ok'}\n");
        }
        var observed = new System.Collections.Concurrent.ConcurrentQueue<RepositoryWatchRequest>();
        void Observed(RepositoryWatchRequest request) => observed.Enqueue(request);
        repositoryWatch.ScanRequested += Observed;
        repositoryWatchVerificationOutput = Path.Combine(directory, "single-watch-reports");
        string ignoredOutput = Path.Combine(roots[0], ".owned-watch-output-canary");
        bool defaultOff = WatchOption.IsChecked != true && !repositoryWatch.Enabled;
        try
        {
            ApplyScanOptions(new NativeScanOptions(TimeoutSeconds: 1200), "python-web,config");
            SelectRepositoryPath(roots[0]);
            WatchOption.IsChecked = true;
            if (!repositoryWatch.Start(roots[0], new[] { repositoryWatchVerificationOutput, ignoredOutput, DesktopActionRunner.ActionDirectory }))
                throw new InvalidDataException(repositoryWatch.Notice);
            RefreshRepositoryWatchNotice();
            await Task.Delay(1400);
            bool explicitOptInIdle = !scanning && observed.IsEmpty;
            File.WriteAllText(Path.Combine(roots[0], "created.py"), "# created after watch opt-in\n");
            await WaitForFleetSmoke(() => presentation.ActiveRun != null && scanning, TimeSpan.FromMinutes(3));
            var first = presentation.ActiveRun!;
            File.AppendAllText(Path.Combine(roots[0], "app.py"), "\n# edited during first scan\n");
            File.Move(Path.Combine(roots[0], "created.py"), Path.Combine(roots[0], "renamed.py"));
            File.Delete(Path.Combine(roots[0], "renamed.py"));
            await WaitForFleetSmoke(() => observed.Count >= 2 && !scanning && displayedRun != first.RunId && displayedRepository == roots[0], TimeSpan.FromMinutes(10));
            bool oneFullFollowup = observed.Count == 2 && observed.All(r => r.RepositoryRoot == roots[0] && r.FullRescan)
                && exportSelection?.Verified == true && scanProgress is { State: "completed", Terminal: true };
            if (!oneFullFollowup) throw new InvalidDataException("Repository watch did not settle one full follow-up: " + Status.Text);
            string? completedRun = displayedRun, completedHash = displayedReadHash;
            Directory.CreateDirectory(ignoredOutput);
            File.WriteAllText(Path.Combine(ignoredOutput, "ignored-output.txt"), "Watcher-only exclusion canary; actual reports remain outside fixture roots.");
            await Task.Delay(1800);
            bool ownedOutputIgnored = !scanning && observed.Count == 2 && !repositoryWatch.Pending && displayedRun == completedRun;
            var captures = await CaptureWatchView(directory, "Repository-watch", 6);
            StopRepositoryWatch();
            File.AppendAllText(Path.Combine(roots[0], "app.py"), "\n# stopped watch remains silent\n");
            await Task.Delay(1400);
            bool stopped = !scanning && !repositoryWatch.Enabled && observed.Count == 2;
            WatchOption.IsChecked = true;
            File.AppendAllText(Path.Combine(roots[0], "app.py"), "\n# next actual worker is cancelled\n");
            await WaitForFleetSmoke(() => presentation.ActiveRun != null && scanning, TimeSpan.FromMinutes(3));
            var cancelled = presentation.ActiveRun!;
            CancelScan(this, new RoutedEventArgs());
            await WaitForFleetSmoke(() => !scanning, TimeSpan.FromMinutes(3));
            bool cancelledSettled = !repositoryWatch.Enabled && WatchOption.IsChecked != true
                && scanProgress is { State: "cancelled", Terminal: true } && !engine.CleanupBlocked
                && !DesktopActionRunner.CleanupBlocked && !fleetSession.CleanupBlocked;
            bool reportPreserved = displayedRun == completedRun && displayedReadHash == completedHash;
            SelectRepositoryPath(roots[1]);
            File.AppendAllText(Path.Combine(roots[0], "app.py"), "\n# old selection remains silent\n");
            await Task.Delay(1400);
            bool oldRootIgnored = !repositoryWatch.Enabled && !scanning && observed.Count == 3 && !repositoryWatch.Pending;
            if (!(defaultOff && explicitOptInIdle && ownedOutputIgnored && stopped && cancelledSettled && reportPreserved && oldRootIgnored))
                throw new InvalidDataException("Repository watch isolation/cancel assertion failed: " + Status.Text);
            return new { passed = true, defaultOff, explicitOptInIdle, oneFullFollowup, ownedOutputIgnored, stopped, cancelledSettled,
                reportPreserved, oldRootIgnored, first, completedRun, cancelled, observed = observed.ToArray(), captures,
                outputRoot = repositoryWatchVerificationOutput, actualEngine = true, providerCallsRequested = false, acceptedManualUi = false };
        }
        finally { StopRepositoryWatch(); repositoryWatch.ScanRequested -= Observed; repositoryWatchVerificationOutput = null; }
    }

    private async Task<IReadOnlyList<CaptureMetadata>> CaptureWatchView(string directory, string name, int navigationIndex)
    {
        var root = (FrameworkElement)Content;
        var captures = new List<CaptureMetadata>();
        Navigation.SelectedItem = Navigation.MenuItems[navigationIndex];
        foreach (var size in new[] { (Width: 1024, Height: 700), (Width: 1600, Height: 1000) })
        foreach (var theme in new[] { ElementTheme.Light, ElementTheme.Dark })
        {
            root.RequestedTheme = theme;
            double scale = root.XamlRoot.RasterizationScale;
            AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(size.Width * scale), (int)Math.Round(size.Height * scale)));
            await Task.Delay(450);
            await ReadinessRenderBarrier();
            if (navigationIndex == 6) WatchOption.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false });
            captures.Add(await NativeCaptureProbe.Capture(root, Path.Combine(directory, $"{size.Width}x{size.Height}-{theme}-{name}.png")));
        }
        return captures;
    }
}
