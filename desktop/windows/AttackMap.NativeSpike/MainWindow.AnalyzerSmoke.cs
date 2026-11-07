using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private readonly List<string> analyzerCaptureRetries = new();
    // Explicit QA entry point; all settings, reports and captures stay in the caller's directory.
    private async void AnalyzerSmokeLoaded(object sender, RoutedEventArgs args)
    {
        var root = (FrameworkElement)Content;
        root.Loaded -= AnalyzerSmokeLoaded;
        string[] arguments = Environment.GetCommandLineArgs();
        string directory = Path.GetFullPath(arguments[Array.IndexOf(arguments, "--analyzer-smoke") + 1]);
        var captures = new List<CaptureMetadata>();
        object? result = null;
        string? failure = null;
        try
        {
            if (!Directory.Exists(directory) || File.Exists(Path.Combine(directory, "analyzer-smoke.json")))
                throw new IOException("Create a fresh caller-owned analyzer QA directory.");
            string Argument(string name)
            {
                int position = Array.IndexOf(arguments, name);
                if (position < 0 || position + 1 >= arguments.Length) throw new ArgumentException(name);
                return arguments[position + 1];
            }
            recentStore = new HistoryPrep.RecentRepositoriesStore(Path.Combine(directory, "recent.json"));
            PythonPath.Text = Path.GetFullPath(Argument("--engine"));
            await DiscoverEngineCapabilities();
            string profile = Argument("--analyzer-profile");
            analyzerSelection.SelectProfile(profile);
            analyzerView!.Refresh();
            ApplyScanOptions(new NativeScanOptions(AnalyzerProfile: profile), analyzerSelection.ExpandedProfileModules);
            analyzerSelection.ValidateForScan();
            SaveLocalSettings(this, new RoutedEventArgs());
            var saved = settings.Load();
            if (saved.EffectiveOptions.AnalyzerProfile != profile || string.IsNullOrEmpty(saved.Modules))
                throw new InvalidDataException("Named profile settings were not preserved.");
            ApplyScanOptions(saved.EffectiveOptions, saved.Modules);
            analyzerSelection.ValidateForScan();
            string request = NativeScanRequest.Serialize("profile-qa", directory, directory, 1, ReadScanOptions(), analyzerSelection.RequestModules);
            File.WriteAllText(Path.Combine(directory, "profile-request.json"), request);
            bool staleBlocked = false;
            analyzerSelection.EngineChanged();
            try { analyzerSelection.ValidateForScan(); } catch (InvalidDataException) { staleBlocked = true; }
            capabilityCache.Invalidate();
            await DiscoverEngineCapabilities();
            analyzerSelection.ValidateForScan();
            if (!staleBlocked || analyzerSelection.RequestProfile != profile)
                throw new InvalidDataException("Engine refresh lost profile identity or did not block stale discovery.");
            bool scanned = arguments.Contains("--native-scan");
            if (scanned)
            {
                repositoryPath = Path.GetFullPath(Argument("--repository"));
                presentation.SelectRepository(repositoryPath);
                await RunSelectedRepository(Path.Combine(directory, "reports"));
                if (scanProgress.State != "completed" || !scanProgress.Terminal || exportSelection?.Verified != true)
                    throw new InvalidDataException("Profile native scan did not publish a verified generation: " + Status.Text);
            }
            Navigation.SelectedItem = Navigation.MenuItems[6];
            AdvancedOptions.IsExpanded = AnalyzerPicker.IsExpanded = true;
            await Task.Delay(450); // Let the native Expander transition finish before positioning the review viewport.
            foreach (var size in new[] { (Width: 1024, Height: 700), (Width: 1600, Height: 1000) })
            foreach (var theme in new[] { ElementTheme.Light, ElementTheme.Dark })
            {
                root.RequestedTheme = theme;
                double scale = root.XamlRoot.RasterizationScale;
                AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(size.Width * scale), (int)Math.Round(size.Height * scale)));
                await ReadinessRenderBarrier();
                root.UpdateLayout();
                var position = AnalyzerPicker.TransformToVisual(ScanOptionsPanel).TransformPoint(new Windows.Foundation.Point());
                ScanOptionsPanel.ChangeView(null, ScanOptionsPanel.VerticalOffset + position.Y, null, true);
                await ReadinessRenderBarrier();
                captures.Add(await CaptureAnalyzerReview(root, Path.Combine(directory, $"{size.Width}x{size.Height}-{theme}-Analyzers.png")));
            }
            var ledger = AnalyzerReviewChildren<Expander>(analyzerView!).Single(item => item.Name == "AnalyzerRunLedger");
            var innerScroll = AnalyzerReviewChildren<ScrollViewer>(analyzerView!).First();
            foreach (bool showLedger in new[] { true, false })
            {
                ledger.IsExpanded = showLedger;
                if (showLedger)
                {
                    await ReadinessRenderBarrier();
                    var firstRecord = AnalyzerReviewChildren<Expander>(ledger).FirstOrDefault();
                    if (firstRecord != null) firstRecord.IsExpanded = true;
                }
                if (!showLedger) AnalyzerReviewChildren<TextBox>(analyzerView!)
                    .First(text => text.PlaceholderText == "Filter installed analyzers").Text = "php-laminas";
                await Task.Delay(450);
                root.UpdateLayout();
                FrameworkElement target = showLedger ? ledger : AnalyzerReviewChildren<CheckBox>(analyzerView!)
                    .First(check => check.Content is TextBlock text && text.Text.EndsWith("(php-laminas)", StringComparison.Ordinal));
                var innerPosition = target.TransformToVisual(innerScroll).TransformPoint(new Windows.Foundation.Point());
                innerScroll.ChangeView(null, innerScroll.VerticalOffset + innerPosition.Y, null, true);
                await ReadinessRenderBarrier();
                captures.Add(await CaptureAnalyzerReview(root, Path.Combine(directory, showLedger ? "1600x1000-Dark-Ledger.png" : "1600x1000-Dark-Collision.png")));
            }
            if (scanned)
            {
                Navigation.SelectedItem = Navigation.MenuItems[0];
                ProgressPanel.IsExpanded = true;
                AnalyzerReviewChildren<Expander>(ScanProgress).Single().IsExpanded = true;
                await Task.Delay(450);
                await ReadinessRenderBarrier();
                captures.Add(await CaptureAnalyzerReview(root, Path.Combine(directory, "1600x1000-Dark-Activity.png")));
                if (!scanProgress.Activity.Any(item => item.Stage.StartsWith("analyzer", StringComparison.OrdinalIgnoreCase)))
                    throw new InvalidDataException("No analyzer activity reached the native progress model.");
            }
            bool discoveryFixturePreview = arguments.Contains("--discovery-fixture");
            if (discoveryFixturePreview)
            {
                var fixtureModel = new AnalyzerSelectionModel();
                fixtureModel.LoadDiscovery(File.ReadAllText(Path.GetFullPath(Argument("--discovery-fixture"))));
                if (fixtureModel.DiscoveryIssues.Count != 6 || fixtureModel.CatalogError != null)
                    throw new InvalidDataException("Controlled discovery preview fixture is invalid.");
                var fixtureView = new AnalyzerSelectionView(fixtureModel);
                string priorStatus = Status.Text;
                try
                {
                    ProgressPanel.IsExpanded = false;
                    Navigation.SelectedItem = Navigation.MenuItems[6];
                    Status.Text = "FIXTURE PREVIEW ONLY: six simulated discovery failures/policy skips; not this engine's inventory.";
                    AnalyzerHost.Content = fixtureView;
                    fixtureView.Refresh();
                    await ReadinessRenderBarrier();
                    AnalyzerReviewChildren<Expander>(fixtureView).Single(item => item.Name == "AnalyzerDiscoveryIssues").IsExpanded = true;
                    await Task.Delay(450);
                    var position = AnalyzerPicker.TransformToVisual(ScanOptionsPanel).TransformPoint(new Windows.Foundation.Point());
                    ScanOptionsPanel.ChangeView(null, ScanOptionsPanel.VerticalOffset + position.Y, null, true);
                    captures.Add(await CaptureAnalyzerReview(root, Path.Combine(directory, "1600x1000-Dark-DiscoveryFixture.png")));
                }
                finally { AnalyzerHost.Content = analyzerView; Status.Text = priorStatus; }
            }
            result = new { passed = true, profile, expansion = saved.Modules, staleBlocked, settingsRoundTrip = true,
                scanCompleted = scanned, report = displayedReportPath, reportHash = displayedReadHash,
                selectedEngine = PythonPath.Text, engineIdentity = capabilityCache.Current?.ExpectedIdentity,
                captures, analyzerCaptureRetries, discoveryFixturePreview, activity = scanProgress.Activity, omittedActivity = scanProgress.EarlierActivityCount,
                personalSettingsRead = false, liveProviderCalls = 0, acceptedManualUi = false };
        }
        catch (Exception error) { failure = error.ToString(); }
        finally
        {
            try { File.WriteAllText(Path.Combine(directory, "analyzer-smoke.json"), JsonSerializer.Serialize(new { result, failure }, new JsonSerializerOptions { WriteIndented = true })); }
            finally { Close(); }
        }
    }

    private async Task<CaptureMetadata> CaptureAnalyzerReview(FrameworkElement root, string path)
    {
        Activate();
        await Task.Delay(650);
        return await CaptureStrict(root, path, requireVisibleContent: true);
    }

    private static IEnumerable<T> AnalyzerReviewChildren<T>(DependencyObject parent) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) yield return match;
            foreach (var descendant in AnalyzerReviewChildren<T>(child)) yield return descendant;
        }
    }
}
