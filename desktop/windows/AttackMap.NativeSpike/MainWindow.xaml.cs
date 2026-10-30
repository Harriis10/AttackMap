using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;
public sealed record FixtureFinding(string Id, string Title, string Severity, string Basis,
    string Confidence, string Source, string Evidence, string Recommendation)
{
    public string Summary => $"{Basis}  -  confidence {Confidence}  -  {Source}";
    public string SeverityLabel => Severity.Trim().ToUpperInvariant();
    public Microsoft.UI.Xaml.Media.Brush SeverityBrush => MarkdownView.SeverityBrush(Severity);
}
public sealed partial class MainWindow : Window
{
    private List<FixtureFinding> all = [];
    private List<JsonElement> findingRecords = [];
    private string? displayedReportPath;
    private string displayedRepository = "";
    private string displayedRun = "";
    private string displayedReadHash = "";
    private NativeScanOptions? activeScanOptions;
    private long findingRevision;
    private bool actionRunning;
    private IDisposable? keyboardBindings;
    private readonly CancellationTokenSource actionLifetime = new();
    private bool ready;
    private StructureData? structure;
    private bool inventoryView;
    private ExportSelection? exportSelection;
    private long generation;
    private string? repositoryPath;
    private readonly EngineSession engine = new();
    private bool scanning;
    private readonly RunPresentation presentation = new();
    private readonly LocalSettingsStore settings = new(LocalSettingsStore.DefaultPath);
    private readonly WindowPlacementStore placementStore = new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", "window.json"));
    private WindowPlacement? lastPlacement;
    private bool placementPersistenceEnabled;
    private string? lastScanOutput;
    private bool artifactBusy;
    private string reportLabel = "synthetic findings. No production analysis loaded";
    public MainWindow()
    {
        var startup = Environment.GetCommandLineArgs();
        var diagnosticsStartup = startup;
        int activationIndex = Array.IndexOf(startup, "--activation-smoke");
        if (activationIndex >= 0)
        {
            if (startup.Length != 4 || activationIndex != 1 || startup.Skip(2).Any(path => !Path.IsPathFullyQualified(path)))
                throw new ArgumentException("Activation QA requires absolute report and caller-created output directory paths.");
            string qa = Path.GetFullPath(startup[3]);
            if (!Directory.Exists(qa)) throw new DirectoryNotFoundException("Create a fresh caller-owned activation QA directory first.");
            settings = new LocalSettingsStore(Path.Combine(qa, "settings.json"));
            placementStore = new WindowPlacementStore(Path.Combine(qa, "window.json"));
            recentStore = new HistoryPrep.RecentRepositoriesStore(Path.Combine(qa, "recent.json"));
            string diagnostics = Path.Combine(qa, "diagnostics");
            Directory.CreateDirectory(diagnostics);
            diagnosticsStartup = [.. startup, "--render-diagnostics", diagnostics];
        }
        if (startup.Contains("--provider-render-smoke") || startup.Contains("--navigation-render-smoke"))
        {
            if (startup.Length != 5 || (startup[1] != "--provider-render-smoke" && startup[1] != "--navigation-render-smoke") || startup.Skip(2).Any(path => !Path.IsPathFullyQualified(path)))
                throw new ArgumentException("Provider render QA requires absolute report, fresh output directory and engine paths.");
            string qa = startup[3];
            settings = new LocalSettingsStore(Path.Combine(qa, "settings.json"));
            placementStore = new WindowPlacementStore(Path.Combine(qa, "window.json"));
            recentStore = new HistoryPrep.RecentRepositoriesStore(Path.Combine(qa, "recent.json"));
        }
        providerFaultQa = ReadProviderFaultSmokeArguments(startup);
        if (providerFaultQa is { } providerQa)
        {
            settings = new LocalSettingsStore(providerQa.SettingsPath);
            placementStore = new WindowPlacementStore(providerQa.WindowPath);
            recentStore = new HistoryPrep.RecentRepositoriesStore(providerQa.RecentPath);
        }
        int settingsIndex = Array.IndexOf(startup, "--settings-smoke");
        if (settingsIndex < 0) settingsIndex = Array.IndexOf(startup, "--startup-smoke");
        if (settingsIndex >= 0 && settingsIndex + 1 < startup.Length) settings = new LocalSettingsStore(Path.GetFullPath(startup[settingsIndex + 1]));
        int placementIndex = Array.IndexOf(startup, "--placement-smoke");
        if (placementIndex >= 0 && placementIndex + 1 < startup.Length) placementStore = new WindowPlacementStore(Path.GetFullPath(startup[placementIndex + 1]));
        int parityIndex = Array.IndexOf(startup, "--parity-smoke");
        if (parityIndex >= 0 && parityIndex + 2 < startup.Length) settings = new LocalSettingsStore(Path.Combine(Path.GetFullPath(startup[parityIndex + 2]), "settings.json"));
        int analyzerIndex = Array.IndexOf(startup, "--analyzer-smoke");
        if (analyzerIndex >= 0 && analyzerIndex + 1 < startup.Length) settings = new LocalSettingsStore(Path.Combine(Path.GetFullPath(startup[analyzerIndex + 1]), "settings.json"));
        int fleetGraphIndex = Array.IndexOf(startup, "--fleet-graph-smoke");
        if (fleetGraphIndex >= 0 && fleetGraphIndex + 1 < startup.Length)
        {
            string qaFolder = Path.GetFullPath(startup[fleetGraphIndex + 1]);
            settings = new LocalSettingsStore(Path.Combine(qaFolder, "settings.json"));
            placementStore = new WindowPlacementStore(Path.Combine(qaFolder, "window.json"));
            recentStore = new HistoryPrep.RecentRepositoriesStore(Path.Combine(qaFolder, "recent.json"));
        }
        InitializeComponent();
        Closed += (_, _) => { ready = false; ++generation; };
        InitializeParityWorkspace();
        InitializeRenderDiagnostics(diagnosticsStartup);
        InitializeWorkspaceServices();
        ready = true;
        Navigation.SelectedItem = Navigation.MenuItems[0];
        keyboardBindings = NativeAccessibility.Bind((FrameworkElement)Content, new Dictionary<string, Action> {
            ["open_report"] = () => OpenReport(this, new RoutedEventArgs()),
            ["choose_repository"] = () => ChooseRepository(this, new RoutedEventArgs()),
            ["scan"] = () => { if (ScanButton.IsEnabled) ScanRepository(this, new RoutedEventArgs()); },
            ["cancel"] = () => { if (CancelButton.IsEnabled) CancelScan(this, new RoutedEventArgs()); },
            ["export"] = () => ExportJson(this, new RoutedEventArgs()),
            ["settings"] = () => Navigation.SelectedItem = Navigation.SettingsItem,
            ["history"] = () => Navigation.SelectedItem = Navigation.MenuItems[5]
        });
        ((FrameworkElement)Content).Loaded += (_, _) => NativeAccessibility.ApplyNames((FrameworkElement)Content);
        if (!startup.Any(arg => arg == "--smoke" || arg.EndsWith("-smoke", StringComparison.Ordinal) || arg.StartsWith("--capture-", StringComparison.Ordinal))) LoadSavedTheme();
        History.OwnerWindowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);
        History.CompareRequested += async request => await CompareReports(request);
        History.GenerationsRequested += async () => await LoadRetainedGenerations();
        History.PinRequested += async request => await ToggleGenerationPin(request);
        History.DiagnosticsExportRequested += async () => await ExportDiagnosticsBundle();
        Suppression.ActionRequested += async request => await ChangeSuppression(request);
        Provider.SaveRequested += async request => await ProviderAction("provider_save", request);
        Provider.TestConnectionRequested += async request => await ProviderAction("provider_check", request);
        Provider.ConfigurationChanged += () => NetworkOptionChanged(this, new RoutedEventArgs());
        Closed += (_, _) => { actionLifetime.Cancel(); keyboardBindings?.Dispose(); engine.Disconnect(); };
        if (Environment.GetCommandLineArgs().Contains("--smoke") || Environment.GetCommandLineArgs().Contains("--report-smoke") || Environment.GetCommandLineArgs().Contains("--scan-smoke") || Environment.GetCommandLineArgs().Contains("--settings-smoke") || Environment.GetCommandLineArgs().Contains("--structure-smoke") || Environment.GetCommandLineArgs().Contains("--export-smoke") || Environment.GetCommandLineArgs().Contains("--engine-guard-smoke") || startup.Contains("--performance-smoke") || startup.Contains("--actions-smoke") || startup.Contains("--accessibility-smoke") || startup.Contains("--placement-smoke") || startup.Contains("--startup-smoke"))
            ((FrameworkElement)Content).Loaded += SmokeLoaded;
        else if (startup.Contains("--provider-render-smoke"))
            ((FrameworkElement)Content).Loaded += ProviderRenderSmokeLoaded;
        else if (startup.Contains("--navigation-render-smoke"))
            ((FrameworkElement)Content).Loaded += NavigationRenderSmokeLoaded;
        else if (startup.Contains("--fleet-graph-smoke"))
            ((FrameworkElement)Content).Loaded += FleetGraphSmokeLoaded;
        else if (startup.Contains("--analyzer-smoke"))
            ((FrameworkElement)Content).Loaded += AnalyzerSmokeLoaded;
        else if (startup.Contains("--parity-smoke"))
            ((FrameworkElement)Content).Loaded += ParitySmokeLoaded;
        else if (startup.Contains("--activation-smoke"))
            ((FrameworkElement)Content).Loaded += ActivationSmokeLoaded;
        else if (startup.Contains("--capture-smoke"))
            ((FrameworkElement)Content).Loaded += CaptureLoaded;
        else if (startup.Contains("--capture-startup-smoke"))
            ((FrameworkElement)Content).Loaded += CaptureStartupLoaded;
        else if (startup.Contains("--capture-retention"))
            ((FrameworkElement)Content).Loaded += CaptureRetentionLoaded;
        else if (startup.Contains("--capture-reports-artifacts"))
            ((FrameworkElement)Content).Loaded += CaptureReportsArtifactsLoaded;
        else if (providerFaultQa != null)
            ((FrameworkElement)Content).Loaded += ProviderFaultSmokeLoaded;
        else if (startup.Contains("--fault-smoke"))
            ((FrameworkElement)Content).Loaded += SmokeLoaded;
        else if (startup.Contains("--expanded-accessibility-smoke"))
            ((FrameworkElement)Content).Loaded += SmokeLoaded;
        else if (startup.Contains("--provider-scroll-smoke"))
            ((FrameworkElement)Content).Loaded += SmokeLoaded;
        else if (startup.Contains("--readiness-smoke") || startup.Contains("--menu-smoke") || startup.Contains("--history-baseline-smoke") || startup.Contains("--retention-smoke"))
            ((FrameworkElement)Content).Loaded += SmokeLoaded;
        else
        {
            RestoreLocalSettings(); RestoreProviderSettings();
            RestoreRecentRepositories();
            int showReport = Array.IndexOf(startup, "--show-report");
            if(showReport>=0&&showReport+1<startup.Length)
                ((FrameworkElement)Content).Loaded += async (_, _) => {
                    try
                    {
                        if (!actionLifetime.IsCancellationRequested && Path.IsPathFullyQualified(startup[showReport + 1]) &&
                            await LoadReport(Path.GetFullPath(startup[showReport + 1])) &&
                            startup.Contains("--render-diagnostics") && startup.Contains("--render-open-diagrams"))
                            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Diagrams");
                    }
                    catch(Exception) { if(!actionLifetime.IsCancellationRequested)Status.Text="Requested report could not be opened. Choose a readable canonical JSON report."; }
                };
            ((FrameworkElement)Content).Loaded += RestoreWindowPlacement;
            AppWindow.Changed += (_, _) => CaptureWindowPlacement();
            Closed += (_, _) => { if (placementPersistenceEnabled && lastPlacement != null) try { placementStore.Save(lastPlacement); } catch (Exception) { /* Preserve existing geometry if storage is unavailable. */ } };
            if (startup.Contains("--verify-portable-startup"))
                ((FrameworkElement)Content).Loaded += VerifyPortableStartup;
        }
    }
    private void RestoreWindowPlacement(object sender, RoutedEventArgs args)
    {
        ((FrameworkElement)Content).Loaded -= RestoreWindowPlacement;
        try
        {
            var saved = placementStore.Load();
            double scale = ((FrameworkElement)Content).XamlRoot.RasterizationScale;
            var area = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest).WorkArea;
            int width = Math.Min(area.Width, (int)Math.Round(saved.Width * scale));
            int height = Math.Min(area.Height, (int)Math.Round(saved.Height * scale));
            int left = Math.Clamp(saved.Left ?? area.X + (area.Width - width) / 2, area.X, area.X + area.Width - width);
            int top = Math.Clamp(saved.Top ?? area.Y + (area.Height - height) / 2, area.Y, area.Y + area.Height - height);
            AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(left, top, width, height));
            placementPersistenceEnabled = true;
            CaptureWindowPlacement();
        }
        catch (Exception) { Status.Text = "Window geometry could not be restored; original settings preserved."; }
    }
    private void CaptureWindowPlacement()
    {
        if (!ready || actionLifetime.IsCancellationRequested || !placementPersistenceEnabled || ((FrameworkElement)Content).XamlRoot == null || AppWindow.Presenter is not Microsoft.UI.Windowing.OverlappedPresenter presenter || presenter.State != Microsoft.UI.Windowing.OverlappedPresenterState.Restored) return;
        double scale = ((FrameworkElement)Content).XamlRoot.RasterizationScale;
        int width = (int)Math.Round(AppWindow.Size.Width / scale), height = (int)Math.Round(AppWindow.Size.Height / scale);
        if (width < 1024 || height < 700 || width > 16384 || height > 16384) return;
        lastPlacement = new WindowPlacement(Width: width, Height: height, Left: AppWindow.Position.X, Top: AppWindow.Position.Y);
    }
    private void RestoreLocalSettings()
    {
        try
        {
            var saved = settings.Load();
            PythonPath.Text = EngineCapabilities.RestoreEngineSelection(saved.PythonPath, AppContext.BaseDirectory);
            ApplyScanOptions(saved.EffectiveOptions, saved.Modules);
            repositoryPath = saved.RepositoryPath.Length == 0 ? null : saved.RepositoryPath;
            presentation.SelectRepository(repositoryPath);
            UpdateRunSummary();
            Status.Text = repositoryPath == null ? "Choose a repository to scan, or open a saved report. Review optional network settings before scanning." : $"Restored repository: {repositoryPath}. Scan when ready; no scan started.";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        { Status.Text = $"Local settings unavailable: {error.Message} Original preserved. Configure paths and save, or clear saved settings."; }
    }
    private void SaveLocalSettings(object sender, RoutedEventArgs args)
    {
        try { settings.Save(new LocalSettings(PythonPath: PythonPath.Text.Trim(), RepositoryPath: repositoryPath ?? "", Options: ReadScanOptions(), Modules: analyzerSelection.SelectedProfile == null ? ModulesOption.Text.Trim() : analyzerSelection.ExpandedProfileModules)); NetworkOptionChanged(this, new RoutedEventArgs()); Status.Text = "Local paths and scan options saved; no scan or provider request started. " + NetworkDisclosure.Text; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException)
        { Status.Text = $"Settings could not be saved: {error.Message}"; }
    }
    private void NetworkOptionChanged(object sender, RoutedEventArgs args)
    {
        if (!ready || actionLifetime.IsCancellationRequested) return;
        string ai;
        try { var options = activeScanOptions?.Provider ?? (activeScanOptions == null ? Provider.ReadConfiguration() : new ProviderConfiguration()); ai = options.EnableAi ? $"AI ON: sends structured evidence and minimized source excerpts to {options.Provider} / {options.Endpoint ?? "provider default endpoint"}" : "AI off"; }
        catch (Exception) { ai = "AI options invalid; scan will require correction"; }
        NetworkDisclosure.Text = ai + ((activeScanOptions?.Cve ?? CveOption.IsChecked == true) ? "; CVE ON: sends dependency names/versions to OSV" : "; CVE lookup off");
    }
    private NativeScanOptions ReadScanOptions(bool forRequest = false)
    {
        if (!int.TryParse(SecretsHistoryOption.Text, out int history) || !int.TryParse(TimeoutOption.Text, out int timeout)) throw new InvalidDataException("Secret history and timeout must be whole numbers.");
        int? budget = string.IsNullOrWhiteSpace(TimeBudgetOption.Text) ? null : int.TryParse(TimeBudgetOption.Text, out int parsedBudget) ? parsedBudget : throw new InvalidDataException("Time budget must be a whole number of seconds.");
        var options = restoredScanOptions with { Recall = RecallOption.IsChecked == true, StrictAnalyzers = StrictAnalyzersOption.IsChecked == true,
            NoSuppress = NoSuppressOption.IsChecked == true, Cve = CveOption.IsChecked == true, SecretsHistory = history, TimeoutSeconds = timeout,
            Baseline = BlankOption(BaselineOption.Text), SuppressFile = BlankOption(SuppressFileOption.Text), FailOnNewHigh = FailNewHighOption.IsChecked == true,
            FailOnNewSuppression = FailNewSuppressionOption.IsChecked == true, StrictSuppressions = StrictSuppressionsOption.IsChecked == true,
            IsolatedAnalyzers = IsolatedAnalyzersOption.IsChecked == true, TimeBudgetSeconds = budget,
            AnalyzerProfile = analyzerSelection.RequestProfile };
        options.Validate();
        NativeScanOptions.ParseModules(ModulesOption.Text);
        var provider = forRequest ? Provider.ReadRequestConfiguration() : Provider.ReadConfiguration();
        return options with { Provider = provider };
    }
    private void ApplyScanOptions(NativeScanOptions options, string modules)
    {
        restoredScanOptions = options;
        RecallOption.IsChecked = options.Recall;
        StrictAnalyzersOption.IsChecked = options.StrictAnalyzers;
        NoSuppressOption.IsChecked = options.NoSuppress;
        CveOption.IsChecked = options.Cve;
        SecretsHistoryOption.Text = options.SecretsHistory.ToString();
        TimeoutOption.Text = options.TimeoutSeconds.ToString();
        ModulesOption.Text = modules;
        BaselineOption.Text = options.Baseline ?? "";
        SuppressFileOption.Text = options.SuppressFile ?? "";
        FailNewHighOption.IsChecked = options.FailOnNewHigh;
        FailNewSuppressionOption.IsChecked = options.FailOnNewSuppression;
        StrictSuppressionsOption.IsChecked = options.StrictSuppressions;
        IsolatedAnalyzersOption.IsChecked = options.IsolatedAnalyzers;
        TimeBudgetOption.Text = options.TimeBudgetSeconds?.ToString() ?? "";
        if (options.AnalyzerProfile != null) analyzerSelection.RestoreProfile(options.AnalyzerProfile, modules);
        else analyzerSelection.Restore(modules);
        synchronizingAnalyzers = true;
        ModulesOption.Text = analyzerSelection.RequestModules;
        synchronizingAnalyzers = false;
        analyzerView?.Refresh();
        if (options.Provider != null) Provider.ApplyConfiguration(options.Provider);
    }
    private void ClearLocalSettings(object sender, RoutedEventArgs args)
    {
        try { settings.Clear(); restoredScanOptions = restoredScanOptions with { AdditionalProperties = null, UnrecognizedProviderFields = null }; Status.Text = "Saved settings cleared. Current workspace stays open until you choose another; no scan started."; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { Status.Text = $"Saved settings could not be cleared: {error.Message}"; }
    }
    private async void ChooseRepository(object sender, RoutedEventArgs args)
    {
        try
        {
        var picker = new Windows.Storage.Pickers.FolderPicker();
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        picker.FileTypeFilter.Add("*");
        var folder = await picker.PickSingleFolderAsync();
        if (folder != null) SelectRepositoryPath(folder.Path);
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Repository picker unavailable. Try choosing a repository again; the existing workspace is preserved."; }
    }
    private void MenuScan(object sender, RoutedEventArgs args) { if (ScanButton.IsEnabled) ScanRepository(sender, args); }
    private void MenuCancel(object sender, RoutedEventArgs args) { if (CancelButton.IsEnabled) CancelScan(sender, args); }
    private void MenuSettings(object sender, RoutedEventArgs args) => Navigation.SelectedItem = Navigation.SettingsItem;
    private void MenuHistory(object sender, RoutedEventArgs args) => Navigation.SelectedItem = Navigation.MenuItems[5];
    private void CancelScan(object sender, RoutedEventArgs args)
    {
        StopRepositoryWatch(); StopFleetWatch();
        ++generation; scanAdmission?.Cancel();
        if (fleetRunning) fleetSession.Cancel(); else engine.Cancel();
        scanProgress.RequestCancel(); ScanProgress.SetModel(scanProgress);
        presentation.Update("Cancelling; waiting for owned worker cleanup. Artifacts pending.");
        UpdateRunSummary();
        CancelButton.IsEnabled = false;
        Status.Text = "Cancelling owned engine work; waiting for terminal confirmation - ";
    }
    private async void ScanRepository(object sender, RoutedEventArgs args) => await RunSelectedRepository();
    private async Task RunSelectedRepository(string? verificationOutput = null)
    {
        if (scanning || actionRunning || DesktopActionRunner.CleanupBlocked || engine.CleanupBlocked || fleetSession.CleanupBlocked || repositoryPath == null) { Status.Text = "Choose a repository and wait for verified cleanup of any current action first."; return; }
        StopFleetWatch();
        long current = ++generation;
        string repository = repositoryPath;
        string modules = ModulesOption.Text.Trim();
        using var admission = CancellationTokenSource.CreateLinkedTokenSource(actionLifetime.Token);
        scanAdmission = admission;
        long watchEpoch = repositoryWatch.Epoch;
        bool published = false;
        repositoryWatch.SetScanRunning(true);
        scanning = true;
        ScanButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        ScanOptionsPanel.IsEnabled = Provider.IsEnabled = false;
        // Stable per-repository base: generations accumulate here so engine
        // retention (keep window, budget, pins) applies per repository.
        string output = verificationOutput ?? ScanLocations.ReportsBase(repository);
        lastScanOutput = output;
        DiagnosticPath.Text = $"Selected local run folder: {output}. A terminal diagnostic is available only if the broker writes one.";
        string engineStatus = "";
        RunIdentity? identity = null;
        try
        {
            var preferences = ReadScanOptions();
            string executable = EngineCapabilities.ResolveEngine(PythonPath.Text, AppContext.BaseDirectory);
            await DiscoverEngineCapabilities(admission.Token);
            CheckScanAdmission(current, repository, executable, admission.Token);
            activeScanOptions = preferences with { Provider = preferences.Provider?.ForRequest() };
            capabilityCache.Current!.RequireSupport(activeScanOptions, modules);
            analyzerSelection.ValidateForScan();
            using var preflightRequest = JsonDocument.Parse(NativeScanRequest.Serialize("native_preflight", repository, output, current, activeScanOptions, modules));
            var preflight = await DesktopActionRunner.Run(executable, "preflight", new { request = preflightRequest.RootElement, expected_identity = capabilityCache.Current.ExpectedIdentity }, outputBase: providerFaultQa?.ActionDirectory ?? providerRenderActionDirectory, cancellationToken: admission.Token);
            CheckScanAdmission(current, repository, executable, admission.Token);
            if (!preflight.GetProperty("supported").GetBoolean()) throw new InvalidDataException("Selected engine or request changed since discovery; check compatibility again. No scan was started.");
            var elapsed = System.Diagnostics.Stopwatch.StartNew();
            NetworkOptionChanged(this, new RoutedEventArgs());
            await engine.Run(executable, repository, output, current,
                text => { engineStatus = text; if (actionLifetime.IsCancellationRequested) return; presentation.Update(text); UpdateRunSummary(); if (generation == current) Status.Text = text; },
                async path => {
                    if (actionLifetime.IsCancellationRequested || generation != current) return;
                    if (!await LoadReport(path, identity)) throw new InvalidDataException("Completed engine artifacts could not be imported or verified.");
                    published = true;
                    if (!actionLifetime.IsCancellationRequested) Status.Text += $". {engineStatus}";
                },
                run => { identity = run; if (actionLifetime.IsCancellationRequested) return; scanProgress.Select(run.RunId, run.Repository, run.Generation); ScanProgress.SetModel(scanProgress); ProgressPanel.Visibility = Visibility.Visible; presentation.Begin(run); UpdateRunSummary(); },
                options: activeScanOptions, modules: modules, structuredProgress: snapshot => {
                    if (!actionLifetime.IsCancellationRequested && scanProgress.Accept(snapshot, elapsed.Elapsed)) ScanProgress.SetModel(scanProgress);
                });
        }
        catch (Exception error) { engineStatus = $"Scan result unavailable: {error.Message}. Previous report retained."; if (!actionLifetime.IsCancellationRequested && generation == current) Status.Text = engineStatus; }
        finally { scanAdmission = null; scanning = false; activeScanOptions = null; repositoryWatch.ScanCompleted(watchEpoch, published); fleetWatch.SetFleetRunning(false); if (!actionLifetime.IsCancellationRequested) { RefreshRepositoryWatchNotice(); presentation.End(engineStatus.Length == 0 ? "Run failed before terminal confirmation; previous report retained" : engineStatus); UpdateRunSummary(); NetworkOptionChanged(this, new RoutedEventArgs()); ScanButton.IsEnabled = !DesktopActionRunner.CleanupBlocked && !engine.CleanupBlocked && !fleetSession.CleanupBlocked; ScanOptionsPanel.IsEnabled = Provider.IsEnabled = ScanButton.IsEnabled; CancelButton.IsEnabled = false; if (admission.IsCancellationRequested && ScanButton.IsEnabled) Status.Text = "Scan cancelled; previous report retained."; } }
    }
    private async void ExportJson(object sender, RoutedEventArgs args) => await ExportDisplayed(false);
    private async void RevealScanFolder(object sender, RoutedEventArgs args)
    {
        if (lastScanOutput == null || !Directory.Exists(lastScanOutput)) { Status.Text = "No scan folder exists yet. Start a scan first."; return; }
        try { var folder = await Windows.Storage.StorageFolder.GetFolderFromPathAsync(lastScanOutput); if (!await Windows.System.Launcher.LaunchFolderAsync(folder)) throw new IOException("Folder launch declined."); }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Scan folder could not be revealed. Its selected path remains in run details."; }
    }
    private async void ExportMarkdown(object sender, RoutedEventArgs args) => await ExportDisplayed(true);
    private async Task ExportDisplayed(bool markdown)
    {
        var selected = exportSelection;
        if (selected == null) { Status.Text = "Open a canonical report or complete a scan before exporting. Synthetic fixture export is unavailable."; return; }
        if (markdown && selected.MarkdownPath == null) { Status.Text = selected.Disclosure + " Markdown requires a verified displayed broker generation."; return; }
        Status.Text = selected.Disclosure;
        try
        {
        var picker = new Windows.Storage.Pickers.FileSavePicker();
        WinRT.Interop.InitializeWithWindow.Initialize(picker,WinRT.Interop.WindowNative.GetWindowHandle(this));
        picker.SuggestedFileName = Path.GetFileNameWithoutExtension(selected.SuggestedName(markdown));
        picker.FileTypeChoices.Add(markdown ? "Selected run review Markdown" : "Displayed report JSON",new List<string> { markdown ? ".md" : ".json" });
            var destination = await picker.PickSaveFileAsync();
            if (destination == null || actionLifetime.IsCancellationRequested) return;
            await selected.Export(destination.Path,markdown); Status.Text = $"Exported selected report. {selected.Disclosure}";
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Export or save picker unavailable. Try again; the selected report is preserved."; }
    }
    private async void ExportHtml(object sender, RoutedEventArgs args) => await ExportRendered(".html");
    private async void ExportPdf(object sender, RoutedEventArgs args) => await ExportRendered(".pdf");
    private async Task ExportRendered(string extension)
    {
        var selected = exportSelection;
        if (selected == null) { Status.Text = "Open a canonical report or complete a scan before exporting. Synthetic fixture export is unavailable."; return; }
        bool pdf = extension == ".pdf";
        string capturedReview = ReviewText.Text;
        Status.Text = selected.Disclosure;
        try
        {
        var picker = new Windows.Storage.Pickers.FileSavePicker();
        WinRT.Interop.InitializeWithWindow.Initialize(picker,WinRT.Interop.WindowNative.GetWindowHandle(this));
        picker.SuggestedFileName = Path.GetFileNameWithoutExtension(selected.SuggestedName(extension));
        picker.FileTypeChoices.Add(pdf ? "Printed defensive review PDF" : "Rendered defensive review HTML",new List<string> { extension });
            var destination = await picker.PickSaveFileAsync();
            if (destination == null || actionLifetime.IsCancellationRequested) return;
            // Verified runs render the manifest-bound Markdown; legacy imports
            // render exactly the review text already displayed.
            string markdown = selected.MarkdownPath != null ? await Task.Run(() => selected.ReadVerifiedMarkdown()) : capturedReview;
            selected.EnsureExportDestination(destination.Path,selected.ReportPath);
            string html = ReviewExport.BuildHtml(markdown,Path.GetFileNameWithoutExtension(selected.SuggestedName(extension)));
            if (pdf)
            {
                if (ReviewExport.FindPrintBrowsers().Count == 0) { Status.Text = "PDF export requires Microsoft Edge or Google Chrome; neither was found. HTML export is unaffected."; return; }
                await ReviewExport.WritePdfWithAvailableBrowserAsync(html,destination.Path);
            }
            else await ReviewExport.WriteHtmlAsync(destination.Path,html);
            Status.Text = $"Exported selected report {extension}. {selected.Disclosure}";
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = pdf ? "PDF export unavailable. Check that Edge or Chrome is installed and try again; the selected report is preserved." : "HTML export unavailable. Try again; the selected report is preserved."; }
    }
    private async void OpenReport(object sender, RoutedEventArgs args)
    {
        try
        {
        var picker = new Windows.Storage.Pickers.FileOpenPicker();
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        picker.FileTypeFilter.Add(".json");
        var file = await picker.PickSingleFileAsync();
        if (file != null && !actionLifetime.IsCancellationRequested) await LoadReport(file.Path);
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Report picker unavailable. Try again; the previous report is preserved."; }
    }
    private async Task<bool> LoadReport(string path, RunIdentity? identity = null)
    {
        if (!ready || actionLifetime.IsCancellationRequested) return false;
        long current = ++generation;
        var reportClock = System.Diagnostics.Stopwatch.StartNew();
        RenderDiagnosticsReportStarted(current);
        try
        {
            var snapshot = await VerifiedReportSnapshot.Load(path, identity, actionLifetime.Token);
            if (actionLifetime.IsCancellationRequested || current != generation) return false;
            RenderDiagnosticsWrite("report-snapshot-read", new { generation = current, displayedRun, displayedReadHash,
                snapshotRun = snapshot.Selection.RunId, snapshotReadHash = snapshot.ReadHash, elapsedMilliseconds = reportClock.Elapsed.TotalMilliseconds,
                initialReportReadCount = 1, initialReportHashCount = 1, initialManifestSelectionCount = 1,
                projectionCounts = new { report = 1, sections = 1, overview = 1 }, snapshot.ProjectionThreadId });
            var report = snapshot.Report;
            var selectedExport = snapshot.Selection;
            var sections = snapshot.Sections;
            var overview = snapshot.Overview;
            var timing = await ScanTiming.ReadLabelMeasured(selectedExport);
            string engineTiming = timing.Label;
            RenderDiagnosticsWrite("report-integrity-revalidation", new { generation = current, displayedRun, displayedReadHash,
                snapshotRun = snapshot.Selection.RunId, snapshotReadHash = snapshot.ReadHash, operation = "ScanTiming.ReadLabel",
                initialReportReadCount = 1, laterReportIntegrityReadCount = timing.ReportIntegrityReadCount, elapsedMilliseconds = reportClock.Elapsed.TotalMilliseconds });
            if (actionLifetime.IsCancellationRequested || current != generation) return false;
            RenderDiagnosticsWrite("report-bind-started", new { generation = current, displayedRun, displayedReadHash,
                snapshotRun = snapshot.Selection.RunId, snapshotReadHash = snapshot.ReadHash, elapsedMilliseconds = reportClock.Elapsed.TotalMilliseconds,
                initialReportReadCount = 1, laterReportIntegrityReadCount = timing.ReportIntegrityReadCount });
            all = report.Findings;
            ++findingRevision;
            Suppression.SetContext("", default, "");
            findingRecords = report.FindingRecords;
            displayedReportPath = Path.GetFullPath(path);
            displayedRepository = report.Repository;
            displayedRun = selectedExport.RunId ?? "legacy-import";
            displayedReadHash = report.ReadHash;
            History.CurrentReportPath = displayedReportPath;
            exportSelection = selectedExport;
            ResetAiReview();
            ArtifactRows.ItemsSource = null;
            ArtifactText.Text = "Choose an artifact to inspect its verified text.";
            ArtifactStatus.Text = selectedExport.Disclosure;
            structure = report.Structure;
            ReviewText.Text = report.Review;
            OverviewText.Text = report.Overview;
            BindParityReport(sections, overview, selectedExport);
            presentation.Publish(new DisplayedReport(report.Repository, selectedExport.RunId ?? "Legacy import; run identity unavailable",
                identity == null ? $"Scan timestamp unavailable; opened (client UTC): {DateTimeOffset.UtcNow.UtcDateTime:O}; {engineTiming}" : $"Requested at (client UTC): {identity.RequestedAt.UtcDateTime:O}; {engineTiming}",
                report.Coverage));
            UpdateRunSummary();
            reportLabel = $"engine findings  -  {report.Repository}  -  " + (identity != null ? $"validated broker generation {identity.RunId}; static analysis" : selectedExport.Verified ? $"saved generation {selectedExport.RunId}; manifest integrity checked; origin unverified" : "legacy import, policy/integrity unverified");
            Search.Text = "";
            Navigation.SelectedItem = Navigation.MenuItems[1];
            ShowMatches();
            if (all.Count > 0) Findings.SelectedIndex = 0;
            var binding = parityViewBinding;
            await binding;
            bool bound = !actionLifetime.IsCancellationRequested && current == generation;
            if (bound)
            {
                RenderDiagnosticsWrite("report-bind-completed", new { generation = current, displayedRun, displayedReadHash,
                    elapsedMilliseconds = reportClock.Elapsed.TotalMilliseconds, initialReportReadCount = 1,
                    laterReportIntegrityReadCount = timing.ReportIntegrityReadCount, findingCount = all.Count,
                    reviewCharacters = ReviewText.Text.Length, overviewCount = overview.Counts.Count,
                    hiddenWorkCounters = new { graphLoads = Diagrams.GraphLoadCount, legacySelectionLoads = Diagrams.LegacySelectionLoadCount,
                        interactiveInitializationAttempts = Diagrams.InteractiveInitializationAttemptCount,
                        markdownBuilds = ReviewText.RenderCount + AiReviewText.RenderCount, overviewBuilds = EvidenceOverview.BuildCount },
                    selectedAiMode = AiArtifacts.CurrentMode,
                    selectedAiReads = new { mode = AiArtifacts.CurrentMode,
                        proseReadCount = AiArtifacts.CurrentSnapshot?.ProseReadCount ?? 0,
                        metadataReadCount = AiArtifacts.CurrentSnapshot?.MetadataReadCount ?? 0,
                        runManifestReadCount = AiArtifacts.CurrentSnapshot?.RunManifestReadCount ?? 0,
                        reportIntegrityReadCount = AiArtifacts.CurrentSnapshot?.ReportIntegrityReadCount ?? 0 },
                    privateMemoryBytes = Environment.WorkingSet });
                RenderDiagnosticsReportBindCompleted(current);
            }
            return bound;
        }
        catch (OperationCanceledException) when (actionLifetime.IsCancellationRequested) { return false; }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException or InvalidDataException or InvalidOperationException or KeyNotFoundException)
        {
            if (!actionLifetime.IsCancellationRequested && current == generation) Status.Text = $"Report import failed ({error.Message}). Previous valid report retained.";
            return false;
        }
    }
    private async void LoadFixture(object sender, RoutedEventArgs args) => await LoadData();
    private async Task LoadData()
    {
        if (!ready || actionLifetime.IsCancellationRequested) return;
        long current = ++generation;
        try
        {
            Status.Text = "Loading synthetic fixture - ";
            string path = Path.Combine(AppContext.BaseDirectory, "fixtures", "findings.json");
            var loaded = await Task.Run(async () => JsonSerializer.Deserialize<List<FixtureFinding>>(
                await File.ReadAllTextAsync(path)) ?? throw new InvalidDataException("Fixture is null."));
            if (current != generation) return;
            all = loaded;
            findingRecords = [];
            displayedReportPath = null;
            displayedRepository = "";
            displayedRun = "";
            History.CurrentReportPath = "";
            Suppression.SetContext("", default, "");
            exportSelection = null;
            ResetAiReview();
            ArtifactRows.ItemsSource = null;
            ArtifactText.Text = "Synthetic findings do not supply generation artifacts.";
            structure = null;
            ReviewText.Text = "Synthetic findings do not supply a defensive review.";
            OverviewText.Text = "Synthetic findings are for UI testing; they do not supply a system overview.";
            presentation.Publish(new DisplayedReport("synthetic fixture", "Synthetic fixture; no engine run", "Scan timestamp unavailable (synthetic)", "Synthetic UI rows; no production coverage."));
            UpdateRunSummary();
            reportLabel = "synthetic findings. No production analysis loaded";
            Navigation.SelectedItem = Navigation.MenuItems[1];
            ShowMatches();
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException)
        {
            if (!actionLifetime.IsCancellationRequested && current == generation) Status.Text = $"Fixture unavailable ({error.GetType().Name}). Generate it and retry Load fixture.";
        }
    }
    private async void SmokeLoaded(object sender, RoutedEventArgs args)
    {
        ((FrameworkElement)Content).Loaded -= SmokeLoaded;
        var arguments = Environment.GetCommandLineArgs();
        int historyIndex = Array.IndexOf(arguments, "--history-baseline-smoke");
        if (historyIndex >= 0)
        {
            Navigation.SelectedItem = Navigation.MenuItems[5];
            await ReadinessRenderBarrier();
            string baselineA = Path.Combine(Path.GetTempPath(), "history-baseline-A.json"), baselineB = Path.Combine(Path.GetTempPath(), "history-baseline-B.json"), current = Path.Combine(Path.GetTempPath(), "history-current-C.json");
            JsonElement Comparison(string baseline, string label) => JsonSerializer.SerializeToElement(new { comparison_version = "1.0", baseline = new { report_path = baseline }, current = new { report_path = current }, changes = new { persisted = new[] { new { id = label, title = label, mitigation = "Fixture recommendation" } } }, counts = new { persisted = 1 }, notes = new[] { label + " notes" } });
            History.CurrentReportPath = current;
            History.BaselineReportPath = baselineA;
            var oldResult = Comparison(baselineA, "A versus C");
            History.SetResult(oldResult);
            await ReadinessRenderBarrier();
            bool originalVisible = History.ResultCount == 1 && History.ComparisonDetailText.Contains("A versus C") && History.ComparisonNotesText.Contains("A versus C notes");
            History.BaselineReportPath = baselineA;
            bool unchangedSelectionRetained = History.ResultCount == 1;
            History.SetBusy(true);
            History.BaselineReportPath = baselineB;
            bool changedCleared = History.ResultCount == 0 && History.ComparisonDetailText.Length == 0 && History.ComparisonNotesText.Length == 0;
            bool changedDisclosed = History.SummaryText.Contains("baseline report changed");
            bool busyPreserved = !History.ChooseBaselineEnabled && !History.CompareEnabled;
            History.SetResult(oldResult);
            bool lateOldRejected = History.ResultCount == 0 && History.ComparisonDetailText.Length == 0 && History.ComparisonNotesText.Length == 0 && History.SummaryText.Contains("Selected reports changed");
            History.SetResult(Comparison(baselineB, "B versus C"));
            await ReadinessRenderBarrier();
            bool freshResultVisible = History.ResultCount == 1 && History.ComparisonDetailText.Contains("B versus C") && History.ComparisonNotesText.Contains("B versus C notes");
            History.BaselineReportPath = "";
            bool emptySelectionCleared = History.ResultCount == 0 && History.ComparisonDetailText.Length == 0 && History.ComparisonNotesText.Length == 0 && !History.CompareEnabled;
            File.WriteAllText(arguments[historyIndex + 1], JsonSerializer.Serialize(new { passed = History.IsLoaded && originalVisible && unchangedSelectionRetained && changedCleared && changedDisclosed && busyPreserved && lateOldRejected && freshResultVisible && emptySelectionCleared, actualControlLoaded = History.IsLoaded, originalVisible, unchangedSelectionRetained, changedCleared, changedDisclosed, busyPreserved, lateOldRejected, freshResultVisible, emptySelectionCleared, personalSettingsRead = false, limitations = "Actual loaded production control with fixture comparison envelopes; no core action, file picker, manual keyboard or full history acceptance." }));
            Close(); return;
        }
        int retentionIndex = Array.IndexOf(arguments, "--retention-smoke");
        if (retentionIndex >= 0)
        {
            Navigation.SelectedItem = Navigation.MenuItems[5];
            await ReadinessRenderBarrier();
            var payload = JsonSerializer.SerializeToElement(new
            {
                schema_version = "1.0",
                export_type = "attackmap_diagnostic_export",
                current_generation = new { generation = "run-2", state = "valid" },
                pinned = new[] { "run-1" },
                retention = new { mode = "dry_run_summary", keep_completed = 20, soft_budget_bytes = 2147483648L, budget_overage_bytes = 0L },
                generations = new object[]
                {
                    new { run_id = "run-2", created_at = "2026-10-16T10:00:00+00:00", size_bytes = 33_000_000L, current = true, pinned = false },
                    new { run_id = "run-1", created_at = "2026-10-16T09:00:00+00:00", size_bytes = 32_000_000L, current = false, pinned = true },
                },
            });
            History.SetGenerations(payload);
            await ReadinessRenderBarrier();
            bool listedBoth = History.GenerationCount == 2;
            History.SelectGenerationForSmoke(0);
            await ReadinessRenderBarrier();
            bool currentRowBlocksPin = !History.PinToggleEnabled && History.GenerationCount == 2;
            History.SelectGenerationForSmoke(1);
            await ReadinessRenderBarrier();
            bool pinnedRowOffersUnpin = History.PinToggleEnabled && History.PinToggleText == "Unpin selected";
            bool summaryHonest = History.RetentionSummaryText.Contains("never removes pinned or current");
            History.SetRetentionError("fixture failure");
            bool errorVisible = History.RetentionSummaryText.Contains("fixture failure") && History.GenerationCount == 0;
            File.WriteAllText(arguments[retentionIndex + 1], JsonSerializer.Serialize(new { passed = listedBoth && currentRowBlocksPin && pinnedRowOffersUnpin && summaryHonest && errorVisible, listedBoth, currentRowBlocksPin, pinnedRowOffersUnpin, summaryHonest, errorVisible, personalSettingsRead = false, limitations = "Loaded production History control with a fixture diagnostics payload; no engine action, picker export, manual keyboard or cleanup execution." }));
            Close(); return;
        }
        int menuIndex = Array.IndexOf(arguments, "--menu-smoke");
        if (menuIndex >= 0)
        {
            var menus = CommandMenu.Items.Select(menu => new { title = menu.Title, items = menu.Items.OfType<MenuFlyoutItem>().Select(item => new { text = item.Text, shortcut = item.KeyboardAcceleratorTextOverride }).ToArray() }).ToArray();
            var scanCommands = CommandMenu.Items[1].Items.OfType<MenuFlyoutItem>().ToArray();
            await ReadinessRenderBarrier();
            bool initialEnabledStates = scanCommands[0].IsEnabled && !scanCommands[1].IsEnabled;
            ScanButton.IsEnabled = false; CancelButton.IsEnabled = true;
            await ReadinessRenderBarrier();
            bool toggledEnabledStates = !scanCommands[0].IsEnabled && scanCommands[1].IsEnabled;
            ScanButton.IsEnabled = true; CancelButton.IsEnabled = false;
            await ReadinessRenderBarrier();
            bool restoredEnabledStates = scanCommands[0].IsEnabled && !scanCommands[1].IsEnabled;
            MenuSettings(this, new RoutedEventArgs()); bool settingsSelected = Navigation.SelectedItem == Navigation.SettingsItem;
            MenuHistory(this, new RoutedEventArgs()); bool historySelected = Navigation.SelectedItem == Navigation.MenuItems[5];
            MenuScan(this, new RoutedEventArgs()); bool scanGuard = !scanning && repositoryPath == null && Status.Text.Contains("Choose a repository");
            MenuCancel(this, new RoutedEventArgs()); bool cancelGuard = !scanning && !CancelButton.IsEnabled;
            File.WriteAllText(arguments[menuIndex + 1], JsonSerializer.Serialize(new { passed = menus.Length == 3 && menus.Sum(menu => menu.items.Length) == 8 && settingsSelected && historySelected && scanGuard && cancelGuard && initialEnabledStates && toggledEnabledStates && restoredEnabledStates, menus, settingsSelected, historySelected, scanGuard, cancelGuard, initialEnabledStates, toggledEnabledStates, restoredEnabledStates, personalSettingsRead = false, limitations = "Metadata, loaded command enabled-state bindings and direct existing handler routing only; no popup, picker, Explorer, clipboard or manual keyboard acceptance." }));
            Close(); return;
        }
        if (arguments.Contains("--readiness-smoke"))
        {
            await RunReadinessSmoke(arguments);
            return;
        }
        if (arguments.Contains("--provider-scroll-smoke"))
        {
            await RunProviderScrollSmoke(arguments);
            return;
        }
        if (arguments.Contains("--expanded-accessibility-smoke"))
        {
            await RunExpandedAccessibilitySmoke(arguments);
            return;
        }
        if (arguments.Contains("--fault-smoke"))
        {
            await RunFaultSmoke(arguments);
            return;
        }
        int startupIndex = Array.IndexOf(arguments, "--startup-smoke");
        if (startupIndex >= 0)
        {
            RestoreLocalSettings();
            string bundled = Path.Combine(AppContext.BaseDirectory, "engine", "attackmap.exe");
            bool available = File.Exists(bundled);
            var options = ReadScanOptions();
            File.WriteAllText(arguments[startupIndex + 1] + ".result.json", JsonSerializer.Serialize(new { passed = available && PythonPath.Text == bundled && !scanning && repositoryPath == null && options.Provider?.EnableAi != true && !options.Cve, bundledEngine = PythonPath.Text, automaticScan = scanning, aiEnabled = options.Provider?.EnableAi ?? false, cveEnabled = options.Cve, personalSettingsRead = false, manualStartupAcceptance = false }));
            Close(); return;
        }
        int viewportIndex = Array.IndexOf(arguments, "--viewport");
        if (viewportIndex >= 0 && viewportIndex + 2 < arguments.Length && int.TryParse(arguments[viewportIndex + 1], out int logicalWidth) && int.TryParse(arguments[viewportIndex + 2], out int logicalHeight))
        {
            double scale = ((FrameworkElement)Content).XamlRoot.RasterizationScale;
            AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(logicalWidth * scale), (int)Math.Round(logicalHeight * scale)));
        }
        int placementIndex = Array.IndexOf(arguments, "--placement-smoke");
        if (placementIndex >= 0)
        {
            bool save = arguments.Contains("save");
            if (save) placementStore.Save(new WindowPlacement(Width: 1100, Height: 720, Left: 100000, Top: 100000));
            RestoreWindowPlacement(sender, args);
            var barrier = new TaskCompletionSource();
            DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => barrier.SetResult());
            await barrier.Task;
            CaptureWindowPlacement();
            var area = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest).WorkArea;
            bool inside = AppWindow.Position.X >= area.X && AppWindow.Position.Y >= area.Y && AppWindow.Position.X + AppWindow.Size.Width <= area.X + area.Width && AppWindow.Position.Y + AppWindow.Size.Height <= area.Y + area.Height;
            File.WriteAllText(arguments[placementIndex + 1] + (save ? ".save-result.json" : ".restore-result.json"), JsonSerializer.Serialize(new { passed = placementPersistenceEnabled && inside && lastPlacement?.Width == 1100 && lastPlacement?.Height == 720, stage = save ? "save" : "restore", placement = lastPlacement, insideWorkArea = inside, manualDpiOrMultiMonitorAcceptance = false }));
            if (lastPlacement != null) placementStore.Save(lastPlacement);
            Close(); return;
        }
        int accessibilityIndex = Array.IndexOf(arguments, "--accessibility-smoke");
        if (accessibilityIndex >= 0)
        {
            var audits = new List<AccessibilityAuditResult>();
            foreach (var destination in Navigation.MenuItems.Cast<object>().Append(Navigation.SettingsItem))
            {
                Navigation.SelectedItem = destination;
                var settled = new TaskCompletionSource();
                DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => settled.SetResult());
                await settled.Task;
                ((FrameworkElement)Content).UpdateLayout();
                NativeAccessibility.ApplyNames((FrameworkElement)Content);
                audits.Add(NativeAccessibility.Audit((FrameworkElement)Content));
            }
            File.WriteAllText(arguments[accessibilityIndex + 1], JsonSerializer.Serialize(new { scope = "Loaded native views; peer names/roles, enabled keyboard focusability, scan/cancel sizes only. No Narrator, contrast, manual keyboard or full C24 claim.", shortcuts = NativeAccessibility.Shortcuts, audits }));
            Close(); return;
        }
        int performanceIndex = Array.IndexOf(arguments, "--performance-smoke");
        if (performanceIndex >= 0)
        {
            await NativePerformanceProbe.Run(arguments[performanceIndex + 1], arguments[performanceIndex + 2],
                LoadPerformanceReport, text => Search.Text = text, index => Findings.SelectedIndex = index,
                () => (all.Count, Findings.Items.Count, Detail.Text), ClosePerformanceReport);
            Close(); return;
        }
        int actionIndex = Array.IndexOf(arguments, "--actions-smoke");
        if (actionIndex >= 0)
        {
            PythonPath.Text = arguments[actionIndex + 1];
            string baseline = arguments[actionIndex + 2], currentReport = arguments[actionIndex + 3], output = arguments[actionIndex + 4];
            bool loaded = await LoadReport(currentReport);
            History.BaselineReportPath = Path.GetFullPath(baseline);
            var comparison = await DesktopActionRunner.Run(PythonPath.Text, "compare", new { baseline_path = baseline, current_path = currentReport }, outputBase: output);
            History.SetResult(comparison);
            var preview = await DesktopActionRunner.Run(PythonPath.Text, "suppression_preview", new { repo_root = displayedRepository, finding = findingRecords[0], reason = "Synthetic native workflow verification", report_run_id = displayedRun }, outputBase: output);
            Suppression.SetResult(preview);
            var applied = await DesktopActionRunner.Run(PythonPath.Text, "suppression_apply", new { plan = preview.GetProperty("plan") }, outputBase: output);
            Suppression.SetResult(applied);
            var undone = await DesktopActionRunner.Run(PythonPath.Text, "suppression_undo", new { plan = preview.GetProperty("plan") }, outputBase: output);
            Suppression.SetResult(undone);
            File.WriteAllText(Path.Combine(output, "native-actions-smoke.json"), JsonSerializer.Serialize(new { passed = loaded && History.ResultCount > 0 && undone.GetProperty("status").GetString() == "undone", comparison = History.SummaryText, suppression = Suppression.StatusMessage, providerEnabled = Provider.ReadConfiguration().EnableAi, manualDialogAcceptance = false }));
            Close(); return;
        }
        int exportIndex = Array.IndexOf(arguments,"--export-smoke");
        if (exportIndex >= 0)
        {
            string source = Path.GetFullPath(arguments[exportIndex + 1]);
            string output = Path.GetFullPath(arguments[exportIndex + 2]);
            // Test fixture identity supplied explicitly from a previously recorded broker request.
            var fixtureIdentity = new RunIdentity(arguments[exportIndex + 3],arguments[exportIndex + 4],1,DateTimeOffset.UtcNow);
            bool loaded = await LoadReport(source,fixtureIdentity);
            Directory.CreateDirectory(output);
            var selected = exportSelection ?? throw new InvalidDataException("Export smoke report unavailable.");
            bool artifactsListed = await ListSelectedArtifacts();
            var previewArtifact = (ArtifactRows.ItemsSource as IEnumerable<ArtifactRecord>)?.FirstOrDefault(record => record.Format is "md" or "markdown");
            ArtifactRows.SelectedItem = previewArtifact;
            bool artifactRead = previewArtifact != null && await ReadSelectedArtifact();
            presentation.Begin(new RunIdentity("different-active-run",fixtureIdentity.Repository,2,DateTimeOffset.UtcNow));
            UpdateRunSummary();
            await selected.Export(Path.Combine(output,selected.SuggestedName(false)),false);
            await selected.Export(Path.Combine(output,selected.SuggestedName(true)),true);
            string reviewMarkdown = await Task.Run(() => selected.ReadVerifiedMarkdown());
            string exportTitle = Path.GetFileNameWithoutExtension(selected.SuggestedName(".html"));
            string renderedHtml = ReviewExport.BuildHtml(reviewMarkdown,exportTitle);
            string htmlPath = Path.Combine(output,selected.SuggestedName(".html"));
            await ReviewExport.WriteHtmlAsync(htmlPath,renderedHtml);
            var printBrowsers = ReviewExport.FindPrintBrowsers();
            string? pdfHash = null;
            if (printBrowsers.Count > 0)
            {
                string pdfPath = Path.Combine(output,selected.SuggestedName(".pdf"));
                await ReviewExport.WritePdfWithAvailableBrowserAsync(renderedHtml,pdfPath);
                pdfHash = ExportSelection.Hash(File.ReadAllBytes(pdfPath));
            }
            bool htmlWritten = File.Exists(htmlPath);
            bool passedExport = loaded && artifactsListed && artifactRead && selected.RunId == fixtureIdentity.RunId && RunSummary.Text.Contains("PREVIOUS VALID REPORT") && RunSummary.Text.Contains("different-active-run") && htmlWritten && (printBrowsers.Count == 0 || pdfHash != null);
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"export-smoke.json"),JsonSerializer.Serialize(new { passed = passedExport, artifactsListed, artifactRead, artifactCount = ArtifactRows.Items.Count, artifactPreview = previewArtifact?.Name, selectedRun = selected.RunId, activeRun = "different-active-run (presentation fixture only)", disclosure = selected.Disclosure, jsonHash = ExportSelection.Hash(File.ReadAllBytes(Path.Combine(output,selected.SuggestedName(false)))), markdownHash = ExportSelection.Hash(File.ReadAllBytes(Path.Combine(output,selected.SuggestedName(true)))), htmlHash = htmlWritten ? ExportSelection.Hash(File.ReadAllBytes(htmlPath)) : null, pdfHash, pdfBrowsers = printBrowsers, pdfSkipped = printBrowsers.Count == 0 }));
            Close();
            return;
        }
        int structureIndex = Array.IndexOf(arguments, "--structure-smoke");
        if (structureIndex >= 0)
        {
            bool loaded = await LoadReport(arguments[structureIndex + 1]);
            Navigation.SelectedItem = Navigation.MenuItems[2];
            await Task.Delay(100); // Dispatch native navigation events before smoke assertions.
            StructureRecords.SelectedIndex = 0;
            await Task.Delay(100);
            bool architecturePassed = StructurePanel.Visibility == Visibility.Visible && StructureRecords.Items.Count > 0 && StructureDetail.Text.Contains("supplied");
            int architectureCount = StructureRecords.Items.Count;
            Navigation.SelectedItem = Navigation.MenuItems[3];
            StructureSearch.Text = "Dependency";
            await Task.Delay(100); // Dispatch native TextChanged before selecting filtered records.
            StructureRecords.SelectedIndex = 0;
            await Task.Delay(100);
            bool inventoryPassed = StructureRecords.Items.Count > 0 && StructureDetail.Text.Contains("ecosystem") && StructureDetail.Text.Contains("version") && StructureNotes.Text.Contains("runtime verification");
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"structure-smoke.json"),JsonSerializer.Serialize(new { passed = loaded && architecturePassed && inventoryPassed, architectureCount, inventoryCount = structure?.Inventory.Count, filteredDependencies = StructureRecords.Items.Count, detail = StructureDetail.Text, notes = StructureNotes.Text }));
            Close();
            return;
        }
        int settingsIndex = Array.IndexOf(arguments, "--settings-smoke");
        if (settingsIndex >= 0)
        {
            string python = Path.Combine(Path.GetTempPath(), "native settings smoke", "python.exe");
            string repository = Path.Combine(Path.GetTempPath(), "native settings smoke", "repository");
            bool save = arguments[settingsIndex + 2] == "save";
            if (save)
            {
                PythonPath.Text = python;
                repositoryPath = repository;
                ApplyScanOptions(new NativeScanOptions(Recall: true, StrictAnalyzers: true, NoSuppress: true, Cve: true, SecretsHistory: 12, TimeoutSeconds: 123), "javascript-web, config");
                SaveLocalSettings(this, new RoutedEventArgs());
            }
            else RestoreLocalSettings();
            bool passedSettings = settings.Load() == new LocalSettings(PythonPath: python, RepositoryPath: repository, Options: new NativeScanOptions(Recall: true, StrictAnalyzers: true, NoSuppress: true, Cve: true, SecretsHistory: 12, TimeoutSeconds: 123), Modules: "javascript-web, config") && NetworkDisclosure.Text.Contains("CVE ON") && ReadScanOptions() == settings.Load().EffectiveOptions && PythonPath.Text == python && repositoryPath == repository && !scanning;
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, $"settings-{(save ? "save" : "restore")}-smoke.json"), JsonSerializer.Serialize(new { passed = passedSettings, stage = save ? "save" : "restore", automaticScan = scanning, options = ReadScanOptions(), modules = ModulesOption.Text, networkDisclosure = NetworkDisclosure.Text }));
            Close();
            return;
        }
        int engineGuardIndex = Array.IndexOf(arguments, "--engine-guard-smoke");
        if (engineGuardIndex >= 0)
        {
            // Verify the engine-selection guards without spawning anything:
            // the app's own executable must be rejected as an engine (the
            // duplicate-window regression), a non-Python non-frozen executable
            // must be rejected, and a bundled engine must end up selected.
            string? selfRejected = null, foreignRejected = null;
            try { new EngineLaunchSpec(Environment.ProcessPath!); } catch (InvalidDataException error) { selfRejected = error.Message; }
            try { new EngineLaunchSpec(Path.Combine(Environment.SystemDirectory, "cmd.exe")); } catch (InvalidDataException error) { foreignRejected = error.Message; }
            string bundledEngine = Path.Combine(AppContext.BaseDirectory, "engine", "attackmap.exe");
            bool bundled = File.Exists(bundledEngine);
            string configured = PythonPath.Text.Trim();
            if (bundled && !File.Exists(configured)) PythonPath.Text = bundledEngine;
            bool guardPassed = selfRejected != null && foreignRejected != null && (!bundled || PythonPath.Text == bundledEngine);
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "engine-guard-smoke.json"), JsonSerializer.Serialize(new { passed = guardPassed, selfRejected, foreignRejected, bundledEnginePresent = bundled, bundledEngineSelected = PythonPath.Text }));
            Close();
            return;
        }
        int scanIndex = Array.IndexOf(arguments, "--scan-smoke");
        if (scanIndex >= 0)
        {
            bool loaded = false;
            string? failure = null;
            RunIdentity? smokeIdentity = null;
            string smokeStatus = "";
            if (arguments.Contains("--advanced")) ApplyScanOptions(new NativeScanOptions(StrictAnalyzers: true, NoSuppress: true, TimeoutSeconds: 120), "javascript-web, config");
            try
            {
                string output = scanIndex + 3 < arguments.Length ? Path.GetFullPath(arguments[scanIndex + 3]) : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", Guid.NewGuid().ToString("N"));
                await engine.Run(arguments[scanIndex + 1], arguments[scanIndex + 2], output, ++generation,
                    text => { smokeStatus = text; Status.Text = text; presentation.Update(text); UpdateRunSummary(); }, async path => loaded = await LoadReport(path, smokeIdentity), run => { smokeIdentity = run; presentation.Begin(run); UpdateRunSummary(); }, options: ReadScanOptions(), modules: ModulesOption.Text.Trim());
                presentation.End(smokeStatus); UpdateRunSummary();
            }
            catch (Exception error) { failure = error.Message; }
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "scan-smoke.json"), JsonSerializer.Serialize(new { passed = loaded && all.Count > 0 && Detail.Text.Contains("Recommendation"), loaded = all.Count, error = failure, runSummary = RunSummary.Text, coverage = CoverageSummary.Text, options = ReadScanOptions(), modules = ModulesOption.Text }));
            Close();
            return;
        }
        int reportIndex = Array.IndexOf(arguments, "--report-smoke");
        if (reportIndex >= 0)
        {
            bool loaded = reportIndex + 1 < arguments.Length && await LoadReport(arguments[reportIndex + 1]);
            var findingSettled = new TaskCompletionSource();
            DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => findingSettled.SetResult());
            await findingSettled.Task;
            ((FrameworkElement)Content).UpdateLayout();
            var findingViewport = new { width = FindingsPanel.ActualWidth, height = FindingsPanel.ActualHeight, listHeight = Findings.ActualHeight, inspectorWidth = FindingInspector.ActualWidth, stacked = Grid.GetRow(FindingInspector) == 1 };
            bool passedReport = loaded && all.Count > 0 && Detail.Text.Contains(all[0].Id) && Detail.Text.Contains("Priority supplied by engine") && Detail.Text.Contains("Uncertainty") && RunSummary.Text.Contains("Scan timestamp unavailable") && CoverageSummary.Text.Contains("legacy aggregate");
            Navigation.SelectedItem = Navigation.MenuItems[4];
            var settled = new TaskCompletionSource();
            DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => settled.SetResult());
            await settled.Task;
            bool reviewVisible = ReportsPanel.Visibility == Visibility.Visible && FindingsPanel.Visibility == Visibility.Collapsed && ReviewText.Text.Length > 0;
            var liveLocations = loaded && findingRecords.Count > 0 ? SourceLocation.Inspect(displayedRepository, findingRecords[0].GetRawText()) : [];
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "report-smoke.json"), JsonSerializer.Serialize(new { passed = passedReport && reviewVisible, loaded = all.Count, selected = (Findings.SelectedItem as FixtureFinding)?.Id, findingViewport, reviewVisible, sourceLocations = liveLocations, selectedManifestIntegrity = exportSelection?.Verified == true ? "captured manifest checked" : "unverified", brokerExecutionIdentity = "not established by saved import", runSummary = RunSummary.Text, coverage = CoverageSummary.Text }));
            Close();
            return;
        }
        await LoadData();
        Search.Text = "Synthetic authorization review 00042";
        await Task.Delay(100); // Allow the native TextChanged event to dispatch.
        Findings.SelectedIndex = 0;
        await Task.Delay(100); // Allow the native SelectionChanged event to dispatch.
        bool passed = all.Count == 10000 && Findings.Items.Count == 1 &&
            Detail.Text.Contains("synthetic-00042") && Detail.Text.Contains("Recommendation");
        File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "spike-smoke.json"),
            JsonSerializer.Serialize(new { passed, loaded = all.Count, filtered = Findings.Items.Count,
                selected = (Findings.SelectedItem as FixtureFinding)?.Id, shellDestinations = Navigation.MenuItems.Count }));
        Close();
    }
    private void UpdateRunSummary() { RunSummary.Text = presentation.Summary; CoverageSummary.Text = presentation.Coverage; WorkspaceLabel.Text = $"Workspace: {repositoryPath ?? "none selected"}\nDisplayed: {(string.IsNullOrEmpty(displayedRepository) ? "none" : displayedRepository)}"; ToolTipService.SetToolTip(WorkspaceLabel, WorkspaceLabel.Text); }
    private void ResponsivePanels(object sender, SizeChangedEventArgs args)
    {
        if (!ready || sender is not Grid panel || panel.ActualWidth <= 0) return;
        bool stacked = panel.ActualWidth < 720;
        bool findings = panel == FindingsPanel;
        var inspector = findings ? FindingInspector : StructureInspector;
        int first = findings ? 0 : 1;
        panel.ColumnDefinitions[1].Width = stacked ? new GridLength(0) : new GridLength(1, GridUnitType.Star);
        panel.RowDefinitions[first + 1].Height = stacked ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
        Grid.SetColumn(inspector, stacked ? 0 : 1);
        Grid.SetRow(inspector, stacked ? first + 1 : first);
    }
    private async Task<bool> LoadPerformanceReport(string path) { Search.Text = ""; return await LoadReport(path); }
    private Task ClosePerformanceReport()
    {
        all = []; findingRecords = []; Findings.ItemsSource = null; structure = null; exportSelection = null;
        ResetAiReview();
        ReviewText.Text = "No report selected.";
        ArtifactRows.ItemsSource = null; ArtifactText.Text = "No report selected.";
        OverviewText.Text = "No report selected.";
        displayedReportPath = null; displayedRepository = ""; displayedRun = "";
        StructureRecords.ItemsSource = null; Detail.Text = "No report selected.";
        History.CurrentReportPath = ""; Suppression.SetContext("", default, "");
        return Task.CompletedTask;
    }
    private static string ThemeStorePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", "theme.json");

    private void LoadSavedTheme()
    {
        try
        {
            if (!File.Exists(ThemeStorePath)) return;
            var saved = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText(ThemeStorePath)).GetProperty("theme").GetString();
            ApplyTheme(saved == "light" ? ElementTheme.Light : saved == "dark" ? ElementTheme.Dark : ElementTheme.Default);
        }
        catch (Exception) { /* unreadable theme choice falls back to system */ }
    }

    private void ApplyTheme(ElementTheme theme)
    {
        ((FrameworkElement)Content).RequestedTheme = theme;
        ThemeSystemItem.IsChecked = theme == ElementTheme.Default;
        ThemeLightItem.IsChecked = theme == ElementTheme.Light;
        ThemeDarkItem.IsChecked = theme == ElementTheme.Dark;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ThemeStorePath)!);
            var value = theme == ElementTheme.Light ? "light" : theme == ElementTheme.Dark ? "dark" : "system";
            File.WriteAllText(ThemeStorePath, JsonSerializer.Serialize(new { theme = value }));
        }
        catch (Exception) { /* theme choice is best-effort persistence */ }
    }

    private void ThemeSystemClick(object sender, RoutedEventArgs args) => ApplyTheme(ElementTheme.Default);
    private void ThemeLightClick(object sender, RoutedEventArgs args) => ApplyTheme(ElementTheme.Light);
    private void ThemeDarkClick(object sender, RoutedEventArgs args) => ApplyTheme(ElementTheme.Dark);

    private void Navigate(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (!ready || actionLifetime.IsCancellationRequested) return;
        ++renderDiagnosticsNavigationRevision;
        if (!navigatingBack && previousDestination != null && previousDestination != args.SelectedItem) navigationBack.Push(previousDestination);
        previousDestination = args.SelectedItem;
        Navigation.IsBackEnabled = navigationBack.Count > 0;
        Heading.Text = args.IsSettingsSelected ? "Settings" :
            (args.SelectedItem as NavigationViewItem)?.Content?.ToString() ?? "Overview";
        bool structured = Heading.Text is "Architecture" or "Inventory";
        bool history = Heading.Text == "History", provider = Heading.Text == "Settings", reports = Heading.Text == "Reports", overview = Heading.Text == "Overview", scanOptions = Heading.Text == "Scan options";
        FindingsPanel.Visibility = structured || history || provider || reports || overview || scanOptions ? Visibility.Collapsed : Visibility.Visible;
        OverviewPanel.Visibility = overview ? Visibility.Visible : Visibility.Collapsed;
        ReportsPanel.Visibility = reports ? Visibility.Visible : Visibility.Collapsed;
        StructurePanel.Visibility = structured ? Visibility.Visible : Visibility.Collapsed;
        HistoryPanel.Visibility = history ? Visibility.Visible : Visibility.Collapsed;
        ProviderPanel.Visibility = provider ? Visibility.Visible : Visibility.Collapsed;
        ScanOptionsPanel.Visibility = scanOptions ? Visibility.Visible : Visibility.Collapsed;
        bool risk = Heading.Text == "Risk and paths", evidenceInventory = Heading.Text == "Evidence inventory", diagrams = Heading.Text == "Diagrams", fleet = Heading.Text == "Fleet", suppressions = Heading.Text == "Suppressions";
        RiskPaths.Visibility = risk ? Visibility.Visible : Visibility.Collapsed;
        EvidenceInventory.Visibility = evidenceInventory ? Visibility.Visible : Visibility.Collapsed;
        Diagrams.Visibility = diagrams ? Visibility.Visible : Visibility.Collapsed;
        if (diagrams) _ = Diagrams.ActivateInteractive();
        Fleet.Visibility = fleet ? Visibility.Visible : Visibility.Collapsed;
        SuppressionWorkspace.Visibility = suppressions ? Visibility.Visible : Visibility.Collapsed;
        if (risk || evidenceInventory || diagrams || fleet || suppressions) FindingsPanel.Visibility = Visibility.Collapsed;
        inventoryView = Heading.Text == "Inventory";
        if (structured) { ShowStructure(); return; }
        Status.Text = Heading.Text switch {
            "History" => "Choose a baseline to compare with the exact displayed report. Coverage uncertainty stays separate from resolved findings.",
            "Scan options" => "Set the engine executable and scan defaults. Options apply to the next scan.",
            "Settings" => "Configure optional AI explicitly. Save protects credentials; connection checks send no repository evidence.",
            "Reports" => "Export the exact displayed report JSON or verified review Markdown using the save controls.",
            _ => "Open a canonical report, scan locally, or select a finding for evidence and reasoned suppression."
        };
        if (history) _ = LoadRetainedGenerations();
    }
    private void FilterStructure(object sender, TextChangedEventArgs args) { if (ready) ShowStructure(); }
    private void ShowStructure()
    {
        var records = structure == null ? new List<StructureRecord>() : inventoryView ? structure.Inventory : structure.Architecture;
        string query = StructureSearch.Text.Trim();
        var matches = records.Where(row => $"{row.Title} {row.Summary}".Contains(query,StringComparison.OrdinalIgnoreCase)).ToList();
        StructureRecords.ItemsSource = matches;
        StructureNotes.Text = structure == null ? "No canonical report loaded. Synthetic findings do not supply architecture or inventory." : inventoryView ? structure.InventoryNotes : structure.ArchitectureNotes;
        Status.Text = $"{matches.Count} of {records.Count} supplied {(inventoryView ? "inventory" : "architecture")} records. See displayed report coverage.";
        StructureDetail.Text = matches.Count == 0 ? "No matching supplied records. Missing records are not proof of absence." : "Select a supplied record for evidence, source and uncertainty.";
    }
    private void SelectStructure(object sender, SelectionChangedEventArgs args)
    {
        if (ready && StructureRecords.SelectedItem is StructureRecord row) StructureDetail.Text = row.Detail;
    }
    private void Filter(object sender, TextChangedEventArgs args)
    {
        if (ready) ShowMatches();
    }
    private void ShowMatches()
    {
        string query = Search.Text.Trim();
        var matches = all.Where(f => $"{f.Title} {f.Summary}".Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
        Findings.ItemsSource = matches;
        Status.Text = $"{matches.Count:N0} of {all.Count:N0} {reportLabel}.";
        Detail.Text = matches.Count == 0 ? "No matches. Clear the filter or load the fixture." : "Select a finding for evidence and recommendation.";
    }
    private void SelectFinding(object sender, SelectionChangedEventArgs args)
    {
        if (ready) { SourceLocations.ItemsSource = null; SourceWarning.Text = "Source files may have changed since the scan. Inspect locations before revealing their folder."; }
        if (ready && Findings.SelectedItem is not FixtureFinding) { ++findingRevision; Suppression.SetContext("", default, ""); FindingSeverityChip.Visibility = Visibility.Collapsed; }
        if (ready && Findings.SelectedItem is FixtureFinding finding)
        {
            ++findingRevision;
            FindingSeverityChip.Background = MarkdownView.SeverityBrush(finding.Severity);
            FindingSeverityLabel.Text = finding.SeverityLabel;
            FindingSeverityChip.Visibility = Visibility.Visible;
            Detail.Text = $"{finding.Id}\n{finding.Title}\n{finding.Summary}\n\nEvidence (engine supplied; classification shown above)\n{finding.Evidence}\n\nRecommendation\n{finding.Recommendation}";
            int index = all.IndexOf(finding);
            Suppression.SetContext(displayedRepository, index >= 0 && index < findingRecords.Count ? findingRecords[index] : default, displayedRun);
        }
        if (ready) RenderDiagnosticsWrite("finding-selection", new { generation, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision,
            hasFinding = Findings.SelectedItem is FixtureFinding });
    }

    private async void InspectSource(object sender, RoutedEventArgs args)
    {
        if (Findings.SelectedItem is not FixtureFinding finding) return;
        int index = all.IndexOf(finding);
        if (index < 0 || index >= findingRecords.Count || string.IsNullOrWhiteSpace(displayedRepository)) { SourceWarning.Text = "No structured source locations are supplied for this selection."; return; }
        long revision = findingRevision;
        string repository = displayedRepository, json = findingRecords[index].GetRawText();
        try
        {
            var locations = await Task.Run(() => SourceLocation.Inspect(repository, json));
            if (actionLifetime.IsCancellationRequested || revision != findingRevision) return;
            SourceLocations.ItemsSource = locations;
            SourceWarning.Text = locations.Count == 0 ? "No structured source locations supplied." : "Live file checks do not verify the finding. Select a location to reveal its folder or copy its path.";
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested && revision == findingRevision) SourceWarning.Text = "Source inspection failed. Saved evidence remains available above."; }
    }
    private async void RevealSource(object sender, RoutedEventArgs args)
    {
        if (SourceLocations.SelectedItem is not SourceLocationResult { Status: "valid", FullPath: not null } location) { SourceWarning.Text = "Inspect and select an accessible source location first."; return; }
        SourceWarning.Text = location.Warning;
        try { var folder = await Windows.Storage.StorageFolder.GetFolderFromPathAsync(Path.GetDirectoryName(location.FullPath)!); if (!await Windows.System.Launcher.LaunchFolderAsync(folder)) throw new IOException("Folder launch declined."); }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) SourceWarning.Text = "Source folder could not be revealed; the live file may have moved."; }
    }
    private void CopySource(object sender, RoutedEventArgs args)
    {
        if (SourceLocations.SelectedItem is not SourceLocationResult { FullPath: not null } location) return;
        try
        {
            var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
            data.SetText($"{location.FullPath}:{location.Line?.ToString() ?? "unknown"}");
            Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
            SourceWarning.Text = location.Warning;
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) SourceWarning.Text = $"Source location could not be copied. Try again or select its path manually. {location.Warning}"; }
    }

    private void RestoreProviderSettings()
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", "provider.json");
        try
        {
            if (!File.Exists(path) || restoredScanOptions.Provider != null) return;
            if (new FileInfo(path).Length > 16384) throw new InvalidDataException("Provider settings exceed their limit.");
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (document.RootElement.GetProperty("schema_version").GetInt32() != 1) throw new InvalidDataException("Unsupported provider settings.");
            var config = document.RootElement.GetProperty("configuration").Deserialize<ProviderConfiguration>() ?? throw new InvalidDataException("Missing provider configuration.");
            config.Validate();
            Provider.ApplyConfiguration(config);
            NetworkOptionChanged(this, new RoutedEventArgs());
        }
        catch (Exception) { Provider.ShowResult("Saved provider settings could not be restored. Original preserved; configure and save explicitly. No connection was made."); }
    }

    private async void ListArtifacts(object sender, RoutedEventArgs args) => await ListSelectedArtifacts();
    private async Task<bool> ListSelectedArtifacts()
    {
        var selected = exportSelection;
        if (selected == null || !selected.Verified) { ArtifactStatus.Text = "Open a verified broker generation to browse artifacts. Legacy reports retain JSON export."; return false; }
        if (artifactBusy) return false;
        artifactBusy = true; ArtifactListButton.IsEnabled = ArtifactReadButton.IsEnabled = false;
        try
        {
            var records = await Task.Run(() => SelectedArtifacts.List(selected));
            if (actionLifetime.IsCancellationRequested || exportSelection != selected) return false;
            ArtifactRows.ItemsSource = records;
            ArtifactStatus.Text = selected.Disclosure;
            return true;
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested && exportSelection == selected) ArtifactStatus.Text = "Artifact listing failed or selected files changed. Reopen the report; previous preview retained."; return false; }
        finally { artifactBusy = false; if (!actionLifetime.IsCancellationRequested) ArtifactListButton.IsEnabled = ArtifactReadButton.IsEnabled = true; }
    }
    private async void ReadArtifact(object sender, RoutedEventArgs args) => await ReadSelectedArtifact();
    private async Task<bool> ReadSelectedArtifact()
    {
        var selected = exportSelection;
        if (artifactBusy || selected == null || ArtifactRows.SelectedItem is not ArtifactRecord record) return false;
        artifactBusy = true; ArtifactListButton.IsEnabled = ArtifactReadButton.IsEnabled = false;
        try
        {
            string content = await SelectedArtifacts.ReadText(selected, record);
            if (actionLifetime.IsCancellationRequested || exportSelection != selected || !Equals(ArtifactRows.SelectedItem, record)) return false;
            ArtifactText.Text = content;
            ArtifactStatus.Text = $"{record.Name}: verified selected-run text ({record.Format}). {selected.Disclosure}";
            return true;
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested && exportSelection == selected) ArtifactStatus.Text = "Artifact changed, is unavailable, or exceeds the 4 MiB text preview limit. Reopen the report; previous preview retained."; return false; }
        finally { artifactBusy = false; if (!actionLifetime.IsCancellationRequested) ArtifactListButton.IsEnabled = ArtifactReadButton.IsEnabled = true; }
    }
    private async void RevealReportFolder(object sender, RoutedEventArgs args)
    {
        var selected = exportSelection;
        if (selected == null) { Status.Text = "Open a report before revealing its folder."; return; }
        try { var folder = await Windows.Storage.StorageFolder.GetFolderFromPathAsync(Path.GetDirectoryName(selected.ReportPath)!); if (!await Windows.System.Launcher.LaunchFolderAsync(folder)) throw new IOException("Folder launch declined."); }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "The displayed report folder could not be revealed; its saved file may have moved."; }
    }
    private async Task CompareReports(ComparisonRequest request)
    {
        if (actionRunning || scanning) { History.SetError("Wait for the current scan/action to finish."); return; }
        string? selected = displayedReportPath;
        string hash = displayedReadHash;
        long requestGeneration = generation;
        actionRunning = true; History.SetBusy(true);
        try
        {
            if (selected == null || selected != request.CurrentPath) throw new InvalidDataException("Select the displayed current report first.");
            var result = await DesktopActionRunner.Run(PythonPath.Text.Trim(), "compare", new { baseline_path = request.BaselinePath, current_path = request.CurrentPath }, cancellationToken: actionLifetime.Token);
            if (result.GetProperty("current").GetProperty("report_sha256").GetString() != hash) throw new InvalidDataException("Current report changed since it was displayed. Reopen it before comparing.");
            if (displayedReportPath == selected && displayedReadHash == hash && generation == requestGeneration && !actionLifetime.IsCancellationRequested) History.SetResult(result);
        }
        catch (Exception) { if (displayedReportPath == selected && !actionLifetime.IsCancellationRequested) History.SetError("Comparison failed. Verify report identity, coverage and engine path; previous results are preserved."); }
        finally { actionRunning = DesktopActionRunner.CleanupBlocked; if (!actionLifetime.IsCancellationRequested) History.SetBusy(false); }
    }

    private string RetentionBase() => ScanLocations.ReportsBase(repositoryPath!);

    private async Task LoadRetainedGenerations()
    {
        if (actionRunning || scanning) { History.SetRetentionStatus("Wait for the current scan/action to finish."); return; }
        if (repositoryPath == null) { History.SetRetentionStatus("Choose a repository first; generations are retained per repository."); return; }
        string python = PythonPath.Text.Trim();
        if (!Path.IsPathFullyQualified(python) || !File.Exists(python)) { History.SetRetentionStatus("Choose an absolute engine Python path to list and pin retained generations."); return; }
        if (!Directory.Exists(RetentionBase())) { History.SetRetentionStatus("No scan output exists for this repository yet. Run a scan first."); return; }
        actionRunning = true; History.SetRetentionBusy(true);
        try
        {
            var result = await DesktopActionRunner.Run(python, "diagnostics_preview", new { output_base = RetentionBase() }, cancellationToken: actionLifetime.Token);
            if (!actionLifetime.IsCancellationRequested) History.SetGenerations(result);
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) History.SetRetentionError("Retained generations are unavailable. Verify the engine path and the repository's scan output."); }
        finally { actionRunning = DesktopActionRunner.CleanupBlocked; if (!actionLifetime.IsCancellationRequested) History.SetRetentionBusy(false); }
    }

    private async Task ToggleGenerationPin(RetentionPinRequest request)
    {
        if (actionRunning || scanning) { History.SetRetentionStatus("Wait for the current scan/action to finish."); return; }
        if (repositoryPath == null) { History.SetRetentionStatus("Choose a repository first."); return; }
        actionRunning = true; History.SetRetentionBusy(true);
        bool changed = false;
        try
        {
            var result = await DesktopActionRunner.Run(PythonPath.Text.Trim(), request.Pin ? "pin_generation" : "unpin_generation",
                new { output_base = RetentionBase(), run_id = request.RunId }, cancellationToken: actionLifetime.Token);
            changed = true;
            if (actionLifetime.IsCancellationRequested) return;
            if (result.TryGetProperty("pinned", out var pinned) && pinned.ValueKind == JsonValueKind.Array)
                History.SetRetentionStatus(request.Pin
                    ? $"Pinned runs always kept by cleanup: {string.Join(", ", pinned.EnumerateArray().Select(value => value.GetString()))}"
                    : $"Unpinned {request.RunId}; future cleanup may remove it under the retention policy.");
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) History.SetRetentionError("Pin change did not complete. Verify the engine path; the previous pin state is preserved."); }
        finally { actionRunning = DesktopActionRunner.CleanupBlocked; if (!actionLifetime.IsCancellationRequested) History.SetRetentionBusy(false); }
        if (changed && !actionRunning && !actionLifetime.IsCancellationRequested) await LoadRetainedGenerations();
    }

    private async Task ExportDiagnosticsBundle()
    {
        if (actionRunning || scanning) { History.SetRetentionStatus("Wait for the current scan/action to finish."); return; }
        if (repositoryPath == null) { History.SetRetentionStatus("Choose a repository first."); return; }
        string python = PythonPath.Text.Trim();
        if (!Path.IsPathFullyQualified(python) || !File.Exists(python)) { History.SetRetentionStatus("Choose an absolute engine Python path first."); return; }
        try
        {
            if (History.OwnerWindowHandle == 0) { History.SetRetentionStatus("The save picker has no owner window. Reopen History and try again."); return; }
            var picker = new Windows.Storage.Pickers.FileSavePicker();
            picker.SuggestedFileName = "attackmap-diagnostics";
            picker.FileTypeChoices.Add("Redacted diagnostic bundle", new List<string> { ".json" });
            WinRT.Interop.InitializeWithWindow.Initialize(picker, History.OwnerWindowHandle);
            var file = await picker.PickSaveFileAsync();
            if (file is null) return;
            actionRunning = true; History.SetRetentionBusy(true);
            await DesktopActionRunner.Run(python, "diagnostics_export",
                new { output_base = RetentionBase(), target_path = file.Path }, cancellationToken: actionLifetime.Token);
            if (!actionLifetime.IsCancellationRequested)
                History.SetRetentionStatus($"Diagnostic bundle written: {file.Path}. Redacted; no source excerpts are included.");
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) History.SetRetentionError("Diagnostic export failed. Verify the engine path and choose a writable target file."); }
        finally { actionRunning = DesktopActionRunner.CleanupBlocked; if (!actionLifetime.IsCancellationRequested) History.SetRetentionBusy(false); }
    }

    private async Task ChangeSuppression(SuppressionActionRequest request)
    {
        if (actionRunning || scanning) { Suppression.SetResult(JsonSerializer.SerializeToElement(new { status = "failed", message = "Wait for the current scan/action before changing configuration." })); return; }
        long revision = findingRevision;
        actionRunning = true; Suppression.SetBusy(true);
        try
        {
            var payload = JsonSerializer.SerializeToNode(request.Payload)!.AsObject();
            if (request.Operation == "suppression_preview" && BlankOption(SuppressFileOption.Text) is string selectedFile) payload["suppress_file"] = selectedFile;
            var result = await DesktopActionRunner.Run(PythonPath.Text.Trim(), request.Operation, payload, cancellationToken: actionLifetime.Token);
            if (revision == findingRevision && !actionLifetime.IsCancellationRequested) Suppression.SetResult(result);
        }
        catch (Exception) { if (revision == findingRevision && !actionLifetime.IsCancellationRequested) Suppression.SetResult(JsonSerializer.SerializeToElement(new { status = "failed", message = "Action did not confirm completion. A change may have applied; use Recover/Undo with the retained preview. Local request snapshot is preserved." })); }
        finally { actionRunning = DesktopActionRunner.CleanupBlocked; if (!actionLifetime.IsCancellationRequested) Suppression.SetBusy(false); }
    }

    private async Task ProviderAction(string operation, ProviderAccessRequest request)
    {
        if (actionRunning || scanning) { Provider.ShowResult("Wait for the active scan/action before provider changes."); return; }
        actionRunning = true;
        Provider.IsEnabled = false;
        try
        {
            var result = await DesktopActionRunner.Run(PythonPath.Text.Trim(), operation, new { configuration = request.Configuration }, request.Credential, cancellationToken: actionLifetime.Token);
            if (actionLifetime.IsCancellationRequested) return;
            if (operation == "provider_save")
            {
                // The protected credential action has the legacy wire contract. Persist
                // the complete preferences separately, including AI-off advanced values.
                Provider.ApplyConfiguration(request.Preferences);
                settings.Save(new LocalSettings(PythonPath: PythonPath.Text.Trim(), RepositoryPath: repositoryPath ?? "", Options: ReadScanOptions(), Modules: ModulesOption.Text.Trim()));
            }
            string message = result.GetProperty("message").GetString() ?? "Provider action completed.";
            if (operation == "provider_check" && result.TryGetProperty("selected_model_listed", out var listed) && listed.ValueKind == JsonValueKind.False && !message.Contains("NOT listed", StringComparison.Ordinal))
                message = "Selected model was NOT listed. Check the exact model ID (including case) before scanning. " + message;
            Provider.ShowResult(message);
            NetworkOptionChanged(this, new RoutedEventArgs());
        }
        catch (System.IO.InvalidDataException error) { if (!actionLifetime.IsCancellationRequested) Provider.ShowResult(error.Message); }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Provider.ShowResult("Provider action failed. Check endpoint, model and protected credential storage; no secrets were logged."); }
        finally { actionRunning = DesktopActionRunner.CleanupBlocked; if (!actionLifetime.IsCancellationRequested) Provider.IsEnabled = !DesktopActionRunner.CleanupBlocked; }
    }
}
