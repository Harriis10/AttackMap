using System.Text.Json;
namespace LifetimeRegression;

public sealed class BaselineWindow : WindowFixture, IWindowScenario
{
    public Task<bool> Load(string path) => LoadReport(path);
    public Task Fixture() => LoadData();
    public void SendNavigation() => Navigate(Navigation, new() { SelectedItem = new NavigationViewItem { Content = "Overview" } });
    public void SendNetwork() => NetworkOptionChanged(this, new());
    public void SendPlacement() => CaptureWindowPlacement();
    public void Close()
    {
        ObserveMiddleClosedSubscriber();
        actionLifetime.Cancel(); keyboardBindings?.Dispose(); engine.Disconnect();
    }
    private async Task<bool> LoadReport(string path, RunIdentity? identity = null)
    {
        long current = ++generation;
        try
        {
            var report = await ReportAdapter.Load(path);
            if (actionLifetime.IsCancellationRequested || current != generation) return false;
            var selectedExport = identity == null
                ? ExportSelection.CaptureSavedGeneration(path,report.ReadHash,report.Repository)
                : ExportSelection.Capture(path,report.ReadHash,identity);
            string engineTiming = await ScanTiming.ReadLabel(selectedExport);
            var sections = await ReportSectionAdapter.Load(path, report.ReadHash, selectedExport.RunId);
            var overview = await ParityOverviewAdapter.Load(path, report.ReadHash, selectedExport.RunId);
            if (actionLifetime.IsCancellationRequested || current != generation) return false;
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
            return !actionLifetime.IsCancellationRequested && current == generation;
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException or InvalidDataException or InvalidOperationException or KeyNotFoundException)
        {
            if (current == generation) Status.Text = $"Report import failed ({error.Message}). Previous valid report retained.";
            return false;
        }
    }

    private async Task LoadData()
    {
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
            Status.Text = $"Fixture unavailable ({error.GetType().Name}). Generate it and retry Load fixture.";
        }
    }

    private void Navigate(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (!ready) return;
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

    private void NetworkOptionChanged(object sender, RoutedEventArgs args)
    {
        if (!ready) return;
        string ai;
        try { var options = activeScanOptions?.Provider ?? (activeScanOptions == null ? Provider.ReadConfiguration() : new ProviderConfiguration()); ai = options.EnableAi ? $"AI ON: sends structured evidence and minimized source excerpts to {options.Provider} / {options.Endpoint ?? "provider default endpoint"}" : "AI off"; }
        catch (Exception) { ai = "AI options invalid; scan will require correction"; }
        NetworkDisclosure.Text = ai + ((activeScanOptions?.Cve ?? CveOption.IsChecked == true) ? "; CVE ON: sends dependency names/versions to OSV" : "; CVE lookup off");
    }

    private void CaptureWindowPlacement()
    {
        if (!placementPersistenceEnabled || ((FrameworkElement)Content).XamlRoot == null || AppWindow.Presenter is not Microsoft.UI.Windowing.OverlappedPresenter presenter || presenter.State != Microsoft.UI.Windowing.OverlappedPresenterState.Restored) return;
        double scale = ((FrameworkElement)Content).XamlRoot.RasterizationScale;
        int width = (int)Math.Round(AppWindow.Size.Width / scale), height = (int)Math.Round(AppWindow.Size.Height / scale);
        if (width < 1024 || height < 700 || width > 16384 || height > 16384) return;
        lastPlacement = new WindowPlacement(Width: width, Height: height, Left: AppWindow.Position.X, Top: AppWindow.Position.Y);
    }
}


public sealed class CoreWindow : WindowFixture, IWindowScenario
{
    public Task<bool> Load(string path) => LoadReport(path);
    public Task Fixture() => LoadData();
    public void SendNavigation() => Navigate(Navigation, new() { SelectedItem = new NavigationViewItem { Content = "Overview" } });
    public void SendNetwork() => NetworkOptionChanged(this, new());
    public void SendPlacement() => CaptureWindowPlacement();
    public void Close()
    {
        ready = false; ++generation; actionLifetime.Cancel();
        ObserveMiddleClosedSubscriber();
        keyboardBindings?.Dispose(); engine.Disconnect();
    }
    private async Task<bool> LoadReport(string path, RunIdentity? identity = null)
    {
        if (actionLifetime.IsCancellationRequested) return false;
        long current = ++generation;
        try
        {
            var report = await ReportAdapter.Load(path);
            if (actionLifetime.IsCancellationRequested || current != generation) return false;
            var selectedExport = identity == null
                ? ExportSelection.CaptureSavedGeneration(path,report.ReadHash,report.Repository)
                : ExportSelection.Capture(path,report.ReadHash,identity);
            string engineTiming = await ScanTiming.ReadLabel(selectedExport);
            var sections = await ReportSectionAdapter.Load(path, report.ReadHash, selectedExport.RunId);
            var overview = await ParityOverviewAdapter.Load(path, report.ReadHash, selectedExport.RunId);
            if (actionLifetime.IsCancellationRequested || current != generation) return false;
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
            return !actionLifetime.IsCancellationRequested && current == generation;
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException or InvalidDataException or InvalidOperationException or KeyNotFoundException)
        {
            if (!actionLifetime.IsCancellationRequested && current == generation) Status.Text = $"Report import failed ({error.Message}). Previous valid report retained.";
            return false;
        }
    }

    private async Task LoadData()
    {
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
            Status.Text = $"Fixture unavailable ({error.GetType().Name}). Generate it and retry Load fixture.";
        }
    }

    private void Navigate(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (!ready || actionLifetime.IsCancellationRequested) return;
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

    private void NetworkOptionChanged(object sender, RoutedEventArgs args)
    {
        if (!ready || actionLifetime.IsCancellationRequested) return;
        string ai;
        try { var options = activeScanOptions?.Provider ?? (activeScanOptions == null ? Provider.ReadConfiguration() : new ProviderConfiguration()); ai = options.EnableAi ? $"AI ON: sends structured evidence and minimized source excerpts to {options.Provider} / {options.Endpoint ?? "provider default endpoint"}" : "AI off"; }
        catch (Exception) { ai = "AI options invalid; scan will require correction"; }
        NetworkDisclosure.Text = ai + ((activeScanOptions?.Cve ?? CveOption.IsChecked == true) ? "; CVE ON: sends dependency names/versions to OSV" : "; CVE lookup off");
    }

    private void CaptureWindowPlacement()
    {
        if (!placementPersistenceEnabled || ((FrameworkElement)Content).XamlRoot == null || AppWindow.Presenter is not Microsoft.UI.Windowing.OverlappedPresenter presenter || presenter.State != Microsoft.UI.Windowing.OverlappedPresenterState.Restored) return;
        double scale = ((FrameworkElement)Content).XamlRoot.RasterizationScale;
        int width = (int)Math.Round(AppWindow.Size.Width / scale), height = (int)Math.Round(AppWindow.Size.Height / scale);
        if (width < 1024 || height < 700 || width > 16384 || height > 16384) return;
        lastPlacement = new WindowPlacement(Width: width, Height: height, Left: AppWindow.Position.X, Top: AppWindow.Position.Y);
    }
}


public sealed class OptionalWindow : WindowFixture, IWindowScenario
{
    public Task<bool> Load(string path) => LoadReport(path);
    public Task Fixture() => LoadData();
    public void SendNavigation() => Navigate(Navigation, new() { SelectedItem = new NavigationViewItem { Content = "Overview" } });
    public void SendNetwork() => NetworkOptionChanged(this, new());
    public void SendPlacement() => CaptureWindowPlacement();
    public void Close()
    {
        ready = false; ++generation; actionLifetime.Cancel();
        ObserveMiddleClosedSubscriber();
        keyboardBindings?.Dispose(); engine.Disconnect();
    }
    private async Task<bool> LoadReport(string path, RunIdentity? identity = null)
    {
        if (actionLifetime.IsCancellationRequested) return false;
        long current = ++generation;
        try
        {
            var report = await ReportAdapter.Load(path);
            if (actionLifetime.IsCancellationRequested || current != generation) return false;
            var selectedExport = identity == null
                ? ExportSelection.CaptureSavedGeneration(path,report.ReadHash,report.Repository)
                : ExportSelection.Capture(path,report.ReadHash,identity);
            string engineTiming = await ScanTiming.ReadLabel(selectedExport);
            var sections = await ReportSectionAdapter.Load(path, report.ReadHash, selectedExport.RunId);
            var overview = await ParityOverviewAdapter.Load(path, report.ReadHash, selectedExport.RunId);
            if (actionLifetime.IsCancellationRequested || current != generation) return false;
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
            return !actionLifetime.IsCancellationRequested && current == generation;
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException or InvalidDataException or InvalidOperationException or KeyNotFoundException)
        {
            if (!actionLifetime.IsCancellationRequested && current == generation) Status.Text = $"Report import failed ({error.Message}). Previous valid report retained.";
            return false;
        }
    }

    private async Task LoadData()
    {
        if (actionLifetime.IsCancellationRequested) return;
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

    private void Navigate(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (!ready || actionLifetime.IsCancellationRequested) return;
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

    private void NetworkOptionChanged(object sender, RoutedEventArgs args)
    {
        if (!ready || actionLifetime.IsCancellationRequested) return;
        string ai;
        try { var options = activeScanOptions?.Provider ?? (activeScanOptions == null ? Provider.ReadConfiguration() : new ProviderConfiguration()); ai = options.EnableAi ? $"AI ON: sends structured evidence and minimized source excerpts to {options.Provider} / {options.Endpoint ?? "provider default endpoint"}" : "AI off"; }
        catch (Exception) { ai = "AI options invalid; scan will require correction"; }
        NetworkDisclosure.Text = ai + ((activeScanOptions?.Cve ?? CveOption.IsChecked == true) ? "; CVE ON: sends dependency names/versions to OSV" : "; CVE lookup off");
    }

    private void CaptureWindowPlacement()
    {
        if (actionLifetime.IsCancellationRequested || !placementPersistenceEnabled || ((FrameworkElement)Content).XamlRoot == null || AppWindow.Presenter is not Microsoft.UI.Windowing.OverlappedPresenter presenter || presenter.State != Microsoft.UI.Windowing.OverlappedPresenterState.Restored) return;
        double scale = ((FrameworkElement)Content).XamlRoot.RasterizationScale;
        int width = (int)Math.Round(AppWindow.Size.Width / scale), height = (int)Math.Round(AppWindow.Size.Height / scale);
        if (width < 1024 || height < 700 || width > 16384 || height > 16384) return;
        lastPlacement = new WindowPlacement(Width: width, Height: height, Left: AppWindow.Position.X, Top: AppWindow.Position.Y);
    }
}
