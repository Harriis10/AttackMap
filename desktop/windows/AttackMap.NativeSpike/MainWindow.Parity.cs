using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private NativeScanOptions restoredScanOptions = new();
    private readonly EngineCapabilitiesCache capabilityCache = new();
    private readonly AnalyzerSelectionModel analyzerSelection = new();
    private readonly ScanProgressModel scanProgress = new();
    private AnalyzerSelectionView? analyzerView;
    private ReportSections? paritySections;
    private bool synchronizingAnalyzers;
    private readonly Stack<object> navigationBack = new();
    private object? previousDestination;
    private bool navigatingBack;
    private Task parityViewBinding = Task.CompletedTask;
    private static string? BlankOption(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private void InitializeParityWorkspace()
    {
        RiskPaths.ShowHeading = false;
        EvidenceInventory.ShowHeading = false;
        Navigation.IsBackButtonVisible = NavigationViewBackButtonVisible.Visible;
        Navigation.IsBackEnabled = false;
        Navigation.BackRequested += (_, _) => {
            if(navigationBack.Count==0)return;
            navigatingBack=true;
            try { Navigation.SelectedItem=navigationBack.Pop(); }
            finally { navigatingBack=false;Navigation.IsBackEnabled=navigationBack.Count>0; }
        };
        analyzerView = new AnalyzerSelectionView(analyzerSelection);
        AnalyzerHost.Content = analyzerView;
        analyzerView.SelectionChanged += () => {
            synchronizingAnalyzers = true;
            ModulesOption.Text = analyzerSelection.RequestModules;
            synchronizingAnalyzers = false;
        };
        ModulesOption.TextChanged += (_, _) => {
            if (synchronizingAnalyzers) return;
            try { analyzerSelection.Restore(ModulesOption.Text); analyzerView.Refresh(); }
            catch (InvalidDataException error) { EngineCompatibility.Text = error.Message; }
        };
        PythonPath.TextChanged += (_, _) => {
            capabilityCache.Invalidate(); Provider.ApplyCapabilities(null);
            ApplyOptionCapabilities(null);
            analyzerSelection.EngineChanged(); analyzerView.Refresh();
            EngineCompatibility.Text = "Engine changed. Check compatibility again; saved options are retained.";
        };
        EvidenceOverview.NavigationRequested += NavigateOverviewRecord;
        RiskPaths.FindingRequested += SelectFindingIdentity;
        RiskPaths.SourceRequested += async source => await InspectParitySource(source.File, source.Line);
        EvidenceInventory.SourceRequested += async source => await InspectParitySource(source.File, source.Line);
        Diagrams.ExportTextRequested += async text => await ExportDiagramText(text);
        ApplyOptionCapabilities(null);
        Closed += (_, _) => { Diagrams.Stop(); AiArtifacts.Stop(); };
    }

    private async void CheckEngineCapabilities(object sender, RoutedEventArgs args)
    {
        if (scanning || actionRunning || engine.CleanupBlocked || DesktopActionRunner.CleanupBlocked) { EngineCompatibility.Text = "Wait for the active engine operation and verified cleanup."; return; }
        actionRunning = true;
        try { capabilityCache.Invalidate(); await DiscoverEngineCapabilities(); }
        catch (Exception error) { if (!actionLifetime.IsCancellationRequested) EngineCompatibility.Text = "Compatibility unavailable: " + error.Message; }
        finally { actionRunning = DesktopActionRunner.CleanupBlocked; }
    }

    private async Task DiscoverEngineCapabilities(CancellationToken cancellationToken = default)
    {
        string selected = EngineCapabilities.ResolveEngine(PythonPath.Text, AppContext.BaseDirectory);
        capabilityCache.SelectEngine(selected);
        if (capabilityCache.Current != null) return;
        var result = await DesktopActionRunner.Run(selected, "capabilities", new { }, cancellationToken: cancellationToken.CanBeCanceled ? cancellationToken : actionLifetime.Token);
        if (actionLifetime.IsCancellationRequested || EngineCapabilities.ResolveEngine(PythonPath.Text, AppContext.BaseDirectory) != selected) throw new InvalidDataException("Engine selection changed during discovery. Retry explicitly.");
        var capabilities = EngineCapabilities.Parse(result.GetRawText());
        capabilityCache.Store(selected, capabilities);
        Provider.ApplyCapabilities(capabilities);
        ApplyOptionCapabilities(capabilities);
        analyzerSelection.LoadDiscovery(result.GetRawText()); analyzerView!.Refresh();
        EngineCompatibility.Text = capabilities.Reason + $" Installed analyzers: {capabilities.Analyzers.Count}.";
        if (!capabilities.Compatible) throw new InvalidDataException(capabilities.Reason);
    }

    private void CheckScanAdmission(long requestedGeneration, string repository, string executable, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (generation != requestedGeneration || repositoryPath != repository || EngineCapabilities.ResolveEngine(PythonPath.Text, AppContext.BaseDirectory) != executable)
            throw new OperationCanceledException("Scan selection changed during admission; no stale worker was started.", token);
    }

    private void ApplyOptionCapabilities(EngineCapabilities? capabilities)
    {
        foreach (var (name, control) in new (string, Control)[] {
            ("baseline", BaselineOption), ("suppress_file", SuppressFileOption), ("fail_on_new_high", FailNewHighOption),
            ("fail_on_new_suppression", FailNewSuppressionOption), ("strict_suppressions", StrictSuppressionsOption),
            ("isolated_analyzers", IsolatedAnalyzersOption), ("time_budget_seconds", TimeBudgetOption) })
        {
            var support = capabilities?.Option(name) ?? new CapabilityAvailability(false, "Check engine compatibility first; the saved value is retained.");
            control.IsEnabled = support.Enabled; ToolTipService.SetToolTip(control, support.Reason);
        }
        BaselinePicker.IsEnabled = BaselineOption.IsEnabled; SuppressionPicker.IsEnabled = SuppressFileOption.IsEnabled;
    }

    private async void ChooseScanBaseline(object sender, RoutedEventArgs args) => await ChooseOptionFile(BaselineOption, new[] { ".json" });
    private async void ChooseScanSuppression(object sender, RoutedEventArgs args) => await ChooseOptionFile(SuppressFileOption, new[] { ".yaml", ".yml" });
    private async Task ChooseOptionFile(TextBox field, string[] extensions)
    {
        try
        {
            var picker = new Windows.Storage.Pickers.FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            foreach (string extension in extensions) picker.FileTypeFilter.Add(extension);
            var file = await picker.PickSingleFileAsync();
            if (file != null && !actionLifetime.IsCancellationRequested) field.Text = file.Path;
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "File picker unavailable. The existing selection is preserved."; }
    }

    private void BindParityReport(ReportSections sections, ParityOverview overview, ExportSelection selected)
    {
        paritySections = sections;
        suppressionWorkspace = new SuppressionWorkspaceModel(sections) { NoSuppress = NoSuppressOption.IsChecked == true };
        SuppressionWorkspace.SetModel(suppressionWorkspace);
        RiskPaths.SetReport(sections); EvidenceInventory.SetReport(sections); EvidenceOverview.SetOverview(overview);
        parityViewBinding = Task.WhenAll(Diagrams.SetSelection(selected), AiArtifacts.SetSelection(selected));
    }

    private void SelectFindingIdentity(string identity)
    {
        var matches = all.Where(row => row.Id == identity).Take(2).ToArray();
        if (matches.Length != 1) { Status.Text = "The supplied finding reference is unavailable or ambiguous in this displayed report."; return; }
        var finding = matches[0];
        Search.Text = ""; Navigation.SelectedItem = Navigation.MenuItems[1]; Findings.SelectedItem = finding;
        Findings.ScrollIntoView(finding);
    }

    private void NavigateOverviewRecord(OverviewLink link)
    {
        if (paritySections == null || link.Generation != displayedRun || link.ReportHash != displayedReadHash) return;
        if (link.Kind == "finding") SelectFindingIdentity(link.Identity);
        else
        {
            Navigation.SelectedItem = Navigation.MenuItems[link.Kind == "path" ? 7 : 8];
            bool selected=link.Kind=="path"?RiskPaths.SelectPathIdentity(link.Identity):EvidenceInventory.SelectIdentity(link.Identity);
            Status.Text = selected?$"Selected supplied {link.Kind}: {link.Identity}.":$"Supplied {link.Kind} reference {link.Identity} is unavailable or ambiguous in this report.";
        }
    }

    private async Task InspectParitySource(string file, int? line)
    {
        var selected = paritySections;
        if (selected == null) return;
        string json = JsonSerializer.Serialize(new { locations = new[] { new { file, line } } });
        try
        {
            var locations = await Task.Run(() => SourceLocation.Inspect(selected.Repository, json));
            if (actionLifetime.IsCancellationRequested || paritySections != selected) return;
            var location = locations.FirstOrDefault();
            bool reveal = location is { Status: "valid", FullPath: not null };
            var dialog = new ContentDialog { XamlRoot = ((FrameworkElement)Content).XamlRoot, Title = "Supplied source location", Content = $"{file}:{line?.ToString() ?? "unknown"}\n{location?.Warning ?? "Source is unavailable."}", CloseButtonText = "Close" };
            if (reveal) dialog.PrimaryButtonText = "Show folder";
            if (await dialog.ShowAsync() == ContentDialogResult.Primary && reveal && paritySections == selected && !actionLifetime.IsCancellationRequested)
            {
                var folder = await Windows.Storage.StorageFolder.GetFolderFromPathAsync(Path.GetDirectoryName(location!.FullPath!)!);
                await Windows.System.Launcher.LaunchFolderAsync(folder);
            }
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Source inspection unavailable; the displayed report is preserved."; }
    }

    private async Task ExportDiagramText(string text)
    {
        var selected = exportSelection;
        if (selected == null || !selected.Verified) return;
        try
        {
            var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = "attackmap-diagram" };
            picker.FileTypeChoices.Add("Selected diagram text", new List<string> { ".mmd" });
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            var file = await picker.PickSaveFileAsync();
            if (file == null || actionLifetime.IsCancellationRequested) return;
            selected.EnsureExportDestination(file.Path, selected.ReportPath);
            _ = SelectedArtifacts.List(selected); // Revalidate the captured generation after the picker.
            await WriteSelectedBytes(file.Path, System.Text.Encoding.UTF8.GetBytes(text));
            Status.Text = "Exported the captured diagram text. " + selected.Disclosure;
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) Status.Text = "Diagram export unavailable or selected generation changed; retry after reopening the report."; }
    }
}
