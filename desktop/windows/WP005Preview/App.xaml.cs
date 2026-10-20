using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Storage.Streams;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using AttackMap.NativeSpike;

namespace AttackMap.WP005Preview;

public partial class App : Application
{
    private Window? window;
    private static void Trace(string stage)
    {
        try
        {
            string[] args = Environment.GetCommandLineArgs();
            string root = args.Length > 1 ? Path.GetFullPath(args[1]) : AppContext.BaseDirectory;
            Directory.CreateDirectory(root);
            File.AppendAllText(Path.Combine(root, "startup.log"), DateTimeOffset.UtcNow.ToString("O") + " " + stage + Environment.NewLine);
        }
        catch { }
    }
    public App()
    {
        Trace("App constructor before InitializeComponent");
        UnhandledException += (_, args) => Trace("Unhandled application exception: " + args.Exception);
        InitializeComponent();
        Trace("App constructor completed");
    }
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        Trace("OnLaunched entry");
        string[] command = Environment.GetCommandLineArgs();
        string root = command.Length > 1 ? Path.GetFullPath(command[1]) : AppContext.BaseDirectory;
        Directory.CreateDirectory(root);
        window = new Window { Title = "AttackMap — scan settings preview" };
        Trace("Window constructed");
        window.AppWindow.Resize(new Windows.Graphics.SizeInt32(1160, 960));
        SettingsPreview view = new SettingsPreview(window, Path.Combine(root, "preview-settings.json"));
        Trace("Settings control constructed");
        window.Content = view;
        view.Loaded += (_, _) => Trace("Native control Loaded");
        if (command.Contains("--capture")) view.Loaded += async (_, _) =>
        {
            try
            {
                await Task.Delay(1200);
                Trace("Capture journey starting");
                var journey = view.RunControlledJourney(root);
                Trace("Capture journey completed");
                foreach (int state in command.Contains("--supported-only") ? new[] { 0 } : new[] { 0, 1 })
                {
                    view = new SettingsPreview(window, Path.Combine(root, "preview-settings.json"));
                    window.Content = view;
                    view.ChangeCompatibility(state);
                    await Task.Delay(1000);
                    view.UpdateLayout();
                    var bitmap = new RenderTargetBitmap();
                    await bitmap.RenderAsync(view);
                    Trace("RenderTargetBitmap completed for state " + state);
                    var pixels = (await bitmap.GetPixelsAsync()).ToArray();
                    var folder = await StorageFolder.GetFolderFromPathAsync(root);
                    var file = await folder.CreateFileAsync("preview-" + state + ".png", CreationCollisionOption.ReplaceExisting);
                    using var stream = await file.OpenAsync(FileAccessMode.ReadWrite);
                    var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
                    encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, (uint)bitmap.PixelWidth, (uint)bitmap.PixelHeight, 96, 96, pixels);
                    await encoder.FlushAsync();
                }
                File.WriteAllText(Path.Combine(root, "preview-result.json"), JsonSerializer.Serialize(new { rendered = true, journey, capabilities = "synthetic fixture", engineProcesses = 0, providerCalls = 0, manualKeyboardAcceptance = false }));
            }
            catch (Exception error) { Trace("Capture failed: " + error); File.WriteAllText(Path.Combine(root, "preview-error.txt"), error.ToString()); }
            if (command.Contains("--close")) window.Close();
        };
        window.Activate();
        Trace("Window Activate returned");
    }
}

public sealed class SettingsPreview : Grid
{
    private readonly Window window;
    private readonly LocalSettingsStore store;
    private LocalSettings snapshot = new();
    private EngineCapabilities? capabilities;
    private readonly EngineCapabilitiesCache cache = new();
    private readonly TextBox engine = new() { PlaceholderText = "Bundled engine (recommended)" }, modules = new(), baseline = new(), suppress = new(), history = new() { Text = "0" }, timeout = new() { Text = "600" }, budget = new(), endpoint = new() { Text = "http://127.0.0.1:1234/v1" }, model = new() { Text = "cyberstag-security-26b-a4b-v1" };
    private readonly CheckBox recall = new() { Content = "Recall" }, strict = new() { Content = "Strict analyzers" }, noSuppress = new() { Content = "Disable suppressions" }, cve = new() { Content = "CVE lookup (OSV network request)" }, ai = new() { Content = "AI review (explicit scan only)" }, high = new() { Content = "Fail policy on new high findings" }, newSuppression = new() { Content = "Fail policy on new suppressions" }, strictSuppression = new() { Content = "Strict suppression validation" }, isolation = new() { Content = "Isolate analyzers" };
    private readonly TextBlock status = new() { TextWrapping = TextWrapping.Wrap }, unavailable = new() { TextWrapping = TextWrapping.Wrap };
    private readonly ComboBox compatibility = new() { HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly StackPanel extended = new() { Spacing = 8 };
    public SettingsPreview(Window window, string path)
    {
        this.window = window; store = new(path);
        RequestedTheme = ElementTheme.Light;
        Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.White);
        Padding = new Thickness(28); RowSpacing = 16;
        foreach (var box in new[] { baseline, suppress }) { box.TextWrapping = TextWrapping.Wrap; box.AcceptsReturn = true; box.MinHeight = 64; }
        status.Foreground = unavailable.Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Black);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(status, "Settings status");
        RowDefinitions.Add(new() { Height = GridLength.Auto }); RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) }); RowDefinitions.Add(new() { Height = GridLength.Auto });
        var heading = new StackPanel { Spacing = 6 };
        heading.Children.Add(new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Black), Text = "Scan settings", FontSize = 28, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        heading.Children.Add(new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Black), Text = "Standalone native preview · synthetic capabilities · no engine or provider is launched", TextWrapping = TextWrapping.Wrap });
        Children.Add(heading);
        var body = new Grid { ColumnSpacing = 28 }; body.ColumnDefinitions.Add(new()); body.ColumnDefinitions.Add(new()); SetRow(body, 1); Children.Add(body);
        var left = new StackPanel { Spacing = 4 }; body.Children.Add(new ScrollViewer { Content = left, VerticalScrollBarVisibility = ScrollBarVisibility.Visible, VerticalScrollMode = ScrollMode.Enabled, Padding = new Thickness(0, 0, 12, 16) });
        Add(left, "Engine", engine); engine.TextChanged += (_, _) => { cache.Invalidate(); status.Text = "Engine choice changed. Cached compatibility cleared; no probe or scan started."; };
        var choose = new Button { Content = "Choose explicit engine…" }; choose.Click += ChooseEngine; left.Children.Add(choose);
        left.Children.Add(new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Black), Text = "Leave the path empty for the bundled engine. Advanced choices require an existing absolute engine path.", TextWrapping = TextWrapping.Wrap, FontSize = 12 });
        Add(left, "Installed analyzer names (empty = Automatic)", modules);
        var toggles = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 }; toggles.Children.Add(recall); toggles.Children.Add(strict); left.Children.Add(toggles); left.Children.Add(noSuppress); left.Children.Add(cve);
        Add(left, "Git secret history (commits)", history); Add(left, "Hard scan timeout (seconds)", timeout);
        left.Children.Add(ai); Add(left, "Local/provider endpoint", endpoint); Add(left, "Model", model);

        var right = new StackPanel { Spacing = 12 }; var rightScroll = new ScrollViewer { Content = right }; SetColumn(rightScroll, 1); body.Children.Add(rightScroll);
        compatibility.Items.Add("Schema 1.2 fixture — advanced options supported"); compatibility.Items.Add("Schema 1.1 fixture — advanced options unavailable"); compatibility.Items.Add("Unknown capability major — request disabled"); compatibility.SelectedIndex = 0;
        Add(right, "Preview compatibility state (synthetic)", compatibility); compatibility.SelectionChanged += (_, _) => RefreshCompatibility();
        Add(extended, "Baseline report (absolute local file)", baseline); Add(extended, "Suppression file (absolute local file)", suppress);
        extended.Children.Add(high); extended.Children.Add(newSuppression); extended.Children.Add(strictSuppression); extended.Children.Add(isolation); Add(extended, "Soft deterministic budget (seconds, optional)", budget); right.Children.Add(extended);
        right.Children.Add(unavailable);
        right.Children.Add(new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Black), Text = "Hunt / verify / remediate / triage, fleet, incremental and memory/worker limits remain unavailable. Saved unsupported values are retained; no substitute request is sent.", TextWrapping = TextWrapping.Wrap, FontSize = 12 });
        var footer = new StackPanel { Spacing = 12 }; SetRow(footer, 2); Children.Add(footer);
        footer.Children.Add(new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Black), Text = "Startup/reopen only restores preferences. AI and CVE require an explicit scan; these seven advanced options add no network call.", TextWrapping = TextWrapping.Wrap, FontSize = 12 });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
        var save = new Button { Content = "Save settings" }; save.Click += (_, _) => Attempt(SaveSettings);
        var reopen = new Button { Content = "Reopen settings" }; reopen.Click += (_, _) => Attempt(Reopen);
        var validate = new Button { Content = "Validate request (no scan)" }; validate.Click += (_, _) => Attempt(() => { var options = ReadOptions(); capabilities!.RequireSupport(options, modules.Text); status.Text = "Request validated as schema " + options.RequestSchema + ". No scan or provider request started."; });
        var reset = new Button { Content = "Reset advanced options" }; reset.Click += (_, _) => { baseline.Text = suppress.Text = budget.Text = ""; high.IsChecked = newSuppression.IsChecked = strictSuppression.IsChecked = isolation.IsChecked = false; status.Text = "Seven advanced choices explicitly reset. Save when ready; no scan started."; };
        buttons.Children.Add(save); buttons.Children.Add(reopen); buttons.Children.Add(validate); buttons.Children.Add(reset); footer.Children.Add(buttons); footer.Children.Add(status);
        RefreshCompatibility(); Attempt(Reopen);
    }
    private static void Add(Panel panel, string title, UIElement element) { panel.Children.Add(new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Black), Text = title, FontSize = 13 }); Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(element, title); panel.Children.Add(element); }
    private void Attempt(Action action) { try { action(); } catch (Exception error) when (error is IOException or JsonException or InvalidDataException or UnauthorizedAccessException or FormatException) { status.Text = error.Message + " Original preferences retained."; } }
    private NativeScanOptions ReadOptions() => snapshot.EffectiveOptions with { Recall = recall.IsChecked == true, StrictAnalyzers = strict.IsChecked == true, NoSuppress = noSuppress.IsChecked == true, Cve = cve.IsChecked == true,
        SecretsHistory = int.Parse(history.Text), TimeoutSeconds = int.Parse(timeout.Text), Baseline = string.IsNullOrWhiteSpace(baseline.Text) ? null : baseline.Text.Trim(), SuppressFile = string.IsNullOrWhiteSpace(suppress.Text) ? null : suppress.Text.Trim(),
        FailOnNewHigh = high.IsChecked == true, FailOnNewSuppression = newSuppression.IsChecked == true, StrictSuppressions = strictSuppression.IsChecked == true, IsolatedAnalyzers = isolation.IsChecked == true,
        TimeBudgetSeconds = string.IsNullOrWhiteSpace(budget.Text) ? null : int.Parse(budget.Text), Provider = (snapshot.EffectiveOptions.Provider ?? new()) with { EnableAi = ai.IsChecked == true, Endpoint = endpoint.Text, Model = model.Text } };
    private void SaveSettings()
    {
        snapshot = snapshot with { PythonPath = engine.Text.Trim(), Modules = modules.Text.Trim(), Options = ReadOptions() };
        store.Save(snapshot); status.Text = "Saved all supported preferences. No engine or network request started.";
    }
    public object RunControlledJourney(string root)
    {
        ChangeCompatibility(0);
        baseline.Text = Path.Combine(root, "synthetic-baseline.json"); suppress.Text = Path.Combine(root, "synthetic-suppressions.yml");
        File.WriteAllText(baseline.Text, "{}"); File.WriteAllText(suppress.Text, "suppressions: []");
        high.IsChecked = newSuppression.IsChecked = strictSuppression.IsChecked = isolation.IsChecked = true;
        recall.IsChecked = strict.IsChecked = true; noSuppress.IsChecked = cve.IsChecked = ai.IsChecked = false;
        history.Text = "12"; timeout.Text = "37"; budget.Text = "17";
        SaveSettings(); var saved = ReadOptions(); baseline.Text = ""; budget.Text = ""; high.IsChecked = false; Reopen();
        bool reopened = ReadOptions() == saved;
        capabilities!.RequireSupport(ReadOptions(), modules.Text);
        string request = NativeScanRequest.Serialize("preview-synthetic", root, Path.Combine(root, "unexecuted-output"), 1, ReadOptions(), modules.Text);
        File.WriteAllText(Path.Combine(root, "preview-request.json"), request);
        ChangeCompatibility(1); bool rejected = false;
        try { capabilities!.RequireSupport(ReadOptions(), modules.Text); } catch (InvalidDataException) { rejected = true; }
        bool retained = ReadOptions() == saved && extended.Children.OfType<Control>().All(control => !control.IsEnabled);
        if (!reopened || !rejected || !retained) throw new InvalidDataException("Controlled native settings journey failed.");
        status.Text = "Controlled native preview: save/reopen preserved all choices; schema 1.1 rejects retained 1.2 choices. No scan or provider request started.";
        return new { savedAndReopened = reopened, oldEngineRejectedNewOptions = rejected, disabledValuesRetained = retained, requestSchema = saved.RequestSchema, manualInteraction = false };
    }
    private void Reopen()
    {
        snapshot = store.Load(); var options = snapshot.EffectiveOptions; engine.Text = snapshot.PythonPath; modules.Text = snapshot.Modules;
        recall.IsChecked = options.Recall; strict.IsChecked = options.StrictAnalyzers; noSuppress.IsChecked = options.NoSuppress; cve.IsChecked = options.Cve;
        history.Text = options.SecretsHistory.ToString(); timeout.Text = options.TimeoutSeconds.ToString(); baseline.Text = options.Baseline ?? ""; suppress.Text = options.SuppressFile ?? "";
        high.IsChecked = options.FailOnNewHigh; newSuppression.IsChecked = options.FailOnNewSuppression; strictSuppression.IsChecked = options.StrictSuppressions; isolation.IsChecked = options.IsolatedAnalyzers; budget.Text = options.TimeBudgetSeconds?.ToString() ?? "";
        var provider = options.Provider ?? new(); ai.IsChecked = provider.EnableAi; endpoint.Text = provider.Endpoint ?? ""; model.Text = provider.Model ?? "";
        status.Text = "Preferences reopened. No scan, engine probe or provider request started.";
    }
    private async void ChooseEngine(object sender, RoutedEventArgs args)
    {
        try
        {
            var picker = new Windows.Storage.Pickers.FileOpenPicker(); picker.FileTypeFilter.Add(".exe"); WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(window));
            var file = await picker.PickSingleFileAsync(); if (file == null) return;
            string chosen = new EngineLaunchSpec(file.Path).ExecutablePath; engine.Text = chosen; cache.SelectEngine(chosen); status.Text = "Explicit engine selected. Compatibility cache cleared; no executable was launched.";
        }
        catch (Exception error) { status.Text = "Engine selection unavailable: " + error.Message; }
    }
    public void ChangeCompatibility(int state) { compatibility.SelectedIndex = state; RefreshCompatibility(); }
    private void RefreshCompatibility()
    {
        string[] old = { "recall", "strict_analyzers", "no_suppress", "cve", "secrets_history", "timeout_seconds", "provider" };
        string[] current = old.Concat(new[] { "baseline", "suppress_file", "fail_on_new_high", "fail_on_new_suppression", "strict_suppressions", "isolated_analyzers", "time_budget_seconds" }).ToArray();
        string executable = Environment.ProcessPath!; using var file = File.OpenRead(executable); string hash = Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant();
        int state = compatibility.SelectedIndex;
        string fixture = state == 2 ? "{\"schema\":99}" : JsonSerializer.Serialize(new { schema = 1, commands = new[] { "desktop-worker", "desktop-action" }, engine_identity = new { path = executable, sha256 = hash, size_bytes = file.Length, runtime_kind = "Frozen" }, modules = Array.Empty<object>(),
            desktop = new { schema_versions = state == 0 ? new[] { "1.0", "1.1", "1.2" } : new[] { "1.0", "1.1" }, scan_options = state == 0 ? current : old, provider_options = new[] { "enable_ai", "provider", "endpoint", "model", "max_calls", "timeout_seconds", "output_token_limit" }, modes = new[] { "none", "review" }, providers = new[] { "openai", "claude" } } });
        capabilities = EngineCapabilities.Parse(fixture); bool available = capabilities.Option("baseline").Enabled;
        foreach (var control in extended.Children.OfType<Control>()) control.IsEnabled = available;
        unavailable.Text = available ? "Schema 1.2 advanced options are available in this synthetic preview state. Paths/policies/ranges still require validation." : capabilities.Option("baseline").Reason;
    }
}



