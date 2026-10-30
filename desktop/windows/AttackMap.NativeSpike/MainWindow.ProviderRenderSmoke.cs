using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private string? providerRenderActionDirectory;
    // Opt-in reproduction of the reported scan -> report -> settings journey.
    // All test state lives in the supplied directory; never starts a provider call.
    private async void ProviderRenderSmokeLoaded(object sender, RoutedEventArgs args)
    {
        var root = (FrameworkElement)Content;
        root.Loaded -= ProviderRenderSmokeLoaded;
        var argv = Environment.GetCommandLineArgs();
        string report = Path.GetFullPath(argv[2]), output = Path.GetFullPath(argv[3]);
        var captures = new List<CaptureMetadata>();
        var checks = new Dictionary<string, bool>();
        string scanStatus = "not started";
        try
        {
            if (!Directory.Exists(output)) throw new DirectoryNotFoundException(output);
            checks["savedReportLoaded"] = await LoadReport(report);
            if (!checks["savedReportLoaded"]) throw new InvalidDataException("Report failed to load.");
            PythonPath.Text = Path.GetFullPath(argv[4]);
            providerRenderActionDirectory = Path.Combine(output, "actions");
            repositoryPath = displayedRepository;
            presentation.SelectRepository(repositoryPath);
            ApplyScanOptions(new NativeScanOptions(Provider: new ProviderConfiguration(EnableAi: false)), "");
            await RunSelectedRepository(Path.Combine(output, "reports"));
            scanStatus = Status.Text;
            checks["nativeScanCompleted"] = scanProgress.Terminal && scanProgress.State == "completed";
            checks["scanControlsRestored"] = ScanButton.IsEnabled && !CancelButton.IsEnabled && Provider.IsEnabled && ScanOptionsPanel.IsEnabled;
            checks["reviewPresent"] = ReviewText.Text.Length > 0;
            Provider.ApplyConfiguration(new ProviderConfiguration(Endpoint: "https://api.z.ai/api/coding/paas/v4", Model: "glm-5.3-flash"));
            Provider.ShowResult("Selected model was NOT listed. Check the exact model ID (including case) before scanning. Model listing does not prove generation.");
            foreach (var size in new[] { (Width: 1024, Height: 700), (Width: 1600, Height: 1000) })
            foreach (var theme in new[] { ElementTheme.Dark, ElementTheme.Light })
            {
                root.RequestedTheme = theme;
                double scale = root.XamlRoot.RasterizationScale;
                AppWindow.Resize(new Windows.Graphics.SizeInt32((int)(size.Width * scale), (int)(size.Height * scale)));
                foreach (var destination in new[] { Navigation.MenuItems[4], Navigation.MenuItems[6], Navigation.SettingsItem })
                {
                    Navigation.SelectedItem = destination;
                    await Task.Delay(450);
                    root.UpdateLayout();
                    if (destination == Navigation.MenuItems[6])
                    {
                        // Expand only after the destination's visual tree is realized.
                        foreach (var expander in ProviderScrollElements(ScanOptionsPanel).OfType<Expander>()) expander.IsExpanded = true;
                        root.UpdateLayout();
                        await Task.Delay(250);
                    }
                    string view = Heading.Text.Replace(' ', '-');
                    captures.Add(await CaptureStrict(root, Path.Combine(output, $"{size.Width}-{theme}-{view}.png"), requireVisibleContent: true));
                    if (destination == Navigation.SettingsItem)
                    {
                        Provider.ScrollHost.ChangeView(null, Provider.ScrollHost.ScrollableHeight, null, true);
                        await Task.Delay(250);
                        captures.Add(await CaptureStrict(root, Path.Combine(output, $"{size.Width}-{theme}-Settings-bottom.png"), requireVisibleContent: true));
                        Provider.ScrollHost.ChangeView(null, 0, null, true);
                    }
                }
            }
            checks["navigationLabelsRetained"] = Navigation.MenuItems.OfType<NavigationViewItem>().All(item => !string.IsNullOrWhiteSpace(item.Content?.ToString()));
            File.WriteAllText(Path.Combine(output, "proof.json"), JsonSerializer.Serialize(new { checks, passed = checks.Values.All(x => x), captures,
                scanStatus, selectedReport = displayedReportPath, providerCalls = 0, scope = NativeCaptureProbe.Scope }, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception error) { File.WriteAllText(Path.Combine(output, "failure.json"), JsonSerializer.Serialize(new { error = error.ToString(), scanStatus, checks, captures })); }
        finally { Close(); }
    }
}
