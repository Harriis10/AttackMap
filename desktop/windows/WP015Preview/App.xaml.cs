using AttackMap.NativeSpike;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Storage;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text.Json;

namespace AttackMap.WP015Preview;

public partial class App : Application
{
    private Window? window;
    private static void Trace(string text)
    {
        string? path = Environment.GetCommandLineArgs().Skip(2).FirstOrDefault();
        if (path != null) File.AppendAllText(Path.GetFullPath(path), DateTimeOffset.UtcNow.ToString("O") + " " + text + Environment.NewLine);
    }
    public App() { Trace("App constructor before InitializeComponent"); InitializeComponent(); Trace("App initialized"); }
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        Trace("OnLaunched");
        var view = new ProviderSettingsView();
        view.SizeChanged += (_, _) => view.Clip = new Microsoft.UI.Xaml.Media.RectangleGeometry {
            Rect = new Windows.Foundation.Rect(0, 0, view.ActualWidth, view.ActualHeight) };
        var status = new TextBlock { Text = "Standalone native AI settings preview. No engine or provider is connected.", TextWrapping = TextWrapping.Wrap };
        view.SaveRequested += _ => status.Text = "Preview intercepted Save. No credential or setting written; no request sent.";
        view.TestConnectionRequested += _ => status.Text = "Preview intercepted Test. No provider request sent.";
        var panel = new Grid { Padding = new Thickness(20), RowDefinitions = { new RowDefinition { Height = GridLength.Auto }, new RowDefinition() } };
        panel.Children.Add(status); Grid.SetRow(view, 1); panel.Children.Add(view);
        window = new Window { Title = "AttackMap — WP015 AI preferences preview", Content = panel };
        window.AppWindow.Resize(new Windows.Graphics.SizeInt32(650, 760));
        string? fixture = Environment.GetCommandLineArgs().Skip(1).FirstOrDefault();
        if (fixture != null) view.ApplyCapabilities(EngineCapabilities.Parse(File.ReadAllText(Path.GetFullPath(fixture))));
        string[] command = Environment.GetCommandLineArgs();
        int captureIndex = Array.IndexOf(command, "--capture");
        if (captureIndex >= 0) view.Loaded += async (_, _) =>
        {
            string? captureRoot = null;
            bool captureCreated = false;
            try
            {
                if (captureIndex + 1 >= command.Length || !Path.IsPathFullyQualified(command[captureIndex + 1]))
                    throw new InvalidDataException("--capture requires a new absolute output directory.");
                captureRoot = Path.GetFullPath(command[captureIndex + 1]);
                if (Directory.Exists(captureRoot)) throw new IOException("Capture output directory already exists; choose a unique path.");
                Directory.CreateDirectory(captureRoot);
                captureCreated = true;
                panel.RequestedTheme = ElementTheme.Light;
                panel.Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.White);
                int actions = 0;
                view.SaveRequested += _ => actions++;
                view.TestConnectionRequested += _ => actions++;
                await Task.Delay(1200);
                await Capture(panel, Path.Combine(captureRoot, "clean-ai-off.png"));
                var preferences = new ProviderConfiguration(true) { Mode = "hunt_verify", JuryVotes = 3, Effort = "max", Backend = "api", Speed = "standard" };
                view.ApplyConfiguration(preferences);
                view.ReadRequestConfiguration();
                await CapturePages(panel, view, captureRoot, "supported");
                view.ApplyCapabilities(null);
                bool rejected = false;
                try { view.ReadRequestConfiguration(); } catch (InvalidDataException) { rejected = true; }
                if (!rejected || view.ReadConfiguration() != preferences || actions != 0)
                    throw new InvalidDataException("Inert capability-switch journey failed.");
                await CapturePages(panel, view, captureRoot, "unsupported-retained");
                view.ResetPreferences();
                if (view.ReadConfiguration().EnableAi || actions != 0) throw new InvalidDataException("Reset was not inert.");
                File.WriteAllText(Path.Combine(captureRoot, "result.json"), JsonSerializer.Serialize(new {
                    rendered = true, supportedRequestValidated = true, unsupportedRequestRejected = rejected,
                    preferencesRetained = true, resetAiOff = true, providerActions = actions,
                    engineProcesses = 0, providerCalls = 0, syntheticCapabilities = true,
                    manualKeyboardAcceptance = false, text200PercentAcceptance = false }));
                Trace("Capture and inert capability-switch/reset journey completed");
            }
            catch (Exception error)
            {
                Trace("Capture failed: " + error);
                if (captureCreated && captureRoot != null)
                    File.WriteAllText(Path.Combine(captureRoot, "error.txt"), error.ToString());
            }
            finally { if (command.Contains("--close")) window.Close(); }
        };
        if (Environment.GetCommandLineArgs().Contains("--smoke")) view.Loaded += (_, _) =>
        {
            int actions = 0;
            view.SaveRequested += _ => actions++;
            view.TestConnectionRequested += _ => actions++;
            view.ApplyConfiguration(new ProviderConfiguration(true) { Mode = "hunt_verify", JuryVotes = 3, Effort = "max" });
            view.ApplyCapabilities(null);
            view.ApplyConfiguration(view.ReadConfiguration() with { EnableAi = false, Speed = "fast", Backend = "cli" });
            view.ResetPreferences();
            if (actions != 0 || view.ReadConfiguration().EnableAi) throw new InvalidDataException("Inert preference journey failed.");
            Trace("Loaded inert switch/restore/reset journey passed; Save/Test actions=0; AI off");
            window.Close();
        };
        window.Activate();
        Trace("Window Activate returned");
    }
    private static async Task CapturePages(Grid panel, ProviderSettingsView view, string root, string state)
    {
        var scroll = (ScrollViewer)view.Content;
        scroll.ChangeView(null, 0, null, true);
        await Task.Delay(600);
        double step = Math.Max(200, scroll.ViewportHeight * 0.75);
        int count = (int)Math.Ceiling(scroll.ScrollableHeight / step) + 1;
        if (count > 12) throw new InvalidDataException("Unexpected preview scroll extent; capture bounded to twelve pages per state.");
        for (int page = 0; page < count; page++)
        {
            scroll.ChangeView(null, Math.Min(page * step, scroll.ScrollableHeight), null, true);
            await Task.Delay(400);
            await Capture(panel, Path.Combine(root, $"{state}-{page}.png"));
        }
    }
    private static async Task Capture(FrameworkElement visual, string path)
    {
        visual.UpdateLayout();
        var bitmap = new RenderTargetBitmap();
        await bitmap.RenderAsync(visual);
        if (bitmap.PixelWidth == 0 || bitmap.PixelHeight == 0) throw new InvalidDataException("Preview has no rendered pixels.");
        var folder = await StorageFolder.GetFolderFromPathAsync(Path.GetDirectoryName(path)!);
        var file = await folder.CreateFileAsync(Path.GetFileName(path), CreationCollisionOption.FailIfExists);
        using var stream = await file.OpenAsync(FileAccessMode.ReadWrite);
        var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
        encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, (uint)bitmap.PixelWidth, (uint)bitmap.PixelHeight, 96, 96, (await bitmap.GetPixelsAsync()).ToArray());
        await encoder.FlushAsync();
    }
}
