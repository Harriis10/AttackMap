using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage;
using Windows.Graphics.Imaging;
using System.Runtime.InteropServices.WindowsRuntime;
using AttackMap.NativeSpike;
namespace AttackMap.WP006Preview;
public partial class App : Application
{
    private Window? window;
    public App() { InitializeComponent(); }
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        string root = Path.GetFullPath(Environment.GetCommandLineArgs()[1]); Directory.CreateDirectory(root);
        window = new Window { Title = "AttackMap · WP006 synthetic progress and analyzer selection" }; window.AppWindow.Resize(new Windows.Graphics.SizeInt32(1120, 900));
        var initial = Build(0); window.Content = initial;
        initial.Loaded += async (_, _) =>
        {
            try
            {
                foreach (int state in Environment.GetCommandLineArgs().Contains("--bounded-only") ? new[] { 0 } : new[] { 0, 1, 2 })
                {
                    var view = Build(state); window.Content = view; await Task.Delay(4500); view.UpdateLayout();
                    var bitmap = new RenderTargetBitmap(); await bitmap.RenderAsync(view);
                    var folder = await StorageFolder.GetFolderFromPathAsync(root); var file = await folder.CreateFileAsync($"state-{state}.png", CreationCollisionOption.ReplaceExisting);
                    using var stream = await file.OpenAsync(FileAccessMode.ReadWrite); var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
                    encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, (uint)bitmap.PixelWidth, (uint)bitmap.PixelHeight, 96, 96, (await bitmap.GetPixelsAsync()).ToArray()); await encoder.FlushAsync();
                }
                File.WriteAllText(Path.Combine(root, "result.json"), "{\"captured\":3,\"synthetic\":true,\"engine_processes\":0,\"provider_calls\":0,\"manual_acceptance\":false}");
            }
            catch (Exception error) { File.WriteAllText(Path.Combine(root, "error.txt"), error.ToString()); }
            window.Close();
        };
        window.Activate();
    }
    private static Grid Build(int state)
    {
        var root = new Grid { RequestedTheme = ElementTheme.Light, Background = new SolidColorBrush(Microsoft.UI.Colors.White), Padding = new Thickness(28), RowSpacing = 20 };
        root.RowDefinitions.Add(new() { Height = GridLength.Auto }); root.RowDefinitions.Add(new() { Height = GridLength.Auto }); root.RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) }); root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        var title = new StackPanel { Spacing = 8 }; title.Children.Add(new TextBlock { Text = "Scan progress & analyzers", FontSize = 28 }); title.Children.Add(new TextBlock { Text = "Synthetic native preview · no scan, engine, provider or plugin installation", TextWrapping = TextWrapping.Wrap }); root.Children.Add(title);
        var model = new ScanProgressModel(); model.Select("synthetic", "C:/synthetic/repository", 1);
        for (int i = 0; i < 3; i++) model.Accept(new("synthetic", "C:/synthetic/repository", 1, i, "running", "python · structured signals", i + 1, 10, false), TimeSpan.FromSeconds(i));
        if (state == 1) model.Accept(new("synthetic", "C:/synthetic/repository", 1, 3, "running", "Unknown stage supplied by engine · no bounded total", null, null, false), TimeSpan.FromSeconds(3));
        if (state == 2) model.RequestCancel();
        var progress = new ScanProgressView(); progress.SetModel(model); Grid.SetRow(progress, 1); root.Children.Add(progress);
        var selection = new AnalyzerSelectionModel(); selection.Restore(state == 2 ? "python,missing-custom-analyzer" : "python,beta");
        selection.LoadDiscovery("""{"schema":1,"modules":[{"name":"python","display_name":"Python service analyzer","experimental":false,"enabled_by_default":true},{"name":"beta","display_name":"Experimental protocol overlay","experimental":true,"enabled_by_default":false},{"name":"config","display_name":"Configuration analyzer","experimental":false,"enabled_by_default":true},{"name":"custom","display_name":"Specialty analyzer","experimental":false,"enabled_by_default":false}]}""");
        selection.SetAnalyzerErrors(new Dictionary<string,string>{{"custom","Synthetic analyzer error; report coverage may be partial."}});
        var picker = new AnalyzerSelectionView(selection); Grid.SetRow(picker, 2); root.Children.Add(picker);
        var footer = new TextBlock { Text = "Stage done is not run completion. ETA is an estimate for this stage only. Missing saved modules remain selected and block explicit scans until resolved. Keyboard/Narrator/real-scan acceptance is pending.", TextWrapping = TextWrapping.Wrap }; Grid.SetRow(footer, 3); root.Children.Add(footer);
        Paint(root); return root;
    }
    private static void Paint(DependencyObject root)
    {
        if (root is TextBlock text) text.Foreground = new SolidColorBrush(Microsoft.UI.Colors.Black);
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++) Paint(VisualTreeHelper.GetChild(root, i));
    }
}

