using AttackMap.NativeSpike;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

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
        var status = new TextBlock { Text = "Standalone native AI settings preview. No engine or provider is connected.", TextWrapping = TextWrapping.Wrap };
        view.SaveRequested += _ => status.Text = "Preview intercepted Save. No credential or setting written; no request sent.";
        view.TestConnectionRequested += _ => status.Text = "Preview intercepted Test. No provider request sent.";
        var panel = new Grid { Padding = new Thickness(20), RowDefinitions = { new RowDefinition { Height = GridLength.Auto }, new RowDefinition() } };
        panel.Children.Add(status); Grid.SetRow(view, 1); panel.Children.Add(view);
        window = new Window { Title = "AttackMap — WP015 AI preferences preview", Content = panel };
        window.AppWindow.Resize(new Windows.Graphics.SizeInt32(650, 760));
        string? fixture = Environment.GetCommandLineArgs().Skip(1).FirstOrDefault();
        if (fixture != null) view.ApplyCapabilities(EngineCapabilities.Parse(File.ReadAllText(Path.GetFullPath(fixture))));
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
}
