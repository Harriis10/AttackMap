using Microsoft.UI.Xaml;
using Microsoft.UI.Dispatching;
using AttackMap.NativeSpike;
internal static class Program
{
    [STAThread]
    static void Main()
    {
        WinRT.ComWrappersSupport.InitializeComWrappers();
        Application.Start(launch=>
        {
            SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));
            _=new PreviewApp();
        });
    }
}
public sealed class PreviewApp:Application
{
    private Window? window;
    public PreviewApp() { Resources.MergedDictionaries.Add(new Microsoft.UI.Xaml.Controls.XamlControlsResources()); }
    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        var view=new RiskPathsView();
        string[] command=Environment.GetCommandLineArgs();
        view.RequestedTheme=command.Contains("--dark")?ElementTheme.Dark:ElementTheme.Light;
        window=new Window {Title="AttackMap WP008 synthetic risk/path preview",Content=view};
        window.AppWindow.Resize(command.Contains("--small")?new Windows.Graphics.SizeInt32(900,700):new Windows.Graphics.SizeInt32(1280,900));
        window.Activate();
        var report=await ReportSectionAdapter.Load(Path.Combine(AppContext.BaseDirectory,"fixture.json"),generationId:"synthetic-preview-generation-1");
        view.SetReport(report);
    }
}
