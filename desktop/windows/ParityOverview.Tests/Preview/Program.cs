using Microsoft.UI.Xaml;using Microsoft.UI.Dispatching;using AttackMap.NativeSpike;
internal static class Program{[STAThread]static void Main(){WinRT.ComWrappersSupport.InitializeComWrappers();Application.Start(launch=>{SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));_=new PreviewApp();});}}
public sealed class PreviewApp:Application
{
    private Window? window;public PreviewApp(){Resources.MergedDictionaries.Add(new Microsoft.UI.Xaml.Controls.XamlControlsResources());}
    protected override async void OnLaunched(LaunchActivatedEventArgs args){string[] command=Environment.GetCommandLineArgs();var view=new OverviewView{RequestedTheme=command.Contains("--dark")?ElementTheme.Dark:ElementTheme.Light};window=new Window{Title="AttackMap WP011 bounded overview preview",Content=view};window.AppWindow.Resize(command.Contains("--small")?new Windows.Graphics.SizeInt32(900,700):new Windows.Graphics.SizeInt32(1280,900));window.Activate();view.SetOverview(await ParityOverviewAdapter.Load(Path.Combine(AppContext.BaseDirectory,"fixture.json"),generation:"synthetic-preview-1"));}
}
