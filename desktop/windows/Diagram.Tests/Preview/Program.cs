using Microsoft.UI.Xaml;
using Microsoft.UI.Dispatching;
using AttackMap.NativeSpike;

internal static class Program
{
    [STAThread]static void Main(){WinRT.ComWrappersSupport.InitializeComWrappers();Application.Start(launch=>{SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));_=new PreviewApp();});}
}
public sealed class PreviewApp:Application
{
    private Window? window;
    public PreviewApp()
    {
        UnhandledException+=(_,error)=>File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"preview-error.txt"),error.Exception.ToString());
        Resources.MergedDictionaries.Add(new Microsoft.UI.Xaml.Controls.XamlControlsResources());
    }
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        string[] command=Environment.GetCommandLineArgs();var view=new DiagramView{RequestedTheme=command.Contains("--dark")?ElementTheme.Dark:ElementTheme.Light};
        window=new Window{Title="AttackMap WP010 standalone synthetic offline diagram preview",Content=view};window.AppWindow.Resize(new Windows.Graphics.SizeInt32(1280,900));
        string source=command.Contains("--empty")?"":command.Contains("--hostile")?"flowchart TD\nclick A href \"https://hostile.invalid\"":command.Contains("--large")?"flowchart TD\n"+string.Join("\n",Enumerable.Range(0,121).Select(i=>$"N{i}[\"node {i}\"]")):"# Synthetic service topology\n```mermaid\nflowchart LR\nS0[\"Public API\"]\nS1[\"Orders database\"]\nS2[\"Worker queue\"]\nS0 -- \"supplied database access\" --> S1\nS0 == \"supplied async dependency\" ==> S2\n```\n";
        view.ShowPreview(DiagramParser.Parse(source));window.Activate();
    }
}
