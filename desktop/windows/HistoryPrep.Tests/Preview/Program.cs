using Microsoft.UI.Xaml;using Microsoft.UI.Dispatching;using AttackMap.NativeSpike.HistoryPrep;
internal static class Program{[STAThread]static void Main(){WinRT.ComWrappersSupport.InitializeComWrappers();Application.Start(launch=>{SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));_=new PreviewApp();});}}
public sealed class PreviewApp:Application
{
    private Window? window;public PreviewApp(){Resources.MergedDictionaries.Add(new Microsoft.UI.Xaml.Controls.XamlControlsResources());}
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        string[] command=Environment.GetCommandLineArgs();var view=new HistoryComparisonView{RequestedTheme=command.Contains("--dark")?ElementTheme.Dark:ElementTheme.Light};window=new Window{Title="AttackMap WP013 bounded history preview",Content=view};window.AppWindow.Resize(command.Contains("--small")?new Windows.Graphics.SizeInt32(900,700):new Windows.Graphics.SizeInt32(1280,900));
        var model=new HistoryComparisonModel();model.SelectRepository(new("synthetic-repo","C:/synthetic/žluťoučký/sample","sample"),false);model.SetGenerations(Enumerable.Range(1,3).Select(i=>new RetainedGeneration(new("synthetic-repo",$"generation-{i}",new string((char)('a'+i),64),$"C:/synthetic/reports/g{i}/attackmap-report.json"),i==1,i==3,"completed",i==3?"failed":"passed")).ToArray());view.SetModel(model);window.Activate();
    }
}
