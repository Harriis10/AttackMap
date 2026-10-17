using Microsoft.UI.Xaml;
namespace AttackMap.NativeSpike;
public partial class App : Application
{
    private Window? window;
    public App()
    {
        UnhandledException += (_, args) =>
        {
            // Development-only diagnostics; no engine data or credentials exist here.
            try { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "spike-error.txt"), $"HRESULT: 0x{args.Exception.HResult:X8}\nMessage: {args.Message}\n{args.Exception}"); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        };
        InitializeComponent();
    }
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        window = new MainWindow();
        window.Activate();
    }
}
