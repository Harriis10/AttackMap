using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
namespace AttackMap.NativeSpike;

public sealed class ProviderSettingsView : UserControl
{
    private readonly CheckBox enabled = new() { Content = "Enable AI review for scans (off by default)" };
    private readonly ComboBox provider = new() { Header = "Provider", ItemsSource = new[] { "openai", "claude" }, SelectedIndex = 0 };
    private readonly TextBox endpoint = new() { Header = "Endpoint (blank uses provider default)", Text = "http://127.0.0.1:1234/v1" };
    private readonly TextBox model = new() { Header = "Model (blank uses provider default)", Text = "cyberstag-security-26b-a4b-v1" };
    private readonly PasswordBox credential = new() { Header = "API credential (runtime only; Save uses protected storage)" };
    private readonly TextBox calls = new() { Header = "Maximum provider calls (1-64)", Text = "8" };
    private readonly TextBox seconds = new() { Header = "AI time allowance in seconds (1-3600)", Text = "600" };
    private readonly TextBox outputTokens = new() { Header = "Output-token allowance only (1-256000)", Text = "32000" };
    private readonly TextBlock result = new() { TextWrapping = TextWrapping.Wrap };
    public event Action<ProviderAccessRequest>? SaveRequested;
    public event Action<ProviderAccessRequest>? TestConnectionRequested;
    public event Action? ConfigurationChanged;
    public ProviderSettingsView()
    {
        var panel = new StackPanel { Spacing = 8 };
        panel.Children.Add(new TextBlock { Text = "AI is optional. Selected provider receives analysis context and potentially source excerpts. Local endpoints stay local; remote endpoints transmit data to that provider. Test connection sends a small request only when clicked. Restore performs no network request.", TextWrapping = TextWrapping.Wrap });
        foreach (var control in new FrameworkElement[] { enabled, provider, endpoint, model, credential, calls, seconds, outputTokens }) panel.Children.Add(control);
        panel.Children.Add(new TextBlock { Text = "API backend only. Output tokens do not bound input tokens, provider reasoning or billing. Missing usage remains unknown. Credentials are never part of configuration JSON.", TextWrapping = TextWrapping.Wrap });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        var save = new Button { Content = "Save provider settings" };
        var test = new Button { Content = "Test connection (sends request)" };
        save.Click += (_,_) => Emit(false);
        test.Click += (_,_) => Emit(true);
        buttons.Children.Add(save); buttons.Children.Add(test); panel.Children.Add(buttons); panel.Children.Add(result);
        Content = panel;
        MaxWidth = 760;
        HorizontalAlignment = HorizontalAlignment.Left;
        VerticalAlignment = VerticalAlignment.Top;
        enabled.Checked += (_, _) => ConfigurationChanged?.Invoke();
        enabled.Unchecked += (_, _) => ConfigurationChanged?.Invoke();
        provider.SelectionChanged += (_, _) => ConfigurationChanged?.Invoke();
        foreach (var field in new[] { endpoint, model, calls, seconds, outputTokens }) field.TextChanged += (_, _) => ConfigurationChanged?.Invoke();
    }
    public ProviderConfiguration ReadConfiguration()
    {
        if (!int.TryParse(calls.Text,out int maxCalls) || !int.TryParse(seconds.Text,out int timeout) || !int.TryParse(outputTokens.Text,out int tokens)) throw new InvalidDataException("AI allowances must be whole numbers.");
        var configuration = new ProviderConfiguration(enabled.IsChecked == true,provider.SelectedItem?.ToString() ?? "openai",Blank(endpoint.Text),Blank(model.Text),maxCalls,timeout,tokens);
        configuration.Validate();
        return configuration;
    }
    public void ApplyConfiguration(ProviderConfiguration configuration)
    {
        configuration.Validate();
        enabled.IsChecked = configuration.EnableAi; provider.SelectedItem = configuration.Provider;
        endpoint.Text = configuration.Endpoint ?? ""; model.Text = configuration.Model ?? "";
        calls.Text = configuration.MaxCalls.ToString(); seconds.Text = configuration.TimeoutSeconds.ToString(); outputTokens.Text = configuration.OutputTokenLimit.ToString();
        credential.Password = "";
    }
    public void ShowResult(string message) => result.Text = message;
    private void Emit(bool test)
    {
        try
        {
            var request = new ProviderAccessRequest(ReadConfiguration(),credential.Password);
            credential.Password = "";
            var handler = test ? TestConnectionRequested : SaveRequested;
            if (handler == null) { ShowResult("Provider action backend unavailable. Configuration not saved and no request sent."); return; }
            handler(request);
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException) { credential.Password = ""; ShowResult(error.Message); }
    }
    private static string? Blank(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
