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
    private readonly ComboBox mode = new() { Header = "AI mode (None sends no AI request)", ItemsSource = new[] { "none", "review", "hunt", "hunt_verify", "remediate", "triage" }, SelectedItem = "review" };
    private readonly TextBox jury = new() { Header = "Hunt+verify jury votes (1–7; blank uses 3)", Text = "" };
    private readonly ComboBox effort = new() { Header = "Requested effort", ItemsSource = new[] { "default", "low", "medium", "high", "xhigh", "max" }, SelectedIndex = 0 };
    private readonly ComboBox speed = new() { Header = "Speed (Fast may have premium provider pricing)", ItemsSource = new[] { "standard", "fast" }, SelectedIndex = 0 };
    private readonly ComboBox backend = new() { Header = "Backend", ItemsSource = new[] { "api", "cli" }, SelectedIndex = 0, IsEnabled = false };
    private readonly TextBlock compatibility = new() { TextWrapping = TextWrapping.Wrap };
    private EngineCapabilities? capabilities;
    private bool advancedPreference;
    private readonly TextBox calls = new() { Header = "Maximum provider calls (1-64)", Text = "8" };
    private readonly TextBox seconds = new() { Header = "Total AI time allowance in seconds (1-3600; explicit local OpenAI HTTP API up to 7200)", Text = "600" };
    private readonly TextBox outputTokens = new() { Header = "Output-token allowance only (1-256000)", Text = "32000" };
    private readonly TextBlock result = new() { TextWrapping = TextWrapping.Wrap };
    public event Action<ProviderAccessRequest>? SaveRequested;
    public event Action<ProviderAccessRequest>? TestConnectionRequested;
    public event Action? ConfigurationChanged;
    public ScrollViewer ScrollHost => (ScrollViewer)Content;
    public ProviderSettingsView()
    {
        var panel = new StackPanel { Spacing = 8 };
        panel.Children.Add(new TextBlock { Text = "AI is optional. Selected provider receives analysis context and potentially source excerpts. Local endpoints stay local; remote endpoints transmit data to that provider. Test connection sends a small request only when clicked. Restore performs no network request.", TextWrapping = TextWrapping.Wrap });
        foreach (var control in new FrameworkElement[] { enabled, mode, jury, effort, speed, backend, compatibility, provider, endpoint, model, credential, calls, seconds, outputTokens }) panel.Children.Add(control);
        panel.Children.Add(new TextBlock { Text = "API backend only. Output tokens do not bound input tokens, provider reasoning or billing. Missing usage remains unknown. Credentials are never part of configuration JSON.", TextWrapping = TextWrapping.Wrap });
        var buttons = new StackPanel { Spacing = 8 };
        var save = new Button { Content = "Save provider settings" };
        var test = new Button { Content = "Test connection (sends request)" };
        var reset = new Button { Content = "Reset AI preferences (no request)" };
        reset.Click += (_, _) => ResetPreferences();
        save.Click += (_,_) => Emit(false);
        test.Click += (_,_) => Emit(true);
        buttons.Children.Add(save); buttons.Children.Add(test); buttons.Children.Add(reset); panel.Children.Add(buttons); panel.Children.Add(result);
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
        MaxWidth = 760;
        HorizontalAlignment = HorizontalAlignment.Left;
        VerticalAlignment = VerticalAlignment.Top;
        enabled.Checked += (_, _) => Changed();
        enabled.Unchecked += (_, _) => Changed();
        foreach (var choice in new[] { provider, mode, effort, speed }) choice.SelectionChanged += (_, _) => Changed();
        foreach (var field in new[] { endpoint, model, calls, seconds, outputTokens, jury }) field.TextChanged += (_, _) => Changed();
        ApplyCapabilities(null);
    }
    public ProviderConfiguration ReadConfiguration()
    {
        if (!int.TryParse(calls.Text,out int maxCalls) || !int.TryParse(seconds.Text,out int timeout) || !int.TryParse(outputTokens.Text,out int tokens)) throw new InvalidDataException("AI allowances must be whole numbers.");
        var configuration = new ProviderConfiguration(enabled.IsChecked == true,provider.SelectedItem?.ToString() ?? "openai",Blank(endpoint.Text),Blank(model.Text),maxCalls,timeout,tokens);
        if (advancedPreference || capabilities?.AdvancedAiAvailable == true)
        {
            if (jury.Text.Length > 0 && !int.TryParse(jury.Text, out _)) throw new InvalidDataException("Jury votes must be a whole number from 1 to 7.");
            string selected = mode.SelectedItem?.ToString() ?? "review";
            configuration = configuration with { EnableAi = configuration.EnableAi && selected != "none", Mode = selected,
                JuryVotes = jury.Text.Length == 0 ? null : int.Parse(jury.Text), Effort = effort.SelectedItem?.ToString() is null or "default" ? null : effort.SelectedItem.ToString(),
                Speed = speed.SelectedItem?.ToString() ?? "standard", Backend = backend.SelectedItem?.ToString() ?? "api" };
        }
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
        advancedPreference = configuration.RequiresSchema13;
        mode.SelectedItem = configuration.Mode ?? "review"; jury.Text = configuration.JuryVotes?.ToString() ?? "";
        effort.SelectedItem = configuration.Effort ?? "default"; speed.SelectedItem = configuration.Speed ?? "standard"; backend.SelectedItem = configuration.Backend ?? "api";
        Changed();
    }
    public void ApplyCapabilities(EngineCapabilities? selected)
    {
        capabilities = selected;
        mode.IsEnabled = effort.IsEnabled = speed.IsEnabled = selected?.AdvancedAiAvailable == true;
        Changed();
    }
    public ProviderConfiguration ReadRequestConfiguration()
    {
        var configuration = ReadConfiguration();
        var support = capabilities?.AiConfiguration(configuration) ?? new CapabilityAvailability(false, "Check selected engine capabilities before enabling AI.");
        if (!support.Enabled) throw new InvalidDataException(support.Reason);
        return configuration.ForRequest();
    }
    private void Changed()
    {
        jury.IsEnabled = capabilities?.AdvancedAiAvailable == true && mode.SelectedItem?.ToString() == "hunt_verify";
        try
        {
            var configuration = ReadConfiguration();
            compatibility.Text = (capabilities?.AiConfiguration(configuration).Reason ?? "Check engine compatibility to enable advanced modes. Saved preferences remain available.") +
                " Requested effort: " + (configuration.Effort ?? "default") + "; mapped: " + (capabilities?.MappedEffort(configuration) ?? "unknown") + ". CLI disabled: strict output cap unavailable.";
        }
        catch (InvalidDataException) { compatibility.Text = "Correct AI preferences before saving or requesting a scan; no request has been sent."; }
        ConfigurationChanged?.Invoke();
    }
    public void ShowResult(string message) => result.Text = message;
    public void ResetPreferences() => ApplyConfiguration(new ProviderConfiguration());
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
