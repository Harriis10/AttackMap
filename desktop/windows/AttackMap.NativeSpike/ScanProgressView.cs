using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Automation;
namespace AttackMap.NativeSpike;

public sealed class ScanProgressView : StackPanel
{
    private readonly TextBlock heading = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private readonly ProgressBar bar = new() { Minimum = 0, Maximum = 100, IsIndeterminate = true };
    private readonly TextBlock units = new() { TextWrapping = TextWrapping.Wrap }, eta = new() { TextWrapping = TextWrapping.Wrap };
    public ScanProgressView()
    {
        Spacing = 8; Children.Add(heading); Children.Add(bar); Children.Add(units); Children.Add(eta);
        AutomationProperties.SetName(bar, "Current scan stage progress");
        AutomationProperties.SetLiveSetting(heading, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);
    }
    public void SetModel(ScanProgressModel model)
    {
        heading.Text = $"Scan {model.State} · Stage: {(string.IsNullOrEmpty(model.Stage) ? "not supplied" : model.Stage)}";
        bar.IsIndeterminate = model.Indeterminate; bar.Value = model.Percent ?? 0;
        units.Text = model.Total > 0 ? $"{model.Completed} / {model.Total} units · {model.Percent:0.#}% of current stage" : "Stage total unknown; no percentage inferred.";
        eta.Text = model.EtaText;
    }
}
