using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Automation;
namespace AttackMap.NativeSpike;

public sealed class ScanProgressView : StackPanel
{
    private readonly TextBlock heading = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private readonly ProgressBar bar = new() { Minimum = 0, Maximum = 100, IsIndeterminate = true };
    private readonly TextBlock units = new() { TextWrapping = TextWrapping.Wrap }, eta = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock activityText = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private readonly Expander activity = new() { Header = "Current run activity", HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch };
    public ScanProgressView()
    {
        Spacing = 8; Children.Add(heading); Children.Add(bar); Children.Add(units); Children.Add(eta);
        activity.Content = new ScrollViewer { Content = activityText, MaxHeight = 192, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Children.Add(activity);
        AutomationProperties.SetName(activity, "Current run stage and analyzer activity in received order");
        AutomationProperties.SetName(bar, "Current scan stage progress");
        AutomationProperties.SetLiveSetting(heading, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);
    }
    public void SetModel(ScanProgressModel model)
    {
        heading.Text = $"Scan {model.State} · Stage: {(string.IsNullOrEmpty(model.Stage) ? "not supplied" : model.Stage)}";
        bar.IsIndeterminate = model.Indeterminate; bar.Value = model.Percent ?? 0;
        units.Text = model.Total > 0 ? $"{model.Completed} / {model.Total} units · {model.Percent:0.#}% of current stage" : "Stage total unknown; no percentage inferred.";
        eta.Text = model.EtaText;
        activity.Header = $"Current run activity · {model.Activity.Count + model.EarlierActivityCount} updates";
        activityText.Text = (model.EarlierActivityCount > 0 ? $"{model.EarlierActivityCount} earlier updates omitted from this live view.\n" : "") +
            (model.Activity.Count == 0 ? "No activity received for the selected run." : string.Join("\n", model.Activity.Select(item =>
                $"+{item.Elapsed.TotalSeconds:0.0}s · {item.State} · {(string.IsNullOrEmpty(item.Stage) ? "waiting for stage" : item.Stage)}")));
    }
}
