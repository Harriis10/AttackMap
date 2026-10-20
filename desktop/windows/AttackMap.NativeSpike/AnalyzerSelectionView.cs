using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Automation;
namespace AttackMap.NativeSpike;

public sealed class AnalyzerSelectionView : Grid
{
    private readonly AnalyzerSelectionModel model;
    private readonly CheckBox automatic = new() { Content = "Automatic (engine defaults; detection still applies)" };
    private readonly TextBox search = new() { PlaceholderText = "Filter installed analyzers" };
    private readonly TextBlock notice = new() { TextWrapping = TextWrapping.Wrap };
    private readonly StackPanel rows = new() { Spacing = 10 };
    public event Action? SelectionChanged;
    public AnalyzerSelectionView(AnalyzerSelectionModel model)
    {
        this.model = model; RowSpacing = 10;
        RowDefinitions.Add(new() { Height = GridLength.Auto }); RowDefinitions.Add(new() { Height = GridLength.Auto }); RowDefinitions.Add(new() { Height = GridLength.Auto }); RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) });
        Children.Add(automatic); SetRow(search, 1); Children.Add(search); SetRow(notice, 2); Children.Add(notice);
        var scroll = new ScrollViewer { Content = rows, VerticalScrollBarVisibility = ScrollBarVisibility.Visible, Padding = new Thickness(0, 0, 16, 20) }; SetRow(scroll, 3); Children.Add(scroll);
        AutomationProperties.SetName(search, "Filter installed analyzers; selected missing analyzers remain visible");
        search.TextChanged += (_, _) => Refresh();
        automatic.Click += (_, _) => { model.SetAutomatic(automatic.IsChecked == true); Refresh(); SelectionChanged?.Invoke(); };
        Refresh();
    }
    public void Refresh()
    {
        automatic.IsChecked = model.Automatic;
        var items = model.Rows(search.Text);
        notice.Text = model.DiscoveryError ?? $"{items.Count} displayed inventory records. Inventory does not establish repository applicability. No automatic installation/download.";
        rows.Children.Clear();
        foreach (var item in items)
        {
            var check = new CheckBox { Content = new TextBlock { Text = item.DisplayName + " (" + item.Name + ")", TextWrapping = TextWrapping.Wrap }, IsThreeState = false, IsChecked = item.Selected, IsEnabled = !model.Automatic };
            AutomationProperties.SetName(check, item.DisplayName + "; " + item.Status);
            check.Click += (_, _) => { model.Select(item.Name, check.IsChecked == true); Refresh(); SelectionChanged?.Invoke(); };
            rows.Children.Add(check);
            rows.Children.Add(new TextBlock { Text = item.Status + (item.Error == null ? "" : ": " + item.Error), TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
        }
        if (items.Count == 0) rows.Children.Add(new TextBlock { Text = "No matching installed analyzer records. Clear the filter or refresh discovery.", TextWrapping = TextWrapping.Wrap });
    }
}


