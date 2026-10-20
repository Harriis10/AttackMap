using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
namespace AttackMap.NativeSpike;

public sealed partial class RiskPathsView : UserControl
{
    private readonly ListView rows = new() { MaxHeight=340, SelectionMode=ListViewSelectionMode.Single };
    private readonly TextBlock notice = new() { TextWrapping=TextWrapping.Wrap, IsTextSelectionEnabled=true };
    private readonly TextBlock detail = new() { TextWrapping=TextWrapping.Wrap, IsTextSelectionEnabled=true };
    private readonly StackPanel links = new() { Spacing=6 };
    private readonly TextBox route = new() { Header="Route filter",PlaceholderText="All routes" };
    private readonly TextBox sink = new() { Header="Sink filter",PlaceholderText="All sinks" };
    private readonly TextBox confidence = new() { Header="Confidence filter",PlaceholderText="All confidence values" };
    private readonly ComboBox classification = new() { Header="Supplied classification",ItemsSource=new[]{"All","observed","candidate","speculative","unknown"},SelectedIndex=0 };
    private RiskPathsViewModel? model;
    public event Action<RiskSourceLink>? SourceRequested;
    public event Action<string>? FindingRequested;
    public RiskPathsView()
    {
        AutomationProperties.SetName(rows,"Core ranked risk and attack path results");
        rows.DisplayMemberPath="Label";
        var panel=new StackPanel {Spacing=12,Padding=new Thickness(16)};
        panel.Children.Add(new TextBlock {Text="Risk and attack paths",FontSize=24});
        foreach(var input in new FrameworkElement[]{route,sink,confidence,classification}) panel.Children.Add(input);
        panel.Children.Add(notice);panel.Children.Add(rows);panel.Children.Add(detail);panel.Children.Add(links);
        Content=new ScrollViewer {Content=panel};
        route.TextChanged+=(_,_)=>Refresh();sink.TextChanged+=(_,_)=>Refresh();confidence.TextChanged+=(_,_)=>Refresh();classification.SelectionChanged+=(_,_)=>Refresh();
        rows.SelectionChanged+=(_,_)=>Select(rows.SelectedItem as RiskPathItem);
    }
    public void SetReport(ReportSections report) {model=new(report);Refresh();}
    private void Refresh()
    {
        if(model==null)return;
        model.Filter(route.Text,sink.Text,confidence.Text,classification.SelectedIndex<=0 ? "" : classification.SelectedItem?.ToString()??"");
        var selected=model.Selected;
        notice.Text=model.Notice;rows.ItemsSource=model.Visible;rows.SelectedItem=selected;Select(selected);
    }
    private void Select(RiskPathItem? item)
    {
        model?.Select(item);detail.Text=item?.Detail??"Select a result to inspect supplied evidence and score factors.";links.Children.Clear();
        if(item==null)return;
        foreach(var source in item.Sources)
        {
            var button=new Button {Content=$"Inspect source: {source.File}:{source.Line?.ToString()??"unknown"}",IsEnabled=SourceRequested!=null};
            button.Click+=(_,_)=>SourceRequested?.Invoke(source);links.Children.Add(button);
        }
        foreach(string findingId in item.FindingIds)
        {
            var button=new Button {Content=$"Open finding: {findingId}",IsEnabled=FindingRequested!=null};
            button.Click+=(_,_)=>FindingRequested?.Invoke(findingId);links.Children.Add(button);
        }
    }
}
