using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
namespace AttackMap.NativeSpike;

public sealed partial class InventoryView:UserControl
{
    private readonly ComboBox group=new(){Header="Inventory section",DisplayMemberPath="Name"};
    private readonly TextBox query=new(){Header="Name filter",PlaceholderText="All names"};
    private readonly TextBox severity=new(){Header="Severity filter",PlaceholderText="All severities"};
    private readonly TextBox confidence=new(){Header="Confidence filter",PlaceholderText="All confidence values"};
    private readonly TextBox evidence=new(){Header="Evidence basis filter",PlaceholderText="All supplied evidence classes"};
    private readonly ListView rows=new(){MaxHeight=340,DisplayMemberPath="Label",SelectionMode=ListViewSelectionMode.Single};
    private readonly TextBlock notice=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};
    private readonly TextBlock detail=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};
    private readonly Button source=new(){Content="Inspect supplied source",IsEnabled=false};
    private InventoryViewModel? model;
    public event Action<InventorySourceLink>? SourceRequested;
    public InventoryView()
    {
        var panel=new StackPanel{Spacing=12,Padding=new Thickness(16)};
        panel.Children.Add(new TextBlock{Text="Evidence inventory",FontSize=24});
        foreach(var control in new FrameworkElement[]{group,query,severity,confidence,evidence,notice,rows,detail,source})panel.Children.Add(control);
        Content=new ScrollViewer{Content=panel};AutomationProperties.SetName(rows,"Supplied inventory records in core order");
        group.SelectionChanged+=(_,_)=>{if(model!=null&&group.SelectedItem is InventoryGroup selected){model.Choose(selected.Name);Refresh();}};
        query.TextChanged+=(_,_)=>Refresh();severity.TextChanged+=(_,_)=>Refresh();confidence.TextChanged+=(_,_)=>Refresh();evidence.TextChanged+=(_,_)=>Refresh();
        rows.SelectionChanged+=(_,_)=>Select(rows.SelectedItem as InventoryItem);
        source.Click+=(_,_)=>{if(model?.Selected?.File is string file)SourceRequested?.Invoke(new(file,model.Selected.Line));};
    }
    public void SetReport(ReportSections report){model=new(report);group.ItemsSource=model.Groups;group.SelectedIndex=0;Refresh();}
    private void Refresh()
    {
        if(model==null)return;model.Filter(query.Text,severity.Text,confidence.Text,evidence.Text);var selected=model.Selected;
        notice.Text=model.Notice;rows.ItemsSource=model.Visible;rows.SelectedItem=selected;Select(selected);
    }
    private void Select(InventoryItem? item)
    {
        model?.Select(item);detail.Text=item?.Detail??"Select a supplied inventory record for details.";
        source.IsEnabled=item?.File!=null&&SourceRequested!=null;
    }
}
