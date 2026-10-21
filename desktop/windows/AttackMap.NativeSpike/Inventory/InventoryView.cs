using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
namespace AttackMap.NativeSpike;

public sealed partial class InventoryView:UserControl
{
    private readonly ComboBox group=new(){Header="Inventory section",DisplayMemberPath="Name"};
    private readonly TextBox query=new(){Header="Name filter",PlaceholderText="All names"};
    private readonly TextBox severity=new(){Header="Severity filter",PlaceholderText="All severities"};
    private readonly TextBox confidence=new(){Header="Confidence filter",PlaceholderText="All confidence values"};
    private readonly TextBox evidence=new(){Header="Evidence basis filter",PlaceholderText="All supplied evidence classes"};
    private readonly ListView rows=new(){MinHeight=160,MaxHeight=300,SelectionMode=ListViewSelectionMode.Single};
    private readonly TextBlock heading=new(){Text="Evidence inventory",FontSize=24};
    private readonly TextBlock summary=new(){Text="No canonical report selected; coverage unknown.",TextWrapping=TextWrapping.Wrap};
    private readonly Grid filters=new(){ColumnSpacing=12,RowSpacing=8};
    private readonly Grid results=new(){ColumnSpacing=12,RowSpacing=12};
    private readonly Border resultCard;
    private readonly Border detailCard;
    private int filterColumns,resultColumns;
    private readonly TextBlock notice=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};
    private readonly TextBlock detail=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};
    private readonly Button source=new(){Content="Inspect supplied source",IsEnabled=false};
    private InventoryViewModel? model;
    public event Action<InventorySourceLink>? SourceRequested;
    public bool ShowHeading {get=>heading.Visibility==Visibility.Visible;set=>heading.Visibility=value ? Visibility.Visible : Visibility.Collapsed;}
    public InventoryView()
    {
        var panel=new StackPanel{Spacing=12,Padding=new Thickness(16)};
        panel.Children.Add(heading);group.MinWidth=240;group.MaxWidth=480;group.HorizontalAlignment=HorizontalAlignment.Left;panel.Children.Add(group);
        foreach(var control in new FrameworkElement[]{query,severity,confidence,evidence}){control.HorizontalAlignment=HorizontalAlignment.Stretch;filters.Children.Add(control);}panel.Children.Add(filters);
        panel.Children.Add(new Expander{Header=summary,Content=notice,HorizontalAlignment=HorizontalAlignment.Stretch,HorizontalContentAlignment=HorizontalAlignment.Stretch});
        rows.ItemTemplate=(DataTemplate)XamlReader.Load("<DataTemplate xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'><TextBlock Text='{Binding Label}' TextWrapping='Wrap' MaxLines='3' TextTrimming='CharacterEllipsis' Margin='0,4'/></DataTemplate>");
        var selectedPanel=new StackPanel{Spacing=12};selectedPanel.Children.Add(detail);selectedPanel.Children.Add(source);
        resultCard=Card(rows);detailCard=Card(new ScrollViewer{Content=selectedPanel,MaxHeight=300,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled});
        results.Children.Add(resultCard);results.Children.Add(detailCard);panel.Children.Add(results);
        Content=new ScrollViewer{Content=panel,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled};AutomationProperties.SetName(rows,"Supplied inventory records in core order");
        panel.SizeChanged+=(_,_)=>ArrangeControls(panel.ActualWidth-panel.Padding.Left-panel.Padding.Right);ArrangeControls(0);
        group.SelectionChanged+=(_,_)=>{if(model!=null&&group.SelectedItem is InventoryGroup selected){model.Choose(selected.Name);Refresh();}};
        query.TextChanged+=(_,_)=>Refresh();severity.TextChanged+=(_,_)=>Refresh();confidence.TextChanged+=(_,_)=>Refresh();evidence.TextChanged+=(_,_)=>Refresh();
        rows.SelectionChanged+=(_,_)=>Select(rows.SelectedItem as InventoryItem);
        source.Click+=(_,_)=>{if(model?.Selected?.File is string file)SourceRequested?.Invoke(new(file,model.Selected.Line));};
    }
    public void SetReport(ReportSections report){model=new(report);group.ItemsSource=model.Groups;group.SelectedIndex=0;Refresh();}
    private static Border Card(UIElement child)
    {
        var card=new Border{Child=child,Padding=new Thickness(12),CornerRadius=new CornerRadius(8),BorderThickness=new Thickness(1)};
        if(Application.Current.Resources.TryGetValue("AttackCardStyle",out var style)&&style is Style cardStyle)card.Style=cardStyle;
        else{card.Background=(Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"];card.BorderBrush=(Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"];}
        return card;
    }
    private void ArrangeControls(double width)
    {
        int columns=width>=600 ? 2 : 1;
        if(columns!=filterColumns)
        {
            filterColumns=columns;filters.ColumnDefinitions.Clear();filters.RowDefinitions.Clear();
            for(int i=0;i<columns;i++)filters.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(1,GridUnitType.Star)});
            for(int i=0;i<(4+columns-1)/columns;i++)filters.RowDefinitions.Add(new RowDefinition{Height=GridLength.Auto});
            for(int i=0;i<filters.Children.Count;i++){Grid.SetRow((FrameworkElement)filters.Children[i],i/columns);Grid.SetColumn((FrameworkElement)filters.Children[i],i%columns);}
        }
        int resultCount=width>=700 ? 2 : 1;
        if(resultCount==resultColumns)return;resultColumns=resultCount;results.ColumnDefinitions.Clear();results.RowDefinitions.Clear();
        for(int i=0;i<resultCount;i++)results.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(1,GridUnitType.Star)});
        for(int i=0;i<(resultCount==2 ? 1 : 2);i++)results.RowDefinitions.Add(new RowDefinition{Height=GridLength.Auto});
        Grid.SetRow(resultCard,0);Grid.SetColumn(resultCard,0);Grid.SetRow(detailCard,resultCount==2 ? 0 : 1);Grid.SetColumn(detailCard,resultCount==2 ? 1 : 0);
    }
    public bool SelectIdentity(string identity)
    {
        var matches=model?.Groups.SelectMany(section=>section.Items).Where(row=>row.Id==identity).ToArray();
        if(matches?.Length!=1)return false;
        query.Text=severity.Text=confidence.Text=evidence.Text="";
        group.SelectedItem=model!.Groups.Single(section=>section.Name==matches[0].Group);Refresh();
        rows.SelectedItem=matches[0];rows.ScrollIntoView(matches[0]);return true;
    }
    private void Refresh()
    {
        if(model==null)return;model.Filter(query.Text,severity.Text,confidence.Text,evidence.Text);var selected=model.Selected;
        summary.Text=$"Coverage and limitations · {model.Visible.Count} displayed / {model.Current.Items.Count} projected; source total: {model.Current.SuppliedCount?.ToString()??"unknown"}; section: {model.Current.Availability}."+
            (model.Visible.Count==0&&model.Current.Items.Count>0 ? " No matching rows; clear filters." : "");
        notice.Text=model.Notice;rows.ItemsSource=model.Visible;rows.SelectedItem=selected;Select(selected);
    }
    private void Select(InventoryItem? item)
    {
        model?.Select(item);detail.Text=item?.Detail??"Select a supplied inventory record for details.";
        source.IsEnabled=item?.File!=null&&SourceRequested!=null;
    }
}
