using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
namespace AttackMap.NativeSpike;

public sealed partial class RiskPathsView : UserControl
{
    private readonly ListView rows = new() { MinHeight=160, MaxHeight=300, SelectionMode=ListViewSelectionMode.Single };
    private readonly TextBlock heading = new() { Text="Risk and attack paths", FontSize=24 };
    private readonly TextBlock summary = new() { Text="No canonical report selected; coverage unknown.", TextWrapping=TextWrapping.Wrap };
    private readonly Grid filters = new() { ColumnSpacing=12, RowSpacing=8 };
    private readonly Grid results = new() { ColumnSpacing=12, RowSpacing=12 };
    private readonly Border resultCard;
    private readonly Border detailCard;
    private int filterColumns, resultColumns;
    private ReportSections? reportSections;
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
    public bool ShowHeading { get => heading.Visibility == Visibility.Visible; set => heading.Visibility=value ? Visibility.Visible : Visibility.Collapsed; }
    public RiskPathsView()
    {
        AutomationProperties.SetName(rows,"Core ranked risk and attack path results");
        rows.ItemTemplate=(DataTemplate)XamlReader.Load("<DataTemplate xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'><TextBlock Text='{Binding Label}' TextWrapping='Wrap' MaxLines='3' TextTrimming='CharacterEllipsis' Margin='0,4'/></DataTemplate>");
        var panel=new StackPanel {Spacing=12,Padding=new Thickness(16)};
        panel.Children.Add(heading);
        foreach(var input in new FrameworkElement[]{route,sink,confidence,classification}) { input.HorizontalAlignment=HorizontalAlignment.Stretch; filters.Children.Add(input); }
        panel.Children.Add(filters);
        panel.Children.Add(new Expander {Header=summary,Content=notice,HorizontalAlignment=HorizontalAlignment.Stretch,HorizontalContentAlignment=HorizontalAlignment.Stretch});
        var selectedPanel=new StackPanel {Spacing=12};selectedPanel.Children.Add(detail);selectedPanel.Children.Add(links);
        resultCard=Card(rows);detailCard=Card(new ScrollViewer {Content=selectedPanel,MaxHeight=300,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled});
        results.Children.Add(resultCard);results.Children.Add(detailCard);panel.Children.Add(results);
        Content=new ScrollViewer {Content=panel,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled};
        panel.SizeChanged+=(_,_)=>ArrangeControls(panel.ActualWidth-panel.Padding.Left-panel.Padding.Right);
        ArrangeControls(0);
        route.TextChanged+=(_,_)=>Refresh();sink.TextChanged+=(_,_)=>Refresh();confidence.TextChanged+=(_,_)=>Refresh();classification.SelectionChanged+=(_,_)=>Refresh();
        rows.SelectionChanged+=(_,_)=>Select(rows.SelectedItem as RiskPathItem);
    }
    public void SetReport(ReportSections report) {reportSections=report;model=new(report);Refresh();}
    private static Border Card(UIElement child)
    {
        var card=new Border {Child=child,Padding=new Thickness(12),CornerRadius=new CornerRadius(8),BorderThickness=new Thickness(1)};
        if(Application.Current.Resources.TryGetValue("AttackCardStyle",out var style)&&style is Style cardStyle)card.Style=cardStyle;
        else {card.Background=(Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"];card.BorderBrush=(Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"];}
        return card;
    }
    private void ArrangeControls(double width)
    {
        int columns=width>=600 ? 2 : 1;
        if(columns!=filterColumns)
        {
            filterColumns=columns;filters.ColumnDefinitions.Clear();filters.RowDefinitions.Clear();
            for(int i=0;i<columns;i++)filters.ColumnDefinitions.Add(new ColumnDefinition {Width=new GridLength(1,GridUnitType.Star)});
            for(int i=0;i<(4+columns-1)/columns;i++)filters.RowDefinitions.Add(new RowDefinition {Height=GridLength.Auto});
            for(int i=0;i<filters.Children.Count;i++){Grid.SetRow((FrameworkElement)filters.Children[i],i/columns);Grid.SetColumn((FrameworkElement)filters.Children[i],i%columns);}
        }
        int resultCount=width>=700 ? 2 : 1;
        if(resultCount==resultColumns)return;resultColumns=resultCount;results.ColumnDefinitions.Clear();results.RowDefinitions.Clear();
        for(int i=0;i<resultCount;i++)results.ColumnDefinitions.Add(new ColumnDefinition {Width=new GridLength(1,GridUnitType.Star)});
        for(int i=0;i<(resultCount==2 ? 1 : 2);i++)results.RowDefinitions.Add(new RowDefinition {Height=GridLength.Auto});
        Grid.SetRow(resultCard,0);Grid.SetColumn(resultCard,0);Grid.SetRow(detailCard,resultCount==2 ? 0 : 1);Grid.SetColumn(detailCard,resultCount==2 ? 1 : 0);
    }
    public bool SelectPathIdentity(string identity)
    {
        var matches=model?.All.Where(row=>row.Kind=="Attack path"&&row.Id==identity).ToArray();
        if(matches?.Length!=1)return false;
        route.Text=sink.Text=confidence.Text="";classification.SelectedIndex=0;Refresh();
        rows.SelectedItem=matches[0];rows.ScrollIntoView(matches[0]);return true;
    }
    private void Refresh()
    {
        if(model==null)return;
        model.Filter(route.Text,sink.Text,confidence.Text,classification.SelectedIndex<=0 ? "" : classification.SelectedItem?.ToString()??"");
        var selected=model.Selected;
        summary.Text=$"Coverage and limitations · {model.Visible.Count} displayed / {model.All.Count} projected; scores: {reportSections?.Exploitability.Availability}; paths: {reportSections?.Paths.Availability}."+
            (model.Visible.Count==0&&model.All.Count>0 ? " No matching rows; clear filters." : "");
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
