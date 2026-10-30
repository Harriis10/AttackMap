using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.ApplicationModel.DataTransfer;

namespace AttackMap.NativeSpike;

/// <summary>Native inert diagram surface. No browser, HTML, JavaScript, URI navigation or network client.</summary>
public sealed partial class DiagramView:UserControl
{
    private readonly ComboBox artifact=new(){Header="Core diagram",ItemsSource=DiagramSelectionReader.ArtifactNames,SelectedIndex=0};
    private readonly TextBlock notice=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};
    private readonly Canvas canvas=new(){Width=960,Height=500};
    private readonly ScrollViewer viewport=new(){Height=380,ZoomMode=ZoomMode.Enabled,MinZoomFactor=.25f,MaxZoomFactor=3,HorizontalScrollBarVisibility=ScrollBarVisibility.Auto,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollMode=ScrollMode.Enabled,VerticalScrollMode=ScrollMode.Enabled};
    private readonly TextBox alternative=new(){Header="Complete text alternative and supplied source",IsReadOnly=true,AcceptsReturn=true,TextWrapping=TextWrapping.Wrap,Height=260};
    private readonly Button copy=new(){Content="Copy complete text"};
    private readonly Button export=new(){Content="Export text…"};
    private ExportSelection? selection;
    private DiagramDocument? current;
    private Task loading = Task.CompletedTask;
    private long revision;
    private long selectionLoadCount;
    private bool stopped, dirty = true;
    private bool? effectiveVisibility;
    internal long SelectionLoadCount => selectionLoadCount;
    public event Action<string>? ExportTextRequested;
    public DiagramView()
    {
        var root=new StackPanel{Spacing=12,Padding=new Thickness(16)};
        root.Children.Add(new TextBlock{Text="Offline diagrams",FontSize=24});root.Children.Add(artifact);root.Children.Add(notice);
        var controls=new StackPanel{Orientation=Orientation.Horizontal,Spacing=6};
        Add("Zoom in",()=>viewport.ChangeView(null,null,Math.Min(3,viewport.ZoomFactor*1.25f)));
        Add("Zoom out",()=>viewport.ChangeView(null,null,Math.Max(.25f,viewport.ZoomFactor/1.25f)));
        Add("Reset view",()=>viewport.ChangeView(0,0,1));
        Add("Pan left",()=>Pan(-160,0));Add("Pan right",()=>Pan(160,0));Add("Pan up",()=>Pan(0,-120));Add("Pan down",()=>Pan(0,120));
        root.Children.Add(new ScrollViewer{Content=controls,HorizontalScrollBarVisibility=ScrollBarVisibility.Auto,VerticalScrollBarVisibility=ScrollBarVisibility.Disabled});
        viewport.Content=canvas;root.Children.Add(viewport);root.Children.Add(alternative);
        // Artifact lines (for example, all external targets) can be tens of thousands of
        // characters long. Keep native text layout within the viewport; retain exact text.
        ScrollViewer.SetHorizontalScrollMode(alternative,ScrollMode.Disabled);
        ScrollViewer.SetHorizontalScrollBarVisibility(alternative,ScrollBarVisibility.Disabled);
        ScrollViewer.SetVerticalScrollBarVisibility(alternative,ScrollBarVisibility.Auto);
        var actions=new StackPanel{Orientation=Orientation.Horizontal,Spacing=8};actions.Children.Add(copy);actions.Children.Add(export);root.Children.Add(actions);
        Content=new ScrollViewer{Content=root};
        AutomationProperties.SetName(viewport,"Offline diagram; complete nodes, edges and original source in the following text alternative");
        AutomationProperties.SetName(alternative,"Complete diagram nodes, edges and original source; selectable read-only text");
        copy.Click+=(_,_)=>{if(current==null)return;var data=new DataPackage();data.SetText(current.TextAlternative);Clipboard.SetContent(data);};
        export.Click+=(_,_)=>{if(current!=null)ExportTextRequested?.Invoke(current.TextAlternative);};
        artifact.SelectionChanged+=async(_,_)=>await Reload();
        LayoutUpdated += OnLayoutUpdated;
        Show(new("",Array.Empty<DiagramNode>(),Array.Empty<DiagramEdge>(),false,"Select a manifest-bound report to view its diagrams."));
        void Add(string name,Action action){var button=new Button{Content=name};AutomationProperties.SetName(button,name);button.Click+=(_,_)=>action();controls.Children.Add(button);}
    }
    private void Pan(double x,double y)=>viewport.ChangeView(Math.Max(0,viewport.HorizontalOffset+x),Math.Max(0,viewport.VerticalOffset+y),null);
    public void Stop()
    {
        if (stopped) return;
        stopped=true;revision++;selection=null;dirty=false;
        LayoutUpdated -= OnLayoutUpdated;
    }
    public async Task SetSelection(ExportSelection? value){if(stopped)return;selection=value;await Reload();}
    private async Task Reload()
    {
        if(stopped)return;
        dirty=true;++revision;
        Show(new("",Array.Empty<DiagramNode>(),Array.Empty<DiagramEdge>(),false,"Select a manifest-bound report to view its diagrams."));
        await ActivateWhenVisible();
    }
    private async void OnLayoutUpdated(object? sender, object args)
    {
        bool visible = UiActivation.IsEffectivelyVisible(this);
        if (effectiveVisibility == visible && (!visible || !dirty)) return;
        effectiveVisibility = visible;
        if (visible && dirty) await ActivateWhenVisible();
    }
    private Task ActivateWhenVisible()
    {
        if (stopped || !dirty || !UiActivation.IsEffectivelyVisible(this)) return Task.CompletedTask;
        if (!loading.IsCompleted) return loading;
        long captured=++revision;
        var selected=selection;
        string artifactName=artifact.SelectedItem?.ToString()??DiagramSelectionReader.ArtifactNames[0];
        dirty=false;
        return loading=Load(selected,artifactName,captured);
    }
    private async Task Load(ExportSelection? selected,string artifactName,long captured)
    {
        try
        {
            if(selected==null)
            {
                if(UiActivation.IsEffectivelyVisible(this))Show(new("",Array.Empty<DiagramNode>(),Array.Empty<DiagramEdge>(),false,"No manifest-bound report selected."));
                else dirty=true;
                return;
            }
            ++selectionLoadCount;
            var loaded=await DiagramSelectionReader.Read(selected,artifactName);
            if(stopped||captured!=revision)return;
            if(UiActivation.IsEffectivelyVisible(this))Show(loaded);
            else dirty=true;
        }
        catch(Exception error) when(error is IOException or System.Text.Json.JsonException or UnauthorizedAccessException or ArgumentException)
        {
            if(stopped||captured!=revision)return;
            if(UiActivation.IsEffectivelyVisible(this))Show(new("",Array.Empty<DiagramNode>(),Array.Empty<DiagramEdge>(),false,"Diagram unavailable: "+error.Message+" No prior graph is shown. Large or invalid inputs must be inspected/exported through the raw artifact workflow."));
            else dirty=true;
        }
        finally
        {
            loading=Task.CompletedTask;
            if(!stopped&&dirty&&UiActivation.IsEffectivelyVisible(this))await ActivateWhenVisible();
        }
    }
    // This bypass is compiled only into the standalone synthetic preview.
#if DIAGRAM_STANDALONE_PREVIEW
    public void ShowPreview(DiagramDocument synthetic){revision++;Show(synthetic with{Notice="Synthetic standalone preview; not a selected report. "+synthetic.Notice});}
#endif
    private void Show(DiagramDocument diagram)
    {
        if(stopped)return;
        current=diagram;notice.Text=diagram.Notice;alternative.Text=diagram.TextAlternative;canvas.Children.Clear();
        copy.IsEnabled=diagram.Source.Length>0;export.IsEnabled=diagram.Source.Length>0&&ExportTextRequested!=null;
        viewport.ChangeView(0,0,1);
        if(!diagram.Renderable){viewport.Visibility=Visibility.Collapsed;return;}viewport.Visibility=Visibility.Visible;
        var positions=DiagramLayout.Positions(diagram);var byId=positions.ToDictionary(p=>p.Id,StringComparer.Ordinal);
        canvas.Height=Math.Max(300,Math.Ceiling(diagram.Nodes.Count/3d)*140+50);
        var ink=new SolidColorBrush(Microsoft.UI.Colors.SlateGray);
        foreach(var edge in diagram.Edges)
        {
            var start=byId[edge.Source];var end=byId[edge.Target];double x1=start.X+110,y1=start.Y+64,x2=end.X+110,y2=end.Y;
            var points=new Windows.Foundation.Point[]{new(x1,y1),new(x1+24,y1+28),new(x2-24,y2-28),new(x2,y2)};
            var line=new Polyline{Stroke=ink,StrokeThickness=edge.Operator=="== ==>"?3:1.5};
            foreach(var point in points)line.Points.Add(point);
            if(edge.Operator.StartsWith("-.",StringComparison.Ordinal))line.StrokeDashArray=new DoubleCollection{4,4};
            canvas.Children.Add(line);
            if(edge.Directed)
            {
                var arrow=new Polygon{Fill=ink};arrow.Points.Add(new(x2,y2));arrow.Points.Add(new(x2-8,y2-9));arrow.Points.Add(new(x2+8,y2-9));canvas.Children.Add(arrow);
            }
            if(edge.Label.Length>0){var label=new TextBlock{Text=edge.Label,MaxWidth=220,TextTrimming=TextTrimming.CharacterEllipsis,FontSize=11};Canvas.SetLeft(label,(x1+x2)/2);Canvas.SetTop(label,(y1+y2)/2);canvas.Children.Add(label);}
        }
        foreach(var node in diagram.Nodes)
        {
            var position=byId[node.Id];
            var text=new TextBlock{Text=node.Label,TextWrapping=TextWrapping.Wrap,MaxLines=2,TextTrimming=TextTrimming.CharacterEllipsis};
            var box=new Border{Width=220,Height=64,Padding=new Thickness(8),BorderBrush=ink,BorderThickness=new Thickness(1),Background=(Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],Child=text};
            AutomationProperties.SetName(box,$"Node {node.Id}: {node.Label}");Canvas.SetLeft(box,position.X);Canvas.SetTop(box,position.Y);canvas.Children.Add(box);
        }
    }
}
