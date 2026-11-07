using Microsoft.UI.Xaml;using Microsoft.UI.Xaml.Controls;
namespace AttackMap.NativeSpike.HistoryPrep;

public sealed partial class HistoryComparisonView:UserControl
{
    private readonly ListView generations=new(){MaxHeight=300,DisplayMemberPath="Label"};private readonly TextBlock notice=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};
    private readonly TextBlock detail=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};private readonly ComboBox mode=new(){Header="Baseline for next scan",ItemsSource=new[]{"None","Previous","Custom"},SelectedIndex=0};private readonly CheckBox fail=new(){Content="Fail policy on new high findings for next scan"};
    private readonly Button open=new(){Content="Open selected historical report"},pin=new(){Content="Request pin selected generation"},options=new(){Content="Use next-run policy intent"},custom=new(){Content="Choose verified custom baseline"},compare=new(){Content="Compare selected report with chosen baseline"};
    private readonly TextBlock comparison=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};
    private HistoryComparisonModel? model;private HistoryArtifact? customBaseline;
    public event Action<HistoryLoadTicket>? OpenRequested;public event Action<HistoryPinIntent>? PinRequested;public event Action<NextRunHistoryIntent>? NextRunOptionsRequested;public event Action<HistorySelectionTicket>? CustomBaselineRequested;public event Action<HistoryCompareIntent>? CompareRequested;
    public HistoryComparisonView()
    {
        var panel=new StackPanel{Spacing=12,Padding=new Thickness(16)};panel.Children.Add(new TextBlock{Text="Repository history and comparison",FontSize=24});foreach(var child in new FrameworkElement[]{notice,generations,detail,open,pin,mode,custom,compare,comparison,fail,options})panel.Children.Add(child);Content=new ScrollViewer{Content=panel};
        generations.SelectionChanged+=(_,_)=>{if(model!=null&&generations.SelectedItem is RetainedGeneration selected)model.SelectGeneration(selected.Artifact);Refresh();};
        open.Click+=(_,_)=>{if(model?.BeginLoad() is HistoryLoadTicket ticket)OpenRequested?.Invoke(ticket);};pin.Click+=(_,_)=>{if(model?.Pin(model.Selected?.IsPinned!=true) is HistoryPinIntent request)PinRequested?.Invoke(request);};custom.Click+=(_,_)=>{if(model?.BeginCustomSelection() is HistorySelectionTicket ticket)CustomBaselineRequested?.Invoke(ticket);};
        compare.Click+=(_,_)=>{if(customBaseline!=null&&model?.Compare(customBaseline) is HistoryCompareIntent request)CompareRequested?.Invoke(request);};
        options.Click+=(_,_)=>{if(model?.SetNextRun((NextBaselineMode)mode.SelectedIndex,fail.IsChecked==true,customBaseline)==true&&model.NextRun!=null)NextRunOptionsRequested?.Invoke(model.NextRun);Refresh();};
    }
    public void SetModel(HistoryComparisonModel value){model=value;customBaseline=null;generations.ItemsSource=value.Generations;Refresh();}
    public bool SetCustomBaseline(HistorySelectionTicket ticket,HistoryArtifact value){if(model?.AcceptCustomSelection(ticket,value)!=true)return false;customBaseline=value;mode.SelectedIndex=2;Refresh();return true;}
    public void Refresh(){if(model==null)return;notice.Text=$"{model.Repository?.DisplayName??"No repository"}\nIdentity: {model.Repository?.RepositoryId??"unknown"}\nRoot: {model.Repository?.Root??"unknown"}\nSource repository available: {model.RepositoryAvailable}. Missing repository is recoverable by locating it; historical reports remain read-only.\n{model.Status}";detail.Text=model.Selected==null?"Select a retained generation.":$"Generation: {model.Selected.Artifact.GenerationId}\nSHA-256: {model.Selected.Artifact.ReportHash}\nReport: {model.Selected.Artifact.ReportPath}\nHistorical reports are read-only.";comparison.Text=string.Join("\n",model.Comparison.Select(c=>$"{c.Name}: {c.SuppliedCount?.ToString()??"unknown"}; supplied IDs in core order: {string.Join(", ",c.FindingIds)}"));open.IsEnabled=OpenRequested!=null&&model.BeginLoad()!=null;pin.IsEnabled=PinRequested!=null&&model.Selected!=null;pin.Content=model.Selected?.IsPinned==true?"Request unpin selected generation":"Request pin selected generation";options.IsEnabled=NextRunOptionsRequested!=null;custom.IsEnabled=CustomBaselineRequested!=null;compare.IsEnabled=CompareRequested!=null&&customBaseline!=null&&model.CanCompare(customBaseline);}
}
