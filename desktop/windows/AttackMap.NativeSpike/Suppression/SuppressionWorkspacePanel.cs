using Microsoft.UI.Xaml;using Microsoft.UI.Xaml.Controls;
namespace AttackMap.NativeSpike;

public sealed partial class SuppressionWorkspacePanel:UserControl
{
    private readonly TextBlock notice=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};
    private readonly TextBlock detail=new(){TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true};
    private readonly ListView rows=new(){MaxHeight=320,DisplayMemberPath="Label"};
    private readonly CheckBox noSuppress=new(){Content="Ignore suppression for next scan (independent of selected baseline)"};
    private readonly Button choose=new(){Content="Choose explicit baseline"},clear=new(){Content="Clear baseline"},preview=new(){Content="Preview intent"},apply=new(){Content="Apply preview intent"},undo=new(){Content="Undo receipt intent"};
    private SuppressionWorkspaceModel? model;
    private bool selectionOnly;
    public event Action<long>? ChooseBaselineRequested;
    public event Action? ClearBaselineRequested;
    public event Action<bool>? NoSuppressChanged;
    public event Action<SuppressionIntent>? ActionRequested;
    public SuppressionWorkspacePanel()
    {
        var panel=new StackPanel{Spacing=12,Padding=new Thickness(16)};panel.Children.Add(new TextBlock{Text="Suppression baseline and retained findings",FontSize=24});
        foreach(var child in new FrameworkElement[]{choose,clear,noSuppress,notice,rows,detail,preview,apply,undo})panel.Children.Add(child);Content=new ScrollViewer{Content=panel};
        choose.Click+=(_,_)=>{if(model==null)return;long ticket=model.BeginBaselineSelection();Refresh();ChooseBaselineRequested?.Invoke(ticket);};
        clear.Click+=(_,_)=>{model?.ClearBaseline();ClearBaselineRequested?.Invoke();Refresh();};
        noSuppress.Checked+=(_,_)=>SetNoSuppress(true);noSuppress.Unchecked+=(_,_)=>SetNoSuppress(false);
        preview.Click+=(_,_)=>Dispatch("suppression_preview");apply.Click+=(_,_)=>Dispatch("suppression_apply");undo.Click+=(_,_)=>Dispatch("suppression_undo");
        rows.SelectionChanged+=(_,_)=>{if(rows.SelectedItem is SuppressedItem row)detail.Text=$"ID: {row.Id??"unknown"}\nReason: {row.Reason}\nOrigin: {row.Origin}\nExpiry: {row.Expiry}";else detail.Text="Select a suppressed record. Selection does not infer a new suppression action.";};
    }
    public void SetModel(SuppressionWorkspaceModel value){model=value;rows.ItemsSource=value.Rows;noSuppress.IsChecked=value.NoSuppress;Refresh();}
    // The product shell keeps its established reason/preview/apply/undo panel.
    // This component can supply only baseline selection and retained records.
    public void SetSelectionOnly(bool value)
    {
        selectionOnly=value;
        foreach(var button in new[]{preview,apply,undo})button.Visibility=value?Visibility.Collapsed:Visibility.Visible;
        Refresh();
    }
    public void Refresh(){if(model==null)return;notice.Text=model.Notice;choose.IsEnabled=ChooseBaselineRequested!=null;clear.IsEnabled=model.Baseline!=null&&ClearBaselineRequested!=null;noSuppress.IsEnabled=NoSuppressChanged!=null;preview.IsEnabled=ActionRequested!=null&&model.CanPreview;apply.IsEnabled=ActionRequested!=null&&model.CanApply;undo.IsEnabled=ActionRequested!=null&&model.CanUndo;}
    private void SetNoSuppress(bool value){if(model==null)return;model.NoSuppress=value;NoSuppressChanged?.Invoke(value);Refresh();}
    private void Dispatch(string operation){if(!selectionOnly&&model?.Request(operation) is SuppressionIntent intent)ActionRequested?.Invoke(intent);Refresh();}
}
