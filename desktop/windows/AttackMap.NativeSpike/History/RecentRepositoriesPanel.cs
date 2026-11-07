using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike.HistoryPrep;

/// <summary>Selection only: the host owns settings, availability checks and scan dispatch.</summary>
public sealed partial class RecentRepositoriesPanel : UserControl
{
    private readonly ComboBox repositories = new() { Header="Recent repositories", HorizontalAlignment=HorizontalAlignment.Stretch };
    private readonly TextBlock notice = new() { TextWrapping=TextWrapping.Wrap };
    private readonly Button select = new() { Content="Open selected repository", IsEnabled=false };
    public event Action<RecentRepository>? RepositoryRequested;

    public RecentRepositoriesPanel()
    {
        Content=new StackPanel { Spacing=8, Children={repositories,select,notice} };
        repositories.SelectionChanged+=(_,_)=>select.IsEnabled=repositories.SelectedItem is ComboBoxItem;
        select.Click+=(_,_)=>
        {
            if(repositories.SelectedItem is ComboBoxItem { Tag:RecentRepository repository })
                RepositoryRequested?.Invoke(repository);
        };
        notice.Text="Choose a saved repository explicitly. Selection does not start a scan.";
    }

    public void SetRepositories(IReadOnlyList<RecentRepository> source)
    {
        // Preserve codec/core order and full paths; identical folder names remain distinguishable.
        repositories.Items.Clear();
        foreach(var repository in source)
            repositories.Items.Add(new ComboBoxItem { Content=$"{repository.DisplayName} · {repository.Root}", Tag=repository });
        repositories.SelectedIndex=-1;
        select.IsEnabled=false;
        notice.Text=source.Count==0?"No recent repositories are saved yet.":"Choose a saved repository explicitly. Selection does not start a scan.";
    }
}
