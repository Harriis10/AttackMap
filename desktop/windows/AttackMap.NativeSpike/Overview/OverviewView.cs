using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
namespace AttackMap.NativeSpike;

public sealed partial class OverviewView:UserControl
{
    private readonly StackPanel panel=new(){Spacing=12,Padding=new Thickness(16)};
    private ParityOverview? current;
    public event Action<OverviewLink>? NavigationRequested;
    public OverviewView(){Content=new ScrollViewer{Content=panel};}
    public void SetOverview(ParityOverview overview)
    {
        current=overview;panel.Children.Clear();Text("Evidence overview",24);Text(overview.Repository,18);Text(overview.Coverage);
        foreach(var count in overview.Counts)Text($"{count.Name}: {count.Value?.ToString()??"unknown"} ({count.Availability})");
        void Section(string title,OverviewList list)
        {
            Text(title,20);Text(list.Notice);
            if(list.Items.Count==0)Text(list.Availability==SectionAvailability.Missing?"Unavailable; unknown.":"No displayable supplied records; inspect section status.");
            foreach(var item in list.Items)
            {
                Text(item.Title,16);Text(item.Detail);
                if(item.Link is OverviewLink link)
                {
                    var button=new Button{Content=$"Inspect supplied {link.Kind} {link.Identity}",IsEnabled=NavigationRequested!=null};
                    button.Click+=(_,_)=>{if(current?.Allows(link,current.Generation,current.ReadHash)==true)NavigationRequested?.Invoke(link);};panel.Children.Add(button);
                }
            }
        }
        Section("Core ranked risks",overview.Risks);Section("Supplied attack paths",overview.Paths);Section("Next actions (core order)",overview.Actions);Section("Strengths (supplied indicators)",overview.Strengths);
    }
    private void Text(string value,double fontSize=14)=>panel.Children.Add(new TextBlock{Text=value,FontSize=fontSize,TextWrapping=TextWrapping.Wrap,IsTextSelectionEnabled=true});
}
