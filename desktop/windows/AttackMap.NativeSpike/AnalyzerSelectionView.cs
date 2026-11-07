using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Automation;
namespace AttackMap.NativeSpike;

public sealed class AnalyzerSelectionView : Grid
{
    private readonly AnalyzerSelectionModel model;
    private readonly ComboBox profile = new() { Header = "Analyzer selection", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly TextBox search = new() { PlaceholderText = "Filter installed analyzers" };
    private readonly TextBlock notice = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock selection = new() { TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
    private readonly StackPanel rows = new() { Spacing = 10 };
    private readonly Expander ledger = new() { Name = "AnalyzerRunLedger", Header = "Selected report · analyzer execution", HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch };
    private readonly Expander discoveryIssues = new() { Name = "AnalyzerDiscoveryIssues", HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch };
    private bool refreshing;
    public event Action? SelectionChanged;
    public AnalyzerSelectionView(AnalyzerSelectionModel model)
    {
        this.model = model;
        var content = new StackPanel { Spacing = 10 };
        content.Children.Add(profile); content.Children.Add(selection); content.Children.Add(search);
        content.Children.Add(ledger); content.Children.Add(discoveryIssues); content.Children.Add(notice); content.Children.Add(rows);
        Children.Add(new ScrollViewer { Content = content, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(0, 0, 16, 20) });
        AutomationProperties.SetName(profile, "Analyzer selection: Automatic, Custom, or versioned profile");
        AutomationProperties.SetName(search, "Filter installed analyzers; selected missing analyzers remain visible");
        search.TextChanged += (_, _) => Refresh();
        profile.SelectionChanged += (_, _) =>
        {
            if (refreshing || profile.SelectedItem is not ComboBoxItem { Tag: string key }) return;
            if (key == "automatic") model.SetAutomatic(true);
            else if (key == "custom") model.SetAutomatic(false);
            else model.SelectProfile(key);
            Refresh(); SelectionChanged?.Invoke();
        };
        Refresh();
    }
    public void Refresh()
    {
        refreshing = true;
        try
        {
            profile.Items.Clear();
            profile.Items.Add(new ComboBoxItem { Content = "Automatic · engine defaults", Tag = "automatic" });
            profile.Items.Add(new ComboBoxItem { Content = "Custom · exact module selection", Tag = "custom" });
            foreach (var item in model.Profiles.Where(item => !item.Automatic))
                profile.Items.Add(new ComboBoxItem { Content = item.DisplayName + " · " + item.Version + (item.Available ? "" : " · missing modules"), Tag = item.QualifiedName });
            string key = model.Automatic ? "automatic" : model.SelectedProfile ?? "custom";
            var selectedItem = profile.Items.Cast<ComboBoxItem>().FirstOrDefault(item => (string)item.Tag == key);
            if (selectedItem == null)
            { selectedItem = new ComboBoxItem { Content = key + " · unavailable saved profile", Tag = key }; profile.Items.Add(selectedItem); }
            profile.SelectedItem = selectedItem;
        }
        finally { refreshing = false; }
        var activeProfile = model.Profiles.FirstOrDefault(item => item.QualifiedName == model.SelectedProfile);
        selection.Text = model.ProfileSelectionError ?? (model.Automatic
            ? "Automatic uses installed engine defaults. Each analyzer still needs to match the repository."
            : model.SelectedProfile == null ? "Custom sends exactly the checked modules. No base modules are added."
            : model.SelectedProfile + " · modules: " + model.ExpandedProfileModules.Replace(",", ", ") +
                (activeProfile?.ExperimentalModuleNames.Count > 0 ? "\nExperimental: " + string.Join(", ", activeProfile.ExperimentalModuleNames) + "." : "") +
                (activeProfile?.OptInModuleNames.Count > 0 ? " Opt-in: " + string.Join(", ", activeProfile.OptInModuleNames) + "." : "") +
                "\nChange a module below to switch to Custom. Selection does not establish applicability or execution.");
        var items = model.Rows(search.Text);
        notice.Text = model.DiscoveryError ?? string.Join("\n", new[] {
            model.ProfileCatalogError, model.CatalogError,
            $"{items.Count} displayed inventory records. No automatic installation/download. Inventory does not establish applicability or execution.",
            model.Profiles.Count == 0 && model.ProfileCatalogError == null ? "This engine does not advertise versioned profiles; Automatic and Custom remain available." : null
        }.Where(text => text != null));
        var unavailable = new StackPanel { Spacing = 8 };
        unavailable.Children.Add(new TextBlock { Text = "Current engine discovery failures and policy skips are separate from usable analyzers. These records do not establish repository applicability or execution.", TextWrapping = TextWrapping.Wrap });
        foreach (var item in model.DiscoveryIssues.Take(64))
            unavailable.Children.Add(new TextBlock { Text = item.Summary, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
        if (model.DiscoveryIssues.Count > 64)
            unavailable.Children.Add(new TextBlock { Text = $"{model.DiscoveryIssues.Count - 64} additional discovery issues are omitted from this view.", TextWrapping = TextWrapping.Wrap });
        discoveryIssues.Header = $"Discovery failures and policy skips ({model.DiscoveryIssues.Count})";
        discoveryIssues.Content = unavailable;
        discoveryIssues.Visibility = model.DiscoveryIssues.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        AutomationProperties.SetName(discoveryIssues, "Current engine discovery failures and policy skips; separate from usable analyzers and report execution");
        rows.Children.Clear();
        foreach (var item in items)
        {
            var check = new CheckBox { Content = new TextBlock { Text = item.DisplayName + " (" + item.Name + ")", TextWrapping = TextWrapping.Wrap }, IsThreeState = false, IsChecked = item.Selected, IsEnabled = !model.Automatic };
            AutomationProperties.SetName(check, item.DisplayName + "; " + item.Status);
            check.Click += (_, _) => { model.Select(item.Name, check.IsChecked == true); Refresh(); SelectionChanged?.Invoke(); };
            var row = new StackPanel { Spacing = 4, Margin = new Thickness(0, 0, 0, 8) };
            row.Children.Add(check);
            row.Children.Add(new TextBlock { Text = item.Status + (item.Error == null ? "" : ": " + item.Error), TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            if (!item.Missing)
                row.Children.Add(new TextBlock { Text = item.OriginSummary ?? "Effective origin/version not advertised by this engine.", TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            if (item.ImplementationSummary != null)
                row.Children.Add(new TextBlock { Text = item.ImplementationSummary, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            if (item.ShadowedSummary != null)
                row.Children.Add(new TextBlock { Text = item.ShadowedSummary, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            rows.Children.Add(row);
        }
        if (items.Count == 0) rows.Children.Add(new TextBlock { Text = "No matching installed analyzer records. Clear the filter or refresh discovery.", TextWrapping = TextWrapping.Wrap });
        var reportRows = new StackPanel { Spacing = 10 };
        reportRows.Children.Add(new TextBlock { Text = model.RunLedgerLabel, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
        reportRows.Children.Add(new TextBlock { Text = model.RunLedgerNotice, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
        foreach (var item in model.RunLedgerRows)
        {
            var record = new StackPanel { Spacing = 4 };
            record.Children.Add(new TextBlock { Text = item.Name + " · " + item.Version + " · recorded " + item.Origin, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            record.Children.Add(new TextBlock { Text = item.Status, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            record.Children.Add(new TextBlock { Text = item.TimingSummary, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            record.Children.Add(new TextBlock { Text = item.SignalSummary, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            if (item.Lifecycle.Count > 0)
                record.Children.Add(new TextBlock { Text = "Activity · elapsed from analyzer selection start\n" + string.Join("\n", item.Lifecycle), TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            var identity = new TextBlock { Text = "Recorded implementation SHA-256: " + item.ImplementationIdentity[..12] + "…", TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
            ToolTipService.SetToolTip(identity, item.ImplementationIdentity); record.Children.Add(identity);
            var details = new Expander { Header = new TextBlock { Text = item.Name + " · " + item.Execution, TextWrapping = TextWrapping.Wrap }, Content = record,
                HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch };
            AutomationProperties.SetName(details, item.Name + " recorded analyzer details; " + item.Execution);
            reportRows.Children.Add(details);
        }
        ledger.Content = reportRows;
        AutomationProperties.SetName(ledger, "Selected report analyzer execution; separate from current installed inventory");
    }
}


