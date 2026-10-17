using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.System;
namespace AttackMap.NativeSpike;

public sealed record AccessibilityIssue(string Code,string Severity,string Element,string Message);
public sealed record AccessibilityControl(string Element,string Name,string Role,bool Enabled,bool KeyboardFocusable,double MinHeight,double ActualHeight);
public sealed record AccessibilityAuditResult(string Scope,int ControlsInspected,IReadOnlyList<AccessibilityControl> Controls,IReadOnlyList<AccessibilityIssue> ScopedIssues);
public static class NativeAccessibility
{
    public static IReadOnlyDictionary<string,string> Shortcuts { get; } = new Dictionary<string,string> {
        ["open_report"]="Ctrl+O",["choose_repository"]="Ctrl+Shift+O",["scan"]="F5",["cancel"]="Escape",["export"]="Ctrl+E",["settings"]="Ctrl+Comma",["history"]="Ctrl+H" };
    public static IDisposable Bind(FrameworkElement root,IReadOnlyDictionary<string,Action> commands)
    {
        var bindings = new List<(KeyboardAccelerator Accelerator,Windows.Foundation.TypedEventHandler<KeyboardAccelerator,KeyboardAcceleratorInvokedEventArgs> Handler)>();
        foreach (var (command,key,modifiers) in new[] {
            ("open_report",VirtualKey.O,VirtualKeyModifiers.Control),
            ("choose_repository",VirtualKey.O,VirtualKeyModifiers.Control|VirtualKeyModifiers.Shift),
            ("scan",VirtualKey.F5,VirtualKeyModifiers.None),
            ("cancel",VirtualKey.Escape,VirtualKeyModifiers.None),
            ("export",VirtualKey.E,VirtualKeyModifiers.Control),
            ("settings",(VirtualKey)0xBC,VirtualKeyModifiers.Control), // VK_OEM_COMMA
            ("history",VirtualKey.H,VirtualKeyModifiers.Control) })
        {
            if (!commands.TryGetValue(command,out var action)) continue;
            var accelerator = new KeyboardAccelerator { Key=key,Modifiers=modifiers,ScopeOwner=root };
            Windows.Foundation.TypedEventHandler<KeyboardAccelerator,KeyboardAcceleratorInvokedEventArgs> handler = (_,args) => {
                // Escape dismisses the active flyout before it can cancel a scan behind it.
                if(command == "cancel" && root.XamlRoot != null && VisualTreeHelper.GetOpenPopupsForXamlRoot(root.XamlRoot).Any(popup => popup.IsOpen)) return;
                if(command is "scan" or "cancel")
                {
                    var primary=VisibleElements(root).OfType<Control>().FirstOrDefault(control => AutomationProperties.GetAutomationId(control)==command);
                    if(primary==null || !primary.IsEnabled)return; // Preserve normal F5/Escape handling when action is unavailable.
                }
                action(); args.Handled=true;
            };
            accelerator.Invoked += handler;
            root.KeyboardAccelerators.Add(accelerator);
            bindings.Add((accelerator,handler));
        }
        var flyouts = new List<(Flyout Flyout, EventHandler<object> Handler)>();
        void RegisterFlyouts()
        {
            foreach (var flyout in VisibleElements(root).OfType<Button>().Select(button => button.Flyout).OfType<Flyout>().Distinct())
            {
                if (flyouts.Any(existing => ReferenceEquals(existing.Flyout, flyout))) continue;
                EventHandler<object> handler = (_, _) => { if (flyout.Content is FrameworkElement content) ApplyNames(content); };
                flyout.Opened += handler;
                flyouts.Add((flyout, handler));
            }
        }
        RoutedEventHandler loaded = (_, _) => RegisterFlyouts();
        root.Loaded += loaded;
        if (root.IsLoaded) RegisterFlyouts();
        return new Binding(root,bindings,flyouts,loaded);
    }
    public static int ApplyNames(FrameworkElement root)
    {
        int changed=0;
        foreach(var element in VisibleElements(root).OfType<Control>().Where(Interactive))
        {
            if (!string.IsNullOrWhiteSpace(AutomationProperties.GetName(element))) continue;
            string? name = element switch {
                TextBox text => Label(text.Header),
                PasswordBox password => Label(password.Header),
                ComboBox combo => Label(combo.Header),
                NumberBox number => Label(number.Header),
                ToggleSwitch toggle => Label(toggle.Header),
                ContentControl content => Label(content.Content),
                _ => null };
            if (string.IsNullOrWhiteSpace(name)) continue;
            AutomationProperties.SetName(element,name);
            changed++;
        }
        return changed;
    }
    public static AccessibilityAuditResult Audit(FrameworkElement root)
    {
        var controls = new List<AccessibilityControl>();
        int inspected=0;
        var issues = new List<AccessibilityIssue>();
        foreach(var control in VisibleElements(root).OfType<Control>().Where(Interactive))
        {
            inspected++;
            string id = AutomationProperties.GetAutomationId(control);
            string element = string.IsNullOrWhiteSpace(id) ? string.IsNullOrWhiteSpace(control.Name) ? control.GetType().Name : control.Name : id;
            try
            {
                var peer = FrameworkElementAutomationPeer.CreatePeerForElement(control);
                if (peer==null) { issues.Add(new("peer-unavailable","warning",element,"No automation peer available in the loaded visible tree.")); continue; }
                string name=peer.GetName();
                string role=peer.GetAutomationControlType().ToString();
                bool enabled=peer.IsEnabled(),focusable=peer.IsKeyboardFocusable();
                controls.Add(new(element,name,role,enabled,focusable,control.MinHeight,control.ActualHeight));
                if(string.IsNullOrWhiteSpace(name)) issues.Add(new("name-missing","warning",element,"Interactive control has no exposed automation name."));
                if(role=="Custom") issues.Add(new("role-review","info",element,"Custom role requires manual semantic review; no role failure inferred."));
                if(enabled && !focusable && control.IsTabStop) issues.Add(new("focusability-review","warning",element,"Enabled tab-stop control is not reported keyboard-focusable; inspect composite behavior/focus manually."));
                if(string.Equals(id,"scan",StringComparison.OrdinalIgnoreCase) || string.Equals(id,"cancel",StringComparison.OrdinalIgnoreCase))
                {
                    if(control.MinHeight<32) issues.Add(new("primary-min-height","warning",element,"Primary scan/cancel MinHeight is below 32 logical units."));
                    if(control.ActualHeight>0 && control.ActualHeight<32) issues.Add(new("primary-actual-height","warning",element,"Loaded primary scan/cancel height is below 32 logical units."));
                }
            }
            catch(Exception error) { issues.Add(new("peer-query-unavailable","warning",element,$"Automation peer query failed ({error.GetType().Name}); no accessibility success inferred.")); }
        }
        return new("Loaded visible interactive controls only; collapsed descendants/templates' non-tab-stop parts excluded. Popup/dialog trees, keyboard task completion, Narrator, contrast, text scaling and full C24 remain unverified.",inspected,controls,issues);
    }
    private static bool Interactive(Control control) => control is ButtonBase or TextBox or PasswordBox or ComboBox or NumberBox or ToggleSwitch or Slider or ListViewBase
        && (control.IsTabStop || !string.IsNullOrEmpty(control.Name) || !string.IsNullOrEmpty(AutomationProperties.GetAutomationId(control)));
    private static bool CompositePart(Control control)
    {
        if(control.IsTabStop)return false;
        for(var parent=VisualTreeHelper.GetParent(control);parent!=null;parent=VisualTreeHelper.GetParent(parent))
        {
            if(parent is TextBox or PasswordBox or ComboBox or NumberBox or ToggleSwitch or ListViewBase)return true;
            if(parent is UserControl)break;
        }
        return false;
    }
    private static string? Label(object? value) => value switch { string text => text,TextBlock text => text.Text,_ => null };
    private static IEnumerable<DependencyObject> VisibleElements(DependencyObject root)
    {
        if(root is UIElement element && element.Visibility!=Visibility.Visible) yield break;
        yield return root;
        int count=VisualTreeHelper.GetChildrenCount(root);
        for(int i=0;i<count;i++) foreach(var child in VisibleElements(VisualTreeHelper.GetChild(root,i))) yield return child;
    }
    private sealed class Binding(FrameworkElement root,List<(KeyboardAccelerator Accelerator,Windows.Foundation.TypedEventHandler<KeyboardAccelerator,KeyboardAcceleratorInvokedEventArgs> Handler)> bindings,List<(Flyout Flyout, EventHandler<object> Handler)> flyouts,RoutedEventHandler loaded) : IDisposable
    {
        private bool disposed;
        public void Dispose()
        {
            if(disposed)return;
            root.Loaded -= loaded;
            foreach(var (accelerator,handler) in bindings) { accelerator.Invoked-=handler;root.KeyboardAccelerators.Remove(accelerator); }
            foreach (var (flyout,handler) in flyouts) flyout.Opened -= handler;
            disposed=true;
        }
    }
}
