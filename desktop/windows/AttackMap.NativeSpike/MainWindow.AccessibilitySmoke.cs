using System.Text.Json;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private async Task RunExpandedAccessibilitySmoke(string[] args)
    {
        int index = Array.IndexOf(args, "--expanded-accessibility-smoke");
        if (index < 0 || index + 2 >= args.Length) throw new ArgumentException("Expanded accessibility smoke requires a canonical report and fresh proof JSON path.");
        string report = Path.GetFullPath(args[index + 1]), output = Path.GetFullPath(args[index + 2]);
        if (!Path.IsPathFullyQualified(args[index + 2]) || Path.GetExtension(output) != ".json" || File.Exists(output) || Directory.Exists(output))
            throw new IOException("Use a fresh absolute QA JSON output path.");
        var directory = new DirectoryInfo(Path.GetDirectoryName(output)!);
        if (!directory.Exists) throw new DirectoryNotFoundException("Create the caller-owned QA directory first.");
        for (DirectoryInfo? part = directory; part != null; part = part.Parent)
            if ((part.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Redirected QA directories are not allowed.");
        var views = new List<object>();
        var popupViews = new List<object>();
        bool popupNamesPassed = false, savedAiReviewRead = false;
        bool loaded = false;
        bool expansionComplete = true;
        string? failure = null;
        try
        {
            loaded = await LoadReport(report);
            if (!loaded) throw new InvalidDataException("Canonical report could not be loaded.");
            var root = (FrameworkElement)Content;
            foreach (var label in new[] { "Scan options", "Run details" })
            {
                var button = AccessibilityRealizedElements(root).OfType<Button>().Single(item => item.Content?.ToString() == label);
                var flyout = button.Flyout as Flyout ?? throw new InvalidDataException("Expected actual flyout.");
                var opened = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                flyout.Opened += (_, _) => opened.TrySetResult();
                flyout.Closed += (_, _) => closed.TrySetResult();
                flyout.ShowAt(button);
                await opened.Task.WaitAsync(TimeSpan.FromSeconds(5));
                await AccessibilityDispatchTurns();
                var content = flyout.Content as FrameworkElement ?? throw new InvalidDataException("Flyout content unavailable.");
                content.UpdateLayout();
                var audit = NativeAccessibility.Audit(content);
                popupViews.Add(new { label, content.IsLoaded, content.ActualWidth, content.ActualHeight, audit.ControlsInspected, audit.Controls, audit.ScopedIssues });
                popupNamesPassed = popupViews.Count == 1 ? content.IsLoaded && audit.ControlsInspected > 0 && audit.Controls.All(control => !string.IsNullOrWhiteSpace(control.Name)) : popupNamesPassed && content.IsLoaded && audit.ControlsInspected > 0 && audit.Controls.All(control => !string.IsNullOrWhiteSpace(control.Name));
                flyout.Hide();
                await closed.Task.WaitAsync(TimeSpan.FromSeconds(5));
                await AccessibilityDispatchTurns();
            }
            Navigation.SelectedItem = Navigation.MenuItems[4];
            await AccessibilityDispatchTurns();
            OpenAiReview(this, new RoutedEventArgs());
            var reviewDeadline = System.Diagnostics.Stopwatch.StartNew();
            while (!AiReviewButton.IsEnabled && reviewDeadline.Elapsed < TimeSpan.FromSeconds(10)) await AccessibilityDispatchTurns();
            savedAiReviewRead = exportSelection?.Verified == true && AiReviewButton.IsEnabled && AiReviewText.Text.Length > 0 && AiReviewStatus.Text.Contains(exportSelection.RunId!);
            foreach (var destination in Navigation.MenuItems.Cast<object>().Append(Navigation.SettingsItem))
            {
                Navigation.SelectedItem = destination;
                await AccessibilityDispatchTurns();
                var expanded = new HashSet<Expander>();
                int passes = 0;
                for (; passes < 8; passes++)
                {
                    root.UpdateLayout();
                    var realized = AccessibilityRealizedElements(root).OfType<Expander>().ToList();
                    bool changed = false;
                    foreach (var expander in realized)
                        if (!expander.IsExpanded)
                        { expander.IsExpanded = true; expanded.Add(expander); changed = true; }
                    await AccessibilityDispatchTurns();
                    if (!changed) { passes++; break; }
                }
                root.UpdateLayout();
                var remaining = AccessibilityRealizedElements(root).OfType<Expander>().ToList();
                expansionComplete &= remaining.All(item => item.IsExpanded);
                // Audit production metadata without repairing names inside the QA hook.
                int namesApplied = 0;
                var audit = NativeAccessibility.Audit(root);
                views.Add(new {
                    destination = destination is NavigationViewItem item ? item.Content?.ToString() : "Settings",
                    expansionPasses = passes, expandersChanged = expanded.Count,
                    realizedExpanders = remaining.Count, expandedRealizedExpanders = remaining.Count(item => item.IsExpanded),
                    unexpandedRealizedExpanders = remaining.Count(item => !item.IsExpanded),
                    namesApplied, audit.ControlsInspected, audit.Controls, audit.ScopedIssues,
                    auditScope = audit.Scope,
                    warning = "Expanded realized visual-tree audit only. Off-screen controls, virtualized rows and dialogs need separate task checks; scoped issue severity is not a WCAG critical/serious classification."
                });
            }
        }
        catch (Exception) { failure = "Expanded audit could not complete; inspect the scoped view records. No button action or provider request was invoked by this helper."; }
        try
        {
            var proof = new {
                scope = "Actual loaded app report and seven navigation destinations with realized Expanders opened. Original production names/roles, enabled focusability and primary sizes only; no QA name repair.",
                report, loaded, expansionComplete, completedViews = views.Count, expectedViews = 7, completed = loaded && expansionComplete && views.Count == 7 && failure == null,
                popupNamesPassed, popupViews, savedAiReviewRead, savedAiReviewCharacters = AiReviewText.Text.Length, savedAiReviewStatus = AiReviewStatus.Text, popupEscapeActualKeyboard = "not run", popupAuditScope = "Programmatic actual Flyout Opened/Closed; Advanced options remains collapsed, so its descendants are excluded. Saved review read invokes the production handler but is not keyboard input.",
                failure, views, manualKeyboard = "not run", narrator = "not run", contrast = "not measured",
                scaling = "not tested", acceptedC24 = false,
                limitations = new[] { "No scan, export, provider test/save or suppression button is clicked.", "Root must route this flag before personal settings/provider restore; this helper performs no settings restore.", "Programmatic expansion is not keyboard task completion or dialog focus verification.", "Current theme/display only; no Windows 11 or full accessibility acceptance claim." }
            };
            using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await JsonSerializer.SerializeAsync(file, proof, new JsonSerializerOptions { WriteIndented = true });
        }
        finally { Close(); }
    }

    private async Task AccessibilityDispatchTurns()
    {
        for (int turn = 0; turn < 2; turn++)
        {
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => completion.TrySetResult()))
                throw new InvalidOperationException("Accessibility dispatcher is unavailable.");
            if (await Task.WhenAny(completion.Task, Task.Delay(TimeSpan.FromSeconds(3))) != completion.Task)
                throw new TimeoutException("Accessibility layout did not settle.");
            await completion.Task;
        }
    }

    private static IEnumerable<FrameworkElement> AccessibilityRealizedElements(DependencyObject value)
    {
        if (value is FrameworkElement element)
        {
            if (element.Visibility == Visibility.Collapsed || !element.IsLoaded) yield break;
            yield return element;
        }
        for (int index = 0; index < VisualTreeHelper.GetChildrenCount(value); index++)
            foreach (var child in AccessibilityRealizedElements(VisualTreeHelper.GetChild(value, index))) yield return child;
    }
}
