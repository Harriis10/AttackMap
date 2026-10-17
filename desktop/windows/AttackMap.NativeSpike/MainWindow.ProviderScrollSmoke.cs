using System.Text.Json;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private async Task RunProviderScrollSmoke(string[] args)
    {
        int index = Array.IndexOf(args, "--provider-scroll-smoke");
        if (index < 0 || index + 1 >= args.Length || !Path.IsPathFullyQualified(args[index + 1]))
            throw new ArgumentException("Provider scroll smoke requires a fresh absolute QA JSON path.");
        string output = Path.GetFullPath(args[index + 1]);
        if (Path.GetExtension(output) != ".json" || File.Exists(output) || Directory.Exists(output)) throw new IOException("Use a fresh QA JSON path.");
        var directory = new DirectoryInfo(Path.GetDirectoryName(output)!);
        if (!directory.Exists) throw new DirectoryNotFoundException("Create the caller-owned QA directory first.");
        for (DirectoryInfo? part = directory; part != null; part = part.Parent)
            if ((part.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Redirected QA output rejected.");
        var root = (FrameworkElement)Content;
        object? result = null;
        string? failure = null;
        try
        {
            int viewport = Array.IndexOf(args, "--viewport");
            if (viewport >= 0 && viewport + 2 < args.Length && int.TryParse(args[viewport + 1], out int width) && int.TryParse(args[viewport + 2], out int height) && width is >= 1024 and <= 16384 && height is >= 700 and <= 16384)
            {
                double scale = root.XamlRoot.RasterizationScale;
                AppWindow.Resize(new Windows.Graphics.SizeInt32((int)Math.Round(width * scale), (int)Math.Round(height * scale)));
            }
            Navigation.SelectedItem = Navigation.SettingsItem;
            await ProviderScrollDispatchTurns(); root.UpdateLayout();
            if (Provider.Content is not ScrollViewer inner) throw new InvalidOperationException("Actual provider content is not a ScrollViewer.");
            var before = ProviderButtons(root);
            for (int pass = 0; pass < 3; pass++)
            {
                inner.ChangeView(null, inner.ScrollableHeight, null, disableAnimation: true);
                ProviderPanel.ChangeView(null, ProviderPanel.ScrollableHeight, null, disableAnimation: true);
                await ProviderScrollDispatchTurns(); root.UpdateLayout();
            }
            var after = ProviderButtons(root);
            result = new {
                rootWidth = root.ActualWidth, rootHeight = root.ActualHeight, scale = root.XamlRoot.RasterizationScale,
                before, after, innerOffset = inner.VerticalOffset, innerScrollableHeight = inner.ScrollableHeight,
                outerOffset = ProviderPanel.VerticalOffset, outerScrollableHeight = ProviderPanel.ScrollableHeight,
                bothActionsFullyVisibleAndEnabled = after.Count == 2 && after.All(button => button.FullyWithinClippedViewport && button.Enabled),
                buttonActionsInvoked = 0, providerRequestsInvoked = 0
            };
        }
        catch (Exception) { failure = "Actual provider scroll/bounds inspection did not complete. No button actions were invoked."; }
        try
        {
            using var stream = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await JsonSerializer.SerializeAsync(stream, new {
                scope = "Programmatic actual Settings inner/outer scroll journey and clipped button bounds only; no keyboard, Narrator, contrast or C24 acceptance.",
                completed = failure == null, failure, result, acceptedC24 = false,
                settingsRestorePerformedByHelper = false, providerRequestsInvokedByHelper = 0,
                limitations = new[] { "Root must route this smoke flag before personal settings/provider restore.", "No report, settings file or credential value is read by this helper.", "Visibility requires nonempty bounds intersection through realized ancestor scroll viewports; Visibility enum alone is insufficient.", "Current window size/theme only; repeat on required sizes/scales and verify actual keyboard tasks independently." }
            }, new JsonSerializerOptions { WriteIndented = true });
        }
        finally { Close(); }
    }

    private sealed record ProviderButtonBounds(string Label, Rect BoundsRelativeRoot, Rect BoundsRelativeProviderPanel,
        Rect ClippedBoundsRelativeRoot, double VisibleFraction, bool FullyWithinClippedViewport, bool Enabled);

    private List<ProviderButtonBounds> ProviderButtons(FrameworkElement root)
    {
        var output = new List<ProviderButtonBounds>();
        foreach (var button in ProviderScrollElements(Provider).OfType<Button>())
        {
            string? label = button.Content as string;
            if (label is not ("Save provider settings" or "Test connection (sends request)")) continue;
            var bounds = button.TransformToVisual(root).TransformBounds(new Rect(0, 0, button.ActualWidth, button.ActualHeight));
            var panelBounds = button.TransformToVisual(ProviderPanel).TransformBounds(new Rect(0, 0, button.ActualWidth, button.ActualHeight));
            var clipped = ProviderIntersection(bounds, new Rect(0, 0, root.ActualWidth, root.ActualHeight));
            bool visible = button.IsLoaded;
            for (DependencyObject? ancestor = button; ancestor != null; ancestor = VisualTreeHelper.GetParent(ancestor))
            {
                if (ancestor is FrameworkElement element)
                {
                    visible &= element.Visibility == Visibility.Visible;
                    if (element is ScrollViewer || element.GetType().Name == "ScrollContentPresenter")
                        clipped = ProviderIntersection(clipped, element.TransformToVisual(root).TransformBounds(new Rect(0, 0, element.ActualWidth, element.ActualHeight)));
                }
                if (ReferenceEquals(ancestor, root)) break;
            }
            if (!visible) clipped = new Rect(0, 0, 0, 0);
            double area = bounds.Width * bounds.Height;
            double fraction = area > 0 ? clipped.Width * clipped.Height / area : 0;
            bool fully = visible && bounds.Width > 0 && bounds.Height > 0 && fraction >= 0.999;
            output.Add(new ProviderButtonBounds(label, bounds, panelBounds, clipped, fraction, fully, button.IsEnabled));
        }
        return output;
    }

    private static Rect ProviderIntersection(Rect first, Rect second)
    {
        double x = Math.Max(first.X, second.X), y = Math.Max(first.Y, second.Y);
        return new Rect(x, y, Math.Max(0, Math.Min(first.Right, second.Right) - x), Math.Max(0, Math.Min(first.Bottom, second.Bottom) - y));
    }

    private static IEnumerable<DependencyObject> ProviderScrollElements(DependencyObject root)
    {
        yield return root;
        for (int index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
            foreach (var child in ProviderScrollElements(VisualTreeHelper.GetChild(root, index))) yield return child;
    }

    private async Task ProviderScrollDispatchTurns()
    {
        for (int turn = 0; turn < 2; turn++)
        {
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => completion.TrySetResult())) throw new InvalidOperationException("Provider scroll dispatcher unavailable.");
            if (await Task.WhenAny(completion.Task, Task.Delay(TimeSpan.FromSeconds(3))) != completion.Task) throw new TimeoutException("Provider scroll layout did not settle.");
            await completion.Task;
        }
    }
}
