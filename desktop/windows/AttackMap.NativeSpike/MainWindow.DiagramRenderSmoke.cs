using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private async Task DiagramNavigationRenderSmoke(string output, string mode, List<CaptureMetadata> captures)
    {
        var root = (FrameworkElement)Content;
        Diagrams.SelectLegacyView();
        Navigation.SelectedItem = Navigation.MenuItems.Cast<NavigationViewItem>().Single(item => Equals(item.Content, "Diagrams"));
        await ReadinessRenderBarrier();
        await Diagrams.SetSelection(exportSelection);
        await ReadinessRenderBarrier();
        var text = ProviderScrollElements(Diagrams).OfType<TextBox>().Single(box => Equals(box.Header, "Complete text alternative and supplied source"));
        var expires = DateTimeOffset.UtcNow.AddSeconds(20);
        while (!text.Text.Contains("Complete supplied source:", StringComparison.Ordinal) && DateTimeOffset.UtcNow < expires) await Task.Delay(50);
        await ReadinessRenderBarrier();
        string original = text.Text;
        int longestLine = original.Split(['\r', '\n']).Max(line => line.Length);
        if (!original.Contains("Complete supplied source:", StringComparison.Ordinal) || longestLine < 10000)
            throw new InvalidDataException($"Regression needs the real report with a long artifact line. Characters={original.Length}; longest={longestLine}; reads={Diagrams.LegacySelectionLoadCount}.");
        // A/B control only; the normal application never enables unwrapped artifact text.
        if (mode == "diagrams-nowrap-control")
        {
            text.TextWrapping = TextWrapping.NoWrap;
            ScrollViewer.SetHorizontalScrollMode(text, ScrollMode.Enabled);
            ScrollViewer.SetHorizontalScrollBarVisibility(text, ScrollBarVisibility.Auto);
        }
        root.UpdateLayout();
        var scroller = ProviderScrollElements(text).OfType<ScrollViewer>().Single();
        var states = new List<object>();
        var captureErrors = new List<object>();
        async Task Capture(string name)
        {
            string? captureMode = Environment.GetEnvironmentVariable("ATTACKMAP_DIAGRAM_QA_CAPTURE");
            if (captureMode == "none" || captureMode == "final" && name != "03-diagrams-small") return;
            await Task.Delay(500);
            root.UpdateLayout();
            try { captures.Add(await CaptureStrict(root, Path.Combine(output, name + ".png"), requireVisibleContent: true)); }
            catch (CaptureValidationException error)
            {
                captures.Add(error.Metadata);
                captureErrors.Add(new { name, error = error.Message, metadata = error.Metadata });
            }
        }
        await Capture("01-diagrams-start");
        text.Focus(FocusState.Programmatic);
        text.Select(original.Length - 1, 0);
        await Task.Delay(250);
        scroller.ChangeView(0, scroller.ScrollableHeight, null);
        await Capture("02-diagrams-end");
        double extentWidth = scroller.ExtentWidth, viewportWidth = scroller.ViewportWidth;
        if (mode == "diagrams" && (extentWidth > viewportWidth + 1 || text.Text != original))
            throw new InvalidOperationException("Artifact text must fit horizontally without changing its content.");
        for (int round = 0; round < 3; round++)
        foreach (string name in new[] { "Fleet", "Inventory", "Findings", "Reports", "Diagrams" })
        {
            Navigation.SelectedItem = Navigation.MenuItems.Cast<NavigationViewItem>().Single(item => Equals(item.Content, name));
            await Task.Delay(350);
            if (Heading.Text != name || text.Text != original)
                throw new InvalidOperationException("Navigation changed artifact content or selected page.");
            states.Add(new { round, name, heading = Heading.Text,
                labels = Navigation.MenuItems.Cast<NavigationViewItem>().Select(item => item.Content?.ToString()).ToArray() });
            await Capture($"round{round}-{name}");
        }
        // Also exercise wrapping at the supported smaller window size.
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1100, 800));
        await Capture("03-diagrams-small");
        if (mode == "diagrams" && scroller.ExtentWidth > scroller.ViewportWidth + 1)
            throw new InvalidOperationException("Small-window artifact text exceeds the viewport.");
        File.WriteAllText(Path.Combine(output, "diagram-proof.json"), JsonSerializer.Serialize(new {
            mode, report = displayedReportPath, displayedRun, characters = original.Length,
            longestLine = original.Split(['\r', '\n']).Max(line => line.Length), extentWidth, viewportWidth,
            smallExtentWidth = scroller.ExtentWidth, smallViewportWidth = scroller.ViewportWidth,
            passed = captureErrors.Count == 0, textPreserved = text.Text == original, states, captureErrors,
            captureMode = Environment.GetEnvironmentVariable("ATTACKMAP_DIAGRAM_QA_CAPTURE") ?? "all",
            providerCalls = 0, scope = NativeCaptureProbe.Scope
        }, new JsonSerializerOptions { WriteIndented = true }));
        if (captureErrors.Count > 0)
            throw new InvalidDataException("One or more required diagram captures failed; see diagram-proof.json.");
    }
}
