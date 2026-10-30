using System.Text;
using System.Text.Json;
using AttackMap.GraphExplorer;
using AttackMap.GraphExplorer.Native;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Windows.Storage.Streams;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private async Task ReportGraphSmoke(string output, bool fallbackOnly = false)
    {
        var root = (FrameworkElement)Content;
        var destination = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Diagrams");
        Navigation.SelectedItem = destination;
        await ReadinessRenderBarrier();
        await Diagrams.ActivateInteractive();
        var graph = Diagrams.CurrentGraph ?? throw new InvalidDataException("The selected report did not load an interactive graph.");
        if (graph.Repositories.Length != 1 || graph.Context.ReportHash != exportSelection?.ReportHash || graph.Context.RunId != exportSelection.RunId)
            throw new InvalidDataException("The report graph identity differs from the displayed report.");
        if (fallbackOnly)
        {
            await RunGraphFallbackCheck((Panel)Content, Encoding.UTF8.GetBytes(graph.SourceJson), graph.Context, Path.Combine(output, "fallback-proof.json"));
            return;
        }
        var pane = Diagrams.GraphPane;
        await pane.SelectSurface(false);
        var expires = DateTimeOffset.UtcNow.AddSeconds(30);
        while (!pane.HasInteractiveLayoutAcknowledgement && DateTimeOffset.UtcNow < expires) await Task.Delay(100);
        if (!pane.HasInteractiveLayoutAcknowledgement) throw new InvalidDataException("The hosted report graph did not acknowledge its current layout.");
        var browser = FleetGraphSmokeChildren<WebView2>(Diagrams).Single();
        var captures = new List<object>();
        foreach (var size in new[] { (Width: 1100, Height: 800), (Width: 1600, Height: 1000) })
        foreach (var theme in new[] { ElementTheme.Light, ElementTheme.Dark })
        {
            root.RequestedTheme = theme;
            AppWindow.Resize(new Windows.Graphics.SizeInt32(size.Width, size.Height));
            Activate();
            string beforeViewport = await WaitForHostedViewport(browser, root, theme);
            string path = Path.Combine(output, $"{size.Width}-{theme}-hosted-report.png");
            string observation = await browser.ExecuteScriptAsync("""
                (() => {
                  const snapshot = window.AttackMapGraph.snapshot();
                  const rect = document.querySelector('#graph').getBoundingClientRect();
                  const layers = [...document.querySelectorAll('#graph canvas')].map(canvas => {
                    const probe = document.createElement('canvas'); probe.width = probe.height = 96;
                    const context = probe.getContext('2d'); context.drawImage(canvas, 0, 0, 96, 96);
                    const data = context.getImageData(0, 0, 96, 96).data; const colors = new Set(); let ink = 0;
                    for (let i = 0; i < data.length; i += 4) if (data[i + 3]) { ink++; colors.add(`${data[i]},${data[i + 1]},${data[i + 2]}`); }
                    return { width: canvas.width, height: canvas.height, ink, colors: colors.size };
                  });
                  return { snapshot, viewport: { width: innerWidth, height: innerHeight },
                    graphRect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
                    graphVisible: rect.width > 0 && rect.height > 0 && rect.x >= -1 && rect.y >= -1 && rect.right <= innerWidth + 1 && rect.bottom <= innerHeight + 1,
                    finitePositions: snapshot.positions.every(p => Number.isFinite(p.x) && Number.isFinite(p.y)),
                    textRows: document.querySelectorAll('#text-list .text-row').length, layers };
                })()
                """);
            await File.WriteAllTextAsync(Path.ChangeExtension(path, ".dom.json"), observation);
            using (var observed = JsonDocument.Parse(observation))
            {
                var snapshot = observed.RootElement.GetProperty("snapshot");
                var context = snapshot.GetProperty("context");
                var counts = snapshot.GetProperty("counts");
                if (!snapshot.GetProperty("loaded").GetBoolean() || snapshot.GetProperty("synthetic").GetBoolean() ||
                    context.GetProperty("report_hash").GetString() != graph.Context.ReportHash || context.GetProperty("run_id").GetString() != graph.Context.RunId ||
                    context.GetProperty("selection_revision").GetInt64() != graph.Context.SelectionRevision ||
                    counts.GetProperty("canonicalNodes").GetInt32() != graph.Nodes.Length || counts.GetProperty("canonicalEdges").GetInt32() != graph.Edges.Length ||
                    counts.GetProperty("displayedNodes").GetInt32() <= 1 || !observed.RootElement.GetProperty("graphVisible").GetBoolean() ||
                    !observed.RootElement.GetProperty("finitePositions").GetBoolean() ||
                    !observed.RootElement.GetProperty("layers").EnumerateArray().Any(layer => layer.GetProperty("ink").GetInt32() > 50 && layer.GetProperty("colors").GetInt32() > 2))
                    throw new InvalidDataException("Hosted report graph is empty, stale, hidden or has no nonuniform canvas pixels. See retained DOM observation.");
            }
            using var stream = new InMemoryRandomAccessStream();
            await browser.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, stream);
            if (stream.Size < 1024 || stream.Size > 32 * 1024 * 1024) throw new InvalidDataException("Hosted graph capture has an invalid size.");
            using var reader = new DataReader(stream.GetInputStreamAt(0));
            await reader.LoadAsync((uint)stream.Size);
            byte[] pixels = new byte[checked((int)stream.Size)]; reader.ReadBytes(pixels);
            await File.WriteAllBytesAsync(path, pixels);
            string afterViewport = await DescribeHostedViewport(browser);
            File.WriteAllText(Path.ChangeExtension(path, ".viewport.json"), JsonSerializer.Serialize(new { beforeViewport, afterViewport,
                nativeWidth = browser.ActualWidth, nativeHeight = browser.ActualHeight, rasterizationScale = root.XamlRoot.RasterizationScale }));
            if (beforeViewport != afterViewport) throw new InvalidDataException("Hosted viewport changed during capture; the image is not accepted.");
            captures.Add(new { path, theme = theme.ToString(), size.Width, size.Height, sha256 = ExportSelection.Hash(pixels),
                scope = "Actual hosted WebView2 page pixels only; excludes native shell/chrome and OS screenshot acceptance. No RenderTargetBitmap." });
        }
        var states = new List<string>();
        for (int round = 0; round < 3; round++)
        foreach (string name in new[] { "Fleet", "Findings", "Inventory", "Reports", "Diagrams" })
        {
            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == name);
            await Task.Delay(250);
            if (Heading.Text != name || Diagrams.CurrentGraph?.Context != graph.Context) throw new InvalidDataException("Navigation lost the selected report graph.");
            states.Add(name);
        }
        await pane.SelectSurface(true);
        if (!pane.HasNativeLayout) throw new InvalidDataException("Report vector alternative did not finish its layout.");
        var native = FleetGraphSmokeChildren<GraphExplorerView>(Diagrams).Single();
        var projection = native.CurrentProjection ?? throw new InvalidDataException("Report vector projection unavailable.");
        if (projection.Nodes.Length != graph.Nodes.Length || projection.Nodes.Length <= 1)
            throw new InvalidDataException("The single-report vector view must expose its components initially.");
        var layout = native.Snapshot ?? throw new InvalidDataException("Report vector layout unavailable.");
        await File.WriteAllTextAsync(Path.Combine(output, "report-full.svg"), GraphExporter.Svg(projection, layout));
        await File.WriteAllTextAsync(Path.Combine(output, "report-full.json"), GraphExporter.JsonWithMetadata(graph, projection));
        await pane.SelectSurface(false);
        File.WriteAllText(Path.Combine(output, "report-graph-proof.json"), JsonSerializer.Serialize(new {
            passed = true, graph.Context, repositories = graph.Repositories.Length, nodes = graph.Nodes.Length, edges = graph.Edges.Length,
            evidence = graph.Evidence.Length, edgeKinds = graph.Edges.GroupBy(edge => edge.Kind).ToDictionary(group => group.Key, group => group.Count()),
            states, captures, nativeVectorLayout = pane.HasNativeLayout, interactiveLayout = pane.HasInteractiveLayoutAcknowledgement,
            reportUnchanged = exportSelection?.ReportHash == graph.Context.ReportHash, providerCalls = 0, newScans = 0,
            scope = "Real retained report, actual frozen action + native host + hosted page captures and vector export. Missing-asset probing runs in a separate disposable process. Manual OS/accessibility gates separate."
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static async Task<string> DescribeHostedViewport(WebView2 browser) => await browser.ExecuteScriptAsync("JSON.stringify({width:innerWidth,height:innerHeight,ratio:devicePixelRatio,theme:document.documentElement.dataset.theme})");

    private static async Task<string> WaitForHostedViewport(WebView2 browser, FrameworkElement root, ElementTheme expectedTheme)
    {
        string? previous = null;
        int stable = 0;
        for (int attempt = 0; attempt < 30; attempt++)
        {
            root.UpdateLayout();
            await Task.Delay(200);
            string current = await DescribeHostedViewport(browser);
            using var encoded = JsonDocument.Parse(current);
            using var viewport = JsonDocument.Parse(encoded.RootElement.GetString() ?? throw new InvalidDataException("Hosted viewport is unavailable."));
            bool themeMatches = viewport.RootElement.GetProperty("theme").GetString() == expectedTheme.ToString().ToLowerInvariant();
            string state = current + JsonSerializer.Serialize(new { width = Math.Round(browser.ActualWidth, 2), height = Math.Round(browser.ActualHeight, 2) });
            stable = state == previous ? stable + 1 : 0; previous = state;
            if (stable >= 3 && themeMatches && browser.ActualWidth > 0 && browser.ActualHeight > 0) return current;
        }
        throw new InvalidDataException("Hosted viewport did not settle with the requested theme after resize/theme change.");
    }
}
