using System.Text.Json;
using AttackMap.GraphExplorer;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    // Run on the owning UI thread with an attached panel. This checks the actual
    // missing-asset host fallback event, without screenshots or an extra window.
    private async Task RunGraphFallbackCheck(Panel host, byte[] graph, GraphContext context, string output)
    {
        if (!host.IsLoaded) throw new InvalidOperationException("Graph fallback probe requires a loaded host panel.");
        _ = GraphReader.Read(graph, context);
        var probe = new GraphWebView(Path.Combine(Path.GetDirectoryName(Path.GetFullPath(output))!,
            "missing-graph-assets-" + Guid.NewGuid().ToString("N")))
        { Width = 640, Height = 360, Opacity = 0, IsHitTestVisible = false,
            HorizontalAlignment = Microsoft.UI.Xaml.HorizontalAlignment.Left,
            VerticalAlignment = Microsoft.UI.Xaml.VerticalAlignment.Top };
        var fallback = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        int fallbackCount = 0;
        probe.FallbackShown += message => { fallbackCount++; fallback.TrySetResult(message); };
        try
        {
            if (host is Grid grid && grid.RowDefinitions.Count > 0) Grid.SetRow(probe, grid.RowDefinitions.Count - 1);
            host.Children.Add(probe);
            await probe.LoadGraph(graph, context);
            string message = await fallback.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (fallbackCount == 0 || probe.LayoutAcknowledgedContext != null)
                throw new InvalidOperationException("Missing graph assets did not clear layout acknowledgement and emit the host fallback event.");
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            File.WriteAllText(output, JsonSerializer.Serialize(new
            {
                schema_version = "1.0", status = "PASS", fallback_event_count = fallbackCount,
                message, layout_acknowledged = false,
                scope = "Actual missing-asset GraphWebView fallback event only; no rendering, screenshots, provider calls or release acceptance."
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        finally
        {
            probe.Stop();
            host.Children.Remove(probe);
        }
    }
}
