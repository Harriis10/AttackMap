### Task 1: Native F7 Detail + Root Pair

**Files:**
- Modify: `desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs`
- Test: `tests/test_wp043_live_capture.py`

**Interfaces:**
- Consumes: existing `Detail`, `Content`, `FindingsPanel`, `Findings`, `generation`, `findingRevision`, `RenderDiagnosticsWrite`, `CaptureOracle.MaxBytes`.
- Produces: `RenderDiagnosticsDetailRootRender()` and events `detail-root-render-capture-started`, `detail-root-render-capture-completed`, `detail-root-render-capture-failed`. Completed metadata contains `probeId`, `detailFileName`, `rootFileName`, `detailWidth`, `detailHeight`, `rootWidth`, `rootHeight`, `scale`, `renderingFrames`, and bound context fields.

- [ ] **Step 1: Add the failing native source-gate test**

Append this test beside the F8 source gate:

```python
def test_detail_root_render_probe_rasterizes_both_targets_without_settling_or_mutation(self):
    source = (Path(__file__).parents[1] / "desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs").read_text(encoding="utf-8")
    self.assertIn("private async Task RenderDiagnosticsDetailRootRender()", source)
    method = source.split("private async Task RenderDiagnosticsDetailRootRender()", 1)[1]
    method = method.split("private void RenderDiagnosticsSnapshot", 1)[0]
    self.assertIn("await bitmap.RenderAsync(target);", method)
    self.assertIn("await Capture(Detail, \"detail\");", method)
    self.assertIn("await Capture(root, \"root\");", method)
    self.assertEqual(method.count("await bitmap.GetPixelsAsync();"), 1)
    self.assertIn("CompositionTarget.Rendering -= rendering;", method)
    for forbidden in (
        "UpdateLayout", "Task.Delay", "Detail.Text =", "Detail.Foreground =",
        "Detail.CharacterSpacing =", "Detail.Visibility =", "Detail.Opacity =",
        "root.Visibility =", "root.Opacity =", "ChangeView(",
    ):
        self.assertNotIn(forbidden, method)
```

- [ ] **Step 2: Verify RED**

Run: `./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k detail_root_render_probe_rasterizes`
Expected: one failure because `RenderDiagnosticsDetailRootRender` does not exist.

- [ ] **Step 3: Register F7 without changing F8**

Immediately before the existing F8 accelerator registration, add:

```csharp
var detailRootRenderAccelerator = new KeyboardAccelerator { Key = VirtualKey.F7, ScopeOwner = root };
TypedEventHandler<KeyboardAccelerator, KeyboardAcceleratorInvokedEventArgs> detailRootRenderInvoked = async (_, args) =>
{
    args.Handled = true;
    await RenderDiagnosticsDetailRootRender();
};
detailRootRenderAccelerator.Invoked += detailRootRenderInvoked;
root.KeyboardAccelerators.Add(detailRootRenderAccelerator);
renderDiagnosticsCleanup.Add(() =>
{
    detailRootRenderAccelerator.Invoked -= detailRootRenderInvoked;
    root.KeyboardAccelerators.Remove(detailRootRenderAccelerator);
});
```

Add `private bool renderDiagnosticsDetailRootRenderActive;` beside the F8 active flag. Extend only the `enabled` metadata with `f7 = "Non-mutating direct Detail and root RenderTargetBitmap pair; QA observation only"` and update the scope string to mention F7 D/T PNG pixels. Do not edit the F8 handler or method.

- [ ] **Step 4: Implement the bounded pair capture**

Insert this method immediately before `RenderDiagnosticsSnapshot`. It intentionally uses one local helper so Detail and root share exactly the same validation and encoding path:

```csharp
private async Task RenderDiagnosticsDetailRootRender()
{
    if (renderDiagnosticsStopped || renderDiagnosticsLog == null || renderDiagnosticsDetailRootRenderActive || actionLifetime.IsCancellationRequested) return;
    renderDiagnosticsDetailRootRenderActive = true;
    long currentGeneration = generation, currentFindingRevision = findingRevision;
    string probeId = Guid.NewGuid().ToString("N");
    int renderingFrames = 0;
    EventHandler<object> rendering = (_, _) => ++renderingFrames;
    var root = (FrameworkElement)Content;
    double scale = Detail.XamlRoot?.RasterizationScale ?? 0;
    string directory = "";
    try
    {
        RenderDiagnosticsWrite("detail-root-render-capture-started", new { probeId,
            generation = currentGeneration, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision = currentFindingRevision,
            detailLoaded = Detail.IsLoaded, detailWidth = Detail.ActualWidth, detailHeight = Detail.ActualHeight,
            rootLoaded = root.IsLoaded, rootWidth = root.ActualWidth, rootHeight = root.ActualHeight, scale });
        CompositionTarget.Rendering += rendering;
        if (!Detail.DispatcherQueue.HasThreadAccess || !Detail.IsLoaded || Detail.XamlRoot == null ||
            !root.IsLoaded || root.XamlRoot == null || Detail.ActualWidth <= 0 || Detail.ActualHeight <= 0 ||
            root.ActualWidth <= 0 || root.ActualHeight <= 0 || root.Visibility != Visibility.Visible ||
            FindingsPanel.Visibility != Visibility.Visible || Findings.SelectedItem is not FixtureFinding ||
            !double.IsFinite(scale) || scale <= 0)
            throw new InvalidOperationException("Detail/root render requires loaded visible bound content on the owning dispatcher.");
        directory = Path.GetDirectoryName(renderDiagnosticsLog.BaseStream is FileStream stream ? stream.Name : null)
            ?? throw new InvalidOperationException("Diagnostics output directory is unavailable.");

        void RequireContext()
        {
            if (generation != currentGeneration || findingRevision != currentFindingRevision || renderDiagnosticsStopped ||
                actionLifetime.IsCancellationRequested || !Detail.IsLoaded || Detail.XamlRoot == null || !root.IsLoaded || root.XamlRoot == null)
                throw new InvalidOperationException("Detail/root render context changed.");
        }

        async Task<(string FileName, int Width, int Height)> Capture(FrameworkElement target, string targetKind)
        {
            string? temporary = null;
            try
            {
                RequireContext();
                var bitmap = new RenderTargetBitmap();
                await bitmap.RenderAsync(target);
                int width = bitmap.PixelWidth, height = bitmap.PixelHeight;
                if (width <= 0 || height <= 0 || width > 16384 || height > 16384 ||
                    (long)width * height * 4 > CaptureOracle.MaxBytes)
                    throw new InvalidDataException("Rendered target is empty or exceeds the bounded capture size.");
                var pixels = await bitmap.GetPixelsAsync();
                if (pixels.Length != (long)width * height * 4) throw new InvalidDataException("Unexpected BGRA8 buffer size.");
                RequireContext();
                var raw = new byte[(int)pixels.Length];
                using (var reader = DataReader.FromBuffer(pixels)) reader.ReadBytes(raw);
                using var encoded = new InMemoryRandomAccessStream();
                var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, encoded);
                encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied,
                    (uint)width, (uint)height, 96 * scale, 96 * scale, raw);
                await encoder.FlushAsync();
                if (encoded.Size > CaptureOracle.MaxBytes) throw new InvalidDataException("Encoded PNG exceeds the capture limit.");
                var png = new byte[(int)encoded.Size];
                using (var reader = new DataReader(encoded.GetInputStreamAt(0)))
                {
                    if (await reader.LoadAsync((uint)png.Length) != png.Length) throw new IOException("Encoded PNG read was incomplete.");
                    reader.ReadBytes(png);
                }
                RequireContext();
                string fileName = $"detail-root-render-{targetKind}-{probeId}.png";
                temporary = Path.Combine(directory, $".detail-root-render-{targetKind}-{probeId}.tmp");
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { await file.WriteAsync(png); file.Flush(flushToDisk: true); }
                File.Move(temporary, Path.Combine(directory, fileName), overwrite: false);
                temporary = null;
                return (fileName, width, height);
            }
            finally
            {
                if (temporary != null)
                    try { if (File.Exists(temporary)) File.Delete(temporary); } catch (Exception) { }
            }
        }

        var detail = await Capture(Detail, "detail");
        RequireContext();
        var tree = await Capture(root, "root");
        RequireContext();
        RenderDiagnosticsWrite("detail-root-render-capture-completed", new { probeId,
            generation = currentGeneration, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision = currentFindingRevision,
            detailFileName = detail.FileName, rootFileName = tree.FileName,
            detailWidth = detail.Width, detailHeight = detail.Height,
            rootWidth = tree.Width, rootHeight = tree.Height, scale, renderingFrames });
    }
    catch (Exception error)
    {
        RenderDiagnosticsWrite("detail-root-render-capture-failed", new { probeId,
            generation = currentGeneration, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision = currentFindingRevision,
            errorType = error.GetType().Name, renderingFrames });
    }
    finally
    {
        CompositionTarget.Rendering -= rendering;
        renderDiagnosticsDetailRootRenderActive = false;
    }
}
```

- [ ] **Step 5: Verify GREEN and unchanged F8 tests**

Run: `./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k "detail_root_render_probe_rasterizes or detail_render_probe_directly"`
Expected: 2 passed. Compile is deferred until runner tests are green; no live process is started.

---

