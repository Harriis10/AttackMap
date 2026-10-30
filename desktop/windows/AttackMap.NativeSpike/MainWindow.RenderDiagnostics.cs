using System.Text;
using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.Web.WebView2.Core;
using Windows.Foundation;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;
using Windows.System;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private StreamWriter? renderDiagnosticsLog;
    private readonly List<Action> renderDiagnosticsCleanup = new();
    private readonly HashSet<WebView2> renderDiagnosticsBrowsers = new();
    private readonly HashSet<CoreWebView2> renderDiagnosticsCores = new();
    private bool renderDiagnosticsStopped, renderDiagnosticsBrushUsed, renderDiagnosticsSpacingUsed, renderDiagnosticsDetailSpacingUsed, renderDiagnosticsDetailBrushUsed;
    private bool renderDiagnosticsDetailRenderActive;
    private bool renderDiagnosticsDetailRootRenderActive;
    private int renderDiagnosticsLostCount;
    private int renderDiagnosticsLifecycleCount;
    private readonly string renderDiagnosticsRunId = Guid.NewGuid().ToString("N");
    private long renderDiagnosticsNavigationRevision;
    private System.Diagnostics.Stopwatch? renderDiagnosticsReportClock;
    private long renderDiagnosticsAwaitingDestination;

    // Explicit opt-in only. JSONL excludes body/source text; F8 may capture Detail pixels. No provider/resource mutation.
    private void InitializeRenderDiagnostics(string[] startup)
    {
        int position = Array.IndexOf(startup, "--render-diagnostics");
        if (position < 0) return;
        try
        {
            if (position + 1 >= startup.Length || !Path.IsPathFullyQualified(startup[position + 1])) return;
            string directory = Path.GetFullPath(startup[position + 1]);
            if (directory.StartsWith("\\\\", StringComparison.Ordinal) || directory.StartsWith("//", StringComparison.Ordinal) ||
                !Directory.Exists(directory) || Directory.EnumerateFileSystemEntries(directory).Any()) return;
            for (string? current = directory; current != null; current = Path.GetDirectoryName(current))
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return;
            renderDiagnosticsLog = new StreamWriter(new FileStream(Path.Combine(directory, "render-diagnostics.jsonl"),
                FileMode.CreateNew, FileAccess.Write, FileShare.Read), new UTF8Encoding(false)) { AutoFlush = true };
            var root = (FrameworkElement)Content;
            RoutedEventHandler loaded = (_, _) => RenderDiagnosticsSnapshot("loaded");
            root.Loaded += loaded;
            renderDiagnosticsCleanup.Add(() => root.Loaded -= loaded);
            TypedEventHandler<NavigationView, NavigationViewSelectionChangedEventArgs> navigation = async (_, _) =>
            {
                try
                {
                    // Yield to the normal selection handler and its first layout turn.
                    await Task.Delay(100);
                    if (!renderDiagnosticsStopped && !actionLifetime.IsCancellationRequested)
                    {
                        RenderDiagnosticsSnapshot("navigation-after-turn");
                        if (renderDiagnosticsAwaitingDestination == generation && renderDiagnosticsReportClock != null)
                        {
                            RenderDiagnosticsWrite("first-destination-acknowledged", new { generation, displayedRun, displayedReadHash,
                                navigationRevision = renderDiagnosticsNavigationRevision,
                                elapsedMilliseconds = renderDiagnosticsReportClock.Elapsed.TotalMilliseconds });
                            renderDiagnosticsAwaitingDestination = 0;
                        }
                    }
                }
                catch (Exception error) { RenderDiagnosticsError("navigation", error); }
            };
            Navigation.SelectionChanged += navigation;
            renderDiagnosticsCleanup.Add(() => Navigation.SelectionChanged -= navigation);
            DiagramWorkspaceView.DiagramActivationEvent activation = (kind, viewKind, selectionRevision, error) => RenderDiagnosticsActivation(kind, viewKind, selectionRevision, error);
            Diagrams.ActivationEvent += activation;
            renderDiagnosticsCleanup.Add(() => Diagrams.ActivationEvent -= activation);
            // QA-only acknowledgment for an explicit click/Enter on an already-selected finding.
            bool previousItemClickEnabled = Findings.IsItemClickEnabled;
            Findings.IsItemClickEnabled = true;
            ItemClickEventHandler findingItemClick = (_, args) =>
            {
                if (!ready || args.ClickedItem is not FixtureFinding finding) return;
                Findings.SelectedItem = finding;
                RenderDiagnosticsWrite("finding-selection", new { generation, displayedRun, displayedReadHash,
                    navigationRevision = renderDiagnosticsNavigationRevision, findingRevision, hasFinding = true });
            };
            Findings.ItemClick += findingItemClick;
            renderDiagnosticsCleanup.Add(() => { Findings.ItemClick -= findingItemClick; Findings.IsItemClickEnabled = previousItemClickEnabled; });
            SelectionChangedEventHandler findingSelection = async (_, _) =>
            {
                try
                {
                    await Task.Delay(100);
                    if (renderDiagnosticsStopped || actionLifetime.IsCancellationRequested) return;
                    var selected = Findings.SelectedItem as FixtureFinding;
                    var root = (FrameworkElement)Content;
                    RenderDiagnosticsWrite("finding-detail-after-turn", new { generation, displayedRun, displayedReadHash,
                        navigationRevision = renderDiagnosticsNavigationRevision, findingRevision,
                        selectedFindingId = selected?.Id,
                        detailMatchesSelection = selected != null && Detail.Text.StartsWith(selected.Id + "\n", StringComparison.Ordinal),
                        detailTextLength = Detail.Text.Length,
                        detail = RenderDiagnosticsText(Detail, root, includeText: false) });
                }
                catch (Exception error) { RenderDiagnosticsError("finding-detail-after-turn", error); }
            };
            Findings.SelectionChanged += findingSelection;
            renderDiagnosticsCleanup.Add(() => Findings.SelectionChanged -= findingSelection);
            RoutedEventHandler detailLoaded = (_, _) => RenderDiagnosticsDetailLifecycle("detail-loaded");
            RoutedEventHandler detailUnloaded = (_, _) => RenderDiagnosticsDetailLifecycle("detail-unloaded");
            SizeChangedEventHandler detailSize = (_, _) => RenderDiagnosticsDetailLifecycle("detail-size-changed");
            EventHandler<object> detailLayout = (_, _) => RenderDiagnosticsDetailLifecycle("detail-layout-updated");
            TypedEventHandler<FrameworkElement, EffectiveViewportChangedEventArgs> detailViewport = (_, args) =>
                RenderDiagnosticsDetailLifecycle("detail-effective-viewport-changed", args.EffectiveViewport);
            EventHandler<ScrollViewerViewChangedEventArgs> inspectorView = (_, _) => RenderDiagnosticsDetailLifecycle("finding-inspector-view-changed");
            Detail.Loaded += detailLoaded; Detail.Unloaded += detailUnloaded; Detail.SizeChanged += detailSize;
            Detail.LayoutUpdated += detailLayout; Detail.EffectiveViewportChanged += detailViewport; FindingInspector.ViewChanged += inspectorView;
            renderDiagnosticsCleanup.Add(() => { Detail.Loaded -= detailLoaded; Detail.Unloaded -= detailUnloaded; Detail.SizeChanged -= detailSize;
                Detail.LayoutUpdated -= detailLayout; Detail.EffectiveViewportChanged -= detailViewport; FindingInspector.ViewChanged -= inspectorView; });
            EventHandler<object> lost = (_, _) =>
            {
                try
                {
                    ++renderDiagnosticsLostCount;
                    RenderDiagnosticsSnapshot("surface-contents-lost");
                }
                catch (Exception error) { RenderDiagnosticsError("surface-contents-lost", error); }
            };
            CompositionTarget.SurfaceContentsLost += lost;
            renderDiagnosticsCleanup.Add(() => CompositionTarget.SurfaceContentsLost -= lost);

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
            var detailRenderAccelerator = new KeyboardAccelerator { Key = VirtualKey.F8, ScopeOwner = root };
            TypedEventHandler<KeyboardAccelerator, KeyboardAcceleratorInvokedEventArgs> detailRenderInvoked = async (_, args) =>
            {
                args.Handled = true;
                await RenderDiagnosticsDetailRender();
            };
            detailRenderAccelerator.Invoked += detailRenderInvoked; root.KeyboardAccelerators.Add(detailRenderAccelerator);
            renderDiagnosticsCleanup.Add(() => { detailRenderAccelerator.Invoked -= detailRenderInvoked; root.KeyboardAccelerators.Remove(detailRenderAccelerator); });
            var accelerator = new KeyboardAccelerator { Key = VirtualKey.F9, ScopeOwner = root };
            TypedEventHandler<KeyboardAccelerator, KeyboardAcceleratorInvokedEventArgs> invoked = async (_, args) =>
            {
                if (renderDiagnosticsStopped || renderDiagnosticsBrushUsed || actionLifetime.IsCancellationRequested) return;
                renderDiagnosticsBrushUsed = true; args.Handled = true;
                try
                {
                    RenderDiagnosticsWrite("f9-invoked", new { generation, displayedRun, displayedReadHash, navigationRevision = renderDiagnosticsNavigationRevision });
                    RenderDiagnosticsSnapshot("f9-before-local-brush");
                    TextBlock target = RenderDiagnosticsTarget(out string targetKind);
                    RenderDiagnosticsWrite("f9-local-brush-target", new { generation, displayedRun, displayedReadHash, navigationRevision = renderDiagnosticsNavigationRevision, targetKind, targetLabel = target.Text, targetName = target.Name });
                    if (target.Foreground is SolidColorBrush old)
                    {
                        // Isolated diagnostic intervention: breaks only the selected label's
                        // (or fallback Heading's) dynamic theme binding; never edit shared resources.
                        target.Foreground = new SolidColorBrush(old.Color) { Opacity = old.Opacity };
                        RenderDiagnosticsWrite("f9-local-brush-replaced", new { generation, displayedRun, displayedReadHash, navigationRevision = renderDiagnosticsNavigationRevision,
                            mutationApplied = true, targetKind, targetLabel = target.Text, targetName = target.Name,
                            scope = "One selected navigation TextBlock or fallback Heading only; diagnostic process only; not a production repair" });
                    }
                    else RenderDiagnosticsWrite("f9-local-brush-skipped", new { generation, displayedRun, displayedReadHash, navigationRevision = renderDiagnosticsNavigationRevision,
                        mutationApplied = false, targetKind, targetLabel = target.Text, targetName = target.Name, reason = "Target foreground is not a SolidColorBrush" });
                    await Task.Delay(100);
                    if (!renderDiagnosticsStopped && !actionLifetime.IsCancellationRequested)
                        RenderDiagnosticsSnapshot("f9-after-local-brush");
                }
                catch (Exception error) { RenderDiagnosticsError("f9", error); }
            };
            accelerator.Invoked += invoked; root.KeyboardAccelerators.Add(accelerator);
            renderDiagnosticsCleanup.Add(() => { accelerator.Invoked -= invoked; root.KeyboardAccelerators.Remove(accelerator); });
            var spacingAccelerator = new KeyboardAccelerator { Key = VirtualKey.F10, ScopeOwner = root };
            TypedEventHandler<KeyboardAccelerator, KeyboardAcceleratorInvokedEventArgs> spacingInvoked = async (_, args) =>
            {
                if (renderDiagnosticsStopped || renderDiagnosticsSpacingUsed || actionLifetime.IsCancellationRequested) return;
                renderDiagnosticsSpacingUsed = true; args.Handled = true;
                try
                {
                    RenderDiagnosticsWrite("f10-invoked", new { generation, displayedRun, displayedReadHash, navigationRevision = renderDiagnosticsNavigationRevision });
                    RenderDiagnosticsSnapshot("f10-before-local-spacing");
                    TextBlock target = RenderDiagnosticsTarget(out string targetKind);
                    int oldSpacing = target.CharacterSpacing, newSpacing = oldSpacing == 0 ? 1 : 0;
                    // One-label content/layout probe only; not a global fast-path workaround
                    // or a claim about the rendering defect's cause.
                    target.CharacterSpacing = newSpacing;
                    RenderDiagnosticsWrite("f10-local-spacing-changed", new { generation, displayedRun, displayedReadHash, navigationRevision = renderDiagnosticsNavigationRevision,
                        mutationApplied = true, targetKind, targetLabel = target.Text, targetName = target.Name, oldSpacing, newSpacing,
                        scope = "One selected navigation TextBlock or fallback Heading only; diagnostic process only" });
                    await Task.Delay(100);
                    if (!renderDiagnosticsStopped && !actionLifetime.IsCancellationRequested)
                        RenderDiagnosticsSnapshot("f10-after-local-spacing");
                }
                catch (Exception error) { RenderDiagnosticsError("f10", error); }
            };
            spacingAccelerator.Invoked += spacingInvoked; root.KeyboardAccelerators.Add(spacingAccelerator);
            renderDiagnosticsCleanup.Add(() => { spacingAccelerator.Invoked -= spacingInvoked; root.KeyboardAccelerators.Remove(spacingAccelerator); });
            var detailSpacingAccelerator = new KeyboardAccelerator { Key = VirtualKey.F11, ScopeOwner = root };
            TypedEventHandler<KeyboardAccelerator, KeyboardAcceleratorInvokedEventArgs> detailSpacingInvoked = async (_, args) =>
            {
                if (renderDiagnosticsStopped || renderDiagnosticsDetailSpacingUsed || actionLifetime.IsCancellationRequested) return;
                renderDiagnosticsDetailSpacingUsed = true; args.Handled = true;
                try
                {
                    var selected = Findings.SelectedItem as FixtureFinding;
                    RenderDiagnosticsWrite("f11-before-detail-spacing", new { generation, displayedRun, displayedReadHash,
                        navigationRevision = renderDiagnosticsNavigationRevision, findingRevision, selectedFindingId = selected?.Id,
                        detail = RenderDiagnosticsText(Detail, root, includeText: false) });
                    int oldSpacing = Detail.CharacterSpacing, newSpacing = oldSpacing == 0 ? 1 : 0;
                    // QA-only single-control layout invalidation. Never mutate shared resources or other text.
                    Detail.CharacterSpacing = newSpacing;
                    RenderDiagnosticsWrite("f11-detail-spacing-changed", new { generation, displayedRun, displayedReadHash,
                        navigationRevision = renderDiagnosticsNavigationRevision, findingRevision, mutationApplied = true,
                        targetKind = "Finding detail", targetName = Detail.Name, oldSpacing, newSpacing,
                        scope = "Detail TextBlock only; diagnostic process only; not a production repair" });
                    await Task.Delay(100);
                    if (!renderDiagnosticsStopped && !actionLifetime.IsCancellationRequested)
                        RenderDiagnosticsWrite("f11-after-detail-spacing", new { generation, displayedRun, displayedReadHash,
                            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision, selectedFindingId = selected?.Id,
                            detail = RenderDiagnosticsText(Detail, root, includeText: false) });
                }
                catch (Exception error) { RenderDiagnosticsError("f11-detail-spacing", error); }
            };
            detailSpacingAccelerator.Invoked += detailSpacingInvoked; root.KeyboardAccelerators.Add(detailSpacingAccelerator);
            renderDiagnosticsCleanup.Add(() => { detailSpacingAccelerator.Invoked -= detailSpacingInvoked; root.KeyboardAccelerators.Remove(detailSpacingAccelerator); });
            var detailBrushAccelerator = new KeyboardAccelerator { Key = VirtualKey.F12, ScopeOwner = root };
            TypedEventHandler<KeyboardAccelerator, KeyboardAcceleratorInvokedEventArgs> detailBrushInvoked = async (_, args) =>
            {
                if (renderDiagnosticsStopped || renderDiagnosticsDetailBrushUsed || actionLifetime.IsCancellationRequested) return;
                renderDiagnosticsDetailBrushUsed = true; args.Handled = true;
                try
                {
                    var selected = Findings.SelectedItem as FixtureFinding;
                    RenderDiagnosticsWrite("f12-before-detail-brush", new { generation, displayedRun, displayedReadHash,
                        navigationRevision = renderDiagnosticsNavigationRevision, findingRevision, selectedFindingId = selected?.Id,
                        detail = RenderDiagnosticsText(Detail, root, includeText: false) });
                    if (Detail.Foreground is not SolidColorBrush old)
                    {
                        RenderDiagnosticsWrite("f12-detail-brush-skipped", new { generation, displayedRun, displayedReadHash,
                            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision, mutationApplied = false,
                            targetName = Detail.Name, reason = "Detail foreground is not a SolidColorBrush" });
                        return;
                    }
                    // QA-only same-color local brush replacement; no spacing or shared-resource mutation.
                    Detail.Foreground = new SolidColorBrush(old.Color) { Opacity = old.Opacity };
                    RenderDiagnosticsWrite("f12-detail-brush-replaced", new { generation, displayedRun, displayedReadHash,
                        navigationRevision = renderDiagnosticsNavigationRevision, findingRevision, mutationApplied = true,
                        targetKind = "Finding detail", targetName = Detail.Name,
                        color = $"#{old.Color.A:X2}{old.Color.R:X2}{old.Color.G:X2}{old.Color.B:X2}", old.Opacity,
                        scope = "Detail TextBlock only; diagnostic process only; not a production repair" });
                    await Task.Delay(100);
                    if (!renderDiagnosticsStopped && !actionLifetime.IsCancellationRequested)
                        RenderDiagnosticsWrite("f12-after-detail-brush", new { generation, displayedRun, displayedReadHash,
                            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision, selectedFindingId = selected?.Id,
                            detail = RenderDiagnosticsText(Detail, root, includeText: false) });
                }
                catch (Exception error) { RenderDiagnosticsError("f12-detail-brush", error); }
            };
            detailBrushAccelerator.Invoked += detailBrushInvoked; root.KeyboardAccelerators.Add(detailBrushAccelerator);
            renderDiagnosticsCleanup.Add(() => { detailBrushAccelerator.Invoked -= detailBrushInvoked; root.KeyboardAccelerators.Remove(detailBrushAccelerator); });
            void closed(object sender, WindowEventArgs args) => StopRenderDiagnostics();
            Closed += closed;
            renderDiagnosticsCleanup.Add(() => Closed -= closed);
            RenderDiagnosticsWrite("enabled", new { processId = Environment.ProcessId,
                scope = "Native heading/navigation/Detail state and WebView2 lifecycle; JSONL excludes body/source text; explicit F7 writes D/T PNG pixels; explicit F8 writes Detail PNG pixels",
                f7 = "Non-mutating direct Detail and root RenderTargetBitmap pair; QA observation only",
                f8 = "Non-mutating direct Detail RenderTargetBitmap capture without layout or frame settling; QA observation only",
                f9 = "One-shot selected navigation label-local same-color fresh brush; Heading fallback if no rendered exact label",
                f10 = "Independent one-shot selected navigation label CharacterSpacing toggle 0/1; same target lookup and Heading fallback",
                f11 = "Independent one-shot Detail TextBlock CharacterSpacing toggle 0/1 with bounded before/after state",
                f12 = "Independent one-shot Detail TextBlock same-color fresh brush with bounded before/after state",
                detailLifecycle = "Non-mutating Loaded/Unloaded/SizeChanged/LayoutUpdated/EffectiveViewportChanged and inspector ViewChanged; bounded at 400 events" });
        }
        catch (Exception) { StopRenderDiagnostics(); } // Optional diagnostics never block startup.
    }

    private async Task RenderDiagnosticsDetailRender()
    {
        if (renderDiagnosticsStopped || renderDiagnosticsLog == null || renderDiagnosticsDetailRenderActive || actionLifetime.IsCancellationRequested) return;
        renderDiagnosticsDetailRenderActive = true;
        long currentGeneration = generation, currentFindingRevision = findingRevision;
        string probeId = Guid.NewGuid().ToString("N");
        string? temporary = null;
        int renderingFrames = 0;
        EventHandler<object> rendering = (_, _) => ++renderingFrames;
        double scale = Detail.XamlRoot?.RasterizationScale ?? 0;
        try
        {
            RenderDiagnosticsWrite("detail-render-capture-started", new { probeId,
                generation = currentGeneration, displayedRun, displayedReadHash,
                navigationRevision = renderDiagnosticsNavigationRevision, findingRevision = currentFindingRevision,
                detailLoaded = Detail.IsLoaded, detailWidth = Detail.ActualWidth, detailHeight = Detail.ActualHeight, scale,
                inspector = new { horizontalOffset = FindingInspector.HorizontalOffset,
                    verticalOffset = FindingInspector.VerticalOffset, extentHeight = FindingInspector.ExtentHeight,
                    viewportHeight = FindingInspector.ViewportHeight } });
            CompositionTarget.Rendering += rendering;
            if (!Detail.DispatcherQueue.HasThreadAccess || !Detail.IsLoaded || Detail.XamlRoot == null ||
                Detail.ActualWidth <= 0 || Detail.ActualHeight <= 0 || FindingsPanel.Visibility != Visibility.Visible ||
                Findings.SelectedItem is not FixtureFinding || !double.IsFinite(scale) || scale <= 0)
                throw new InvalidOperationException("Detail render requires a loaded visible bound finding on the owning dispatcher.");
            string directory = Path.GetDirectoryName(renderDiagnosticsLog.BaseStream is FileStream stream ? stream.Name : null)
                ?? throw new InvalidOperationException("Diagnostics output directory is unavailable.");
            string fileName = "detail-render-" + probeId + ".png";
            string output = Path.Combine(directory, fileName);
            var bitmap = new RenderTargetBitmap();
            await bitmap.RenderAsync(Detail);
            int width = bitmap.PixelWidth, height = bitmap.PixelHeight;
            if (width <= 0 || height <= 0 || width > 16384 || height > 16384 ||
                (long)width * height * 4 > CaptureOracle.MaxBytes)
                throw new InvalidDataException("Rendered Detail is empty or exceeds the bounded capture size.");
            var pixels = await bitmap.GetPixelsAsync();
            if (pixels.Length != (long)width * height * 4) throw new InvalidDataException("Unexpected Detail BGRA8 buffer size.");
            if (generation != currentGeneration || findingRevision != currentFindingRevision || renderDiagnosticsStopped ||
                actionLifetime.IsCancellationRequested || !Detail.IsLoaded || Detail.XamlRoot == null)
                throw new InvalidOperationException("Detail render context changed before PNG encoding.");
            var raw = new byte[(int)pixels.Length];
            using (var reader = DataReader.FromBuffer(pixels)) reader.ReadBytes(raw);
            using var encoded = new InMemoryRandomAccessStream();
            var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, encoded);
            encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied,
                (uint)width, (uint)height, 96 * scale, 96 * scale, raw);
            await encoder.FlushAsync();
            if (encoded.Size > CaptureOracle.MaxBytes) throw new InvalidDataException("Encoded Detail PNG exceeds the capture limit.");
            encoded.Seek(0);
            var png = new byte[(int)encoded.Size];
            using (var reader = new DataReader(encoded.GetInputStreamAt(0)))
            {
                if (await reader.LoadAsync((uint)png.Length) != png.Length) throw new IOException("Encoded Detail PNG read was incomplete.");
                reader.ReadBytes(png);
            }
            if (generation != currentGeneration || findingRevision != currentFindingRevision || renderDiagnosticsStopped ||
                actionLifetime.IsCancellationRequested || !Detail.IsLoaded || Detail.XamlRoot == null)
                throw new InvalidOperationException("Detail render context changed before PNG commit.");
            temporary = Path.Combine(directory, ".detail-render-" + probeId + ".tmp");
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { await file.WriteAsync(png); file.Flush(flushToDisk: true); }
            File.Move(temporary, output, overwrite: false); temporary = null;
            RenderDiagnosticsWrite("detail-render-capture-completed", new { probeId,
                generation = currentGeneration, displayedRun, displayedReadHash,
                navigationRevision = renderDiagnosticsNavigationRevision, findingRevision = currentFindingRevision,
                fileName, width, height, scale, renderingFrames });
        }
        catch (Exception error)
        {
            RenderDiagnosticsWrite("detail-render-capture-failed", new { probeId,
                generation = currentGeneration, displayedRun, displayedReadHash,
                navigationRevision = renderDiagnosticsNavigationRevision, findingRevision = currentFindingRevision,
                errorType = error.GetType().Name, renderingFrames });
        }
        finally
        {
            CompositionTarget.Rendering -= rendering;
            renderDiagnosticsDetailRenderActive = false;
            if (temporary != null)
                try { if (File.Exists(temporary)) File.Delete(temporary); } catch (Exception) { }
        }
    }

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

    private void RenderDiagnosticsSnapshot(string reason)
    {
        if (renderDiagnosticsStopped || renderDiagnosticsLog == null || actionLifetime.IsCancellationRequested) return;
        try
        {
            var root = (FrameworkElement)Content;
            RenderDiagnosticsAttachBrowsers(root);
            var navigation = Navigation.MenuItems.OfType<NavigationViewItem>().Select(item => new {
                label = item.Content is string title ? title : "nontext menu item",
                selected = item.IsSelected,
                text = RenderDiagnosticsChildren(item).OfType<TextBlock>().Select(block => RenderDiagnosticsText(block, root)).ToArray()
            }).ToArray();
            string selectedDestination = ReferenceEquals(Navigation.SelectedItem, Navigation.SettingsItem)
                ? "Settings"
                : (Navigation.SelectedItem as NavigationViewItem)?.Content?.ToString() ?? "";
            RenderDiagnosticsWrite(reason, new { heading = RenderDiagnosticsText(Heading, root), headingText = Heading.Text,
                navigation, selectedDestination, generation, displayedRun, displayedReadHash,
                navigationRevision = renderDiagnosticsNavigationRevision,
                browserControls = renderDiagnosticsBrowsers.Count, initializedBrowserCores = renderDiagnosticsCores.Count,
                rootTheme = root.ActualTheme.ToString(), rootScale = root.XamlRoot?.RasterizationScale,
                rootWidth = root.ActualWidth, rootHeight = root.ActualHeight, rootLoaded = root.IsLoaded });
        }
        catch (Exception error) { RenderDiagnosticsError("snapshot", error); }
    }

    private TextBlock RenderDiagnosticsTarget(out string targetKind)
    {
        targetKind = "Heading fallback";
        if (Navigation.SelectedItem is NavigationViewItem item && item.Content is string label)
        {
            var text = RenderDiagnosticsChildren(item).OfType<TextBlock>().FirstOrDefault(block =>
                block.Text == label && block.IsLoaded && block.Visibility == Visibility.Visible && block.ActualWidth > 0 && block.ActualHeight > 0);
            if (text != null) { targetKind = "Selected navigation label"; return text; }
        }
        return Heading;
    }

    private void RenderDiagnosticsDetailLifecycle(string stage, Rect? effectiveViewport = null)
    {
        if (renderDiagnosticsStopped || renderDiagnosticsLog == null) return;
        // Preserve the bounded event budget for the actual finding-detail workflow.
        if (FindingsPanel.Visibility != Visibility.Visible || Findings.SelectedItem is not FixtureFinding) return;
        if (renderDiagnosticsLifecycleCount >= 400)
        {
            if (renderDiagnosticsLifecycleCount == 400)
                RenderDiagnosticsWrite("detail-lifecycle-truncated", new { limit = 400 });
            ++renderDiagnosticsLifecycleCount;
            return;
        }
        ++renderDiagnosticsLifecycleCount;
        try
        {
            var selected = Findings.SelectedItem as FixtureFinding;
            var root = (FrameworkElement)Content;
            RenderDiagnosticsWrite(stage, new { generation, displayedRun, displayedReadHash,
                navigationRevision = renderDiagnosticsNavigationRevision, findingRevision,
                lifecycleEvent = renderDiagnosticsLifecycleCount, selectedFindingId = selected?.Id,
                detailMatchesSelection = selected != null && Detail.Text.StartsWith(selected.Id + "\n", StringComparison.Ordinal),
                detailLoaded = Detail.IsLoaded, detail = RenderDiagnosticsText(Detail, root, includeText: false),
                inspector = new { loaded = FindingInspector.IsLoaded, width = FindingInspector.ActualWidth,
                    height = FindingInspector.ActualHeight, horizontalOffset = FindingInspector.HorizontalOffset,
                    verticalOffset = FindingInspector.VerticalOffset, extentHeight = FindingInspector.ExtentHeight,
                    viewportHeight = FindingInspector.ViewportHeight, scrollableHeight = FindingInspector.ScrollableHeight },
                effectiveViewport = effectiveViewport is Rect rect ? new { rect.X, rect.Y, rect.Width, rect.Height } : null });
        }
        catch (Exception error) { RenderDiagnosticsError("detail-lifecycle", error); }
    }

    private static object RenderDiagnosticsText(TextBlock block, FrameworkElement root, bool includeText = true)
    {
        object? bounds = null;
        try
        {
            Rect rect = block.TransformToVisual(root).TransformBounds(new Rect(0, 0, block.ActualWidth, block.ActualHeight));
            bounds = new { rect.X, rect.Y, rect.Width, rect.Height };
        }
        catch (Exception) { }
        var parents = new List<object>();
        bool effectiveVisible = block.Visibility == Visibility.Visible;
        double effectiveOpacity = block.Opacity;
        for (DependencyObject? parent = VisualTreeHelper.GetParent(block); parent != null && parents.Count < 32; parent = VisualTreeHelper.GetParent(parent))
            if (parent is FrameworkElement element)
            {
                parents.Add(new { type = element.GetType().Name, element.Name, width = element.ActualWidth,
                    height = element.ActualHeight, visibility = element.Visibility.ToString(), element.Opacity });
                effectiveVisible &= element.Visibility == Visibility.Visible;
                effectiveOpacity *= element.Opacity;
            }
        var solid = block.Foreground as SolidColorBrush;
        return new { block.Name, text = includeText ? block.Text : null, textLength = block.Text.Length, width = block.ActualWidth, height = block.ActualHeight,
            visibility = block.Visibility.ToString(), block.Opacity, effectiveVisible, effectiveOpacity, block.CharacterSpacing,
            theme = block.ActualTheme.ToString(), foregroundType = block.Foreground?.GetType().Name,
            foregroundColor = solid == null ? null : $"#{solid.Color.A:X2}{solid.Color.R:X2}{solid.Color.G:X2}{solid.Color.B:X2}",
            brushOpacity = block.Foreground?.Opacity, bounds, parents };
    }

    private static IEnumerable<DependencyObject> RenderDiagnosticsChildren(DependencyObject root)
    {
        var pending = new Stack<DependencyObject>(); pending.Push(root);
        int visited = 0;
        while (pending.Count > 0 && visited++ < 20000)
        {
            var current = pending.Pop(); yield return current;
            for (int index = VisualTreeHelper.GetChildrenCount(current) - 1; index >= 0; --index)
                pending.Push(VisualTreeHelper.GetChild(current, index));
        }
    }

    private void RenderDiagnosticsAttachBrowsers(FrameworkElement root)
    {
        foreach (var browser in RenderDiagnosticsChildren(root).OfType<WebView2>())
        {
            if (renderDiagnosticsBrowsers.Add(browser))
            {
                TypedEventHandler<WebView2, CoreWebView2InitializedEventArgs> initialized = (_, args) =>
                {
                    try
                    {
                        RenderDiagnosticsWrite("webview-initialized", new { generation, displayedRun, displayedReadHash,
                            navigationRevision = renderDiagnosticsNavigationRevision, success = args.Exception == null,
                            errorType = args.Exception?.GetType().Name, width = browser.ActualWidth, height = browser.ActualHeight });
                        RenderDiagnosticsAttachCore(browser);
                    }
                    catch (Exception error) { RenderDiagnosticsError("webview-initialized", error); }
                };
                browser.CoreWebView2Initialized += initialized;
                renderDiagnosticsCleanup.Add(() => browser.CoreWebView2Initialized -= initialized);
            }
            RenderDiagnosticsAttachCore(browser);
        }
    }

    private void RenderDiagnosticsAttachCore(WebView2 browser)
    {
        var core = browser.CoreWebView2;
        if (core == null || !renderDiagnosticsCores.Add(core)) return;
        RenderDiagnosticsWrite("webview-core-observed", RenderDiagnosticsBrowser(browser, core));
        TypedEventHandler<CoreWebView2, CoreWebView2ProcessFailedEventArgs> failed = (_, args) =>
        {
            try { RenderDiagnosticsWrite("webview-process-failed", new { kind = args.ProcessFailedKind.ToString(),
                reason = args.Reason.ToString(), exitCode = args.ExitCode, browser = RenderDiagnosticsBrowser(browser, core) }); }
            catch (Exception error) { RenderDiagnosticsError("webview-process-failed", error); }
        };
        core.ProcessFailed += failed;
        renderDiagnosticsCleanup.Add(() => core.ProcessFailed -= failed);
    }

    private static object RenderDiagnosticsBrowser(WebView2 browser, CoreWebView2 core) => new {
        browserVersion = core.Environment.BrowserVersionString, browserProcessId = core.BrowserProcessId,
        userDataFolder = core.Environment.UserDataFolder, width = browser.ActualWidth, height = browser.ActualHeight,
        visibility = browser.Visibility.ToString(), browser.Opacity };

    private void RenderDiagnosticsReportStarted(long current)
    {
        renderDiagnosticsReportClock = System.Diagnostics.Stopwatch.StartNew();
        renderDiagnosticsAwaitingDestination = 0;
        RenderDiagnosticsWrite("report-load-started", new { generation = current, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, elapsedMilliseconds = 0.0,
            initialReportReadCount = 0, projectionCounts = new { report = 0, sections = 0, overview = 0 } });
    }

    private void RenderDiagnosticsReportBindCompleted(long current) => renderDiagnosticsAwaitingDestination = current;

    private void RenderDiagnosticsCapture(CaptureMetadata capture, string filename)
    {
        var failed = capture.Assessment.Regions.Where(region => region.Failure != null).Select(region => region.Name).ToArray();
        RenderDiagnosticsWrite("capture-attempt", new { generation, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, filename,
            outcome = capture.Assessment.Passed ? "passed" : "failed", oracleFailure = capture.Assessment.Failure,
            failedRegionNames = failed, failedRegionCount = failed.Length, captureScope = capture.Scope });
    }

    private void RenderDiagnosticsActivation(string kind, string viewKind, long selectionRevision, Exception? error = null) =>
        RenderDiagnosticsWrite(kind, new { generation, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, viewKind, selectionRevision,
            graphLoadCount = Diagrams.GraphLoadCount, legacySelectionLoadCount = Diagrams.LegacySelectionLoadCount,
            interactiveInitializationAttemptCount = Diagrams.InteractiveInitializationAttemptCount,
            initializedWebView2CoreCount = renderDiagnosticsCores.Count,
            errorType = error?.GetType().Name, errorMessage = error?.Message });

    private void RenderDiagnosticsWrite(string kind, object detail)
    {
        if (renderDiagnosticsStopped || renderDiagnosticsLog == null) return;
        try { renderDiagnosticsLog.WriteLine(JsonSerializer.Serialize(new { at = DateTimeOffset.UtcNow,
            runId = renderDiagnosticsRunId, kind, surfaceContentsLostCount = renderDiagnosticsLostCount, detail })); }
        catch (Exception) { } // A log failure must not affect the UI under investigation.
    }

    private void RenderDiagnosticsError(string stage, Exception error) =>
        RenderDiagnosticsWrite("diagnostic-error", new { stage, errorType = error.GetType().Name });

    private void StopRenderDiagnostics()
    {
        if (renderDiagnosticsStopped) return;
        RenderDiagnosticsWrite("closed", new { }); renderDiagnosticsStopped = true;
        foreach (var cleanup in renderDiagnosticsCleanup.AsEnumerable().Reverse())
            try { cleanup(); } catch (Exception) { }
        renderDiagnosticsCleanup.Clear(); renderDiagnosticsBrowsers.Clear(); renderDiagnosticsCores.Clear();
        try { renderDiagnosticsLog?.Dispose(); } catch (Exception) { }
        renderDiagnosticsLog = null;
    }
}
