using System.Security.Cryptography;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;

namespace AttackMap.NativeSpike;

public sealed record CaptureMetadata(int Width, int Height, double Scale, double LogicalWidth,
    double LogicalHeight, string Theme, string OutputPath, string Sha256, DateTimeOffset CapturedAt,
    CaptureAssessment Assessment, string Scope);

public sealed class CaptureValidationException : Exception
{
    public CaptureValidationException(string message, CaptureMetadata metadata) : base(message) => Metadata = metadata;
    public CaptureMetadata Metadata { get; }
}

/// <summary>Caller-owned QA hook: captures only a loaded in-process WinUI visual tree.</summary>
public static class NativeCaptureProbe
{
    public const string Scope = "In-process WinUI RenderTargetBitmap content after dispatcher, layout-quiet and three-rendering-frame settling. Strict captures check required-region ink; this is not OCR and does not prove correctness of all glyphs or independent live-window rendering. Composition-backed effects/surfaces, transparency, theme transitions and selection visuals may be omitted or differ from the displayed window; capture anomalies require independent live-window verification before being classified as UI defects. Excludes window chrome, other apps, desktop, popups outside this tree, Narrator and OS appearance/scaling acceptance. A PNG is visual review material, not C24/C25 acceptance.";

    public static async Task<CaptureMetadata> Capture(FrameworkElement root, string absolutePngPath,
        bool requireVisibleContent = false, IReadOnlyList<CaptureRegion>? requiredText = null)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (requireVisibleContent && (requiredText is null || requiredText.Count == 0))
            throw new ArgumentException("Strict capture requires at least one required text region.", nameof(requiredText));
        if (!root.DispatcherQueue.HasThreadAccess) throw new InvalidOperationException("Capture must be called on the owning WinUI thread.");
        if (root.XamlRoot == null || !root.IsLoaded || root.ActualWidth <= 0 || root.ActualHeight <= 0)
            throw new InvalidOperationException("Capture requires loaded, laid-out app content.");
        if (!Path.IsPathFullyQualified(absolutePngPath) || absolutePngPath.StartsWith(@"\\", StringComparison.Ordinal) ||
            !string.Equals(Path.GetExtension(absolutePngPath), ".png", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Provide an absolute local PNG path in the caller-owned workspace QA directory.");
        string output = Path.GetFullPath(absolutePngPath), directory = Path.GetDirectoryName(output)!;
        CheckDirectory(directory);
        if (File.Exists(output) || Directory.Exists(output)) throw new IOException("Capture output already exists; use a fresh QA path.");
        await SettleRendering(root);
        if (!root.IsLoaded || root.XamlRoot == null) throw new InvalidOperationException("App content unloaded while capture was settling.");
        double scale = root.XamlRoot.RasterizationScale;
        if (!double.IsFinite(scale) || scale <= 0) throw new InvalidOperationException("Invalid WinUI rasterization scale.");
        double logicalWidth = root.ActualWidth, logicalHeight = root.ActualHeight;
        string theme = root.ActualTheme.ToString();
        var bitmap = new RenderTargetBitmap();
        await bitmap.RenderAsync(root);
        int width = bitmap.PixelWidth, height = bitmap.PixelHeight;
        if (width <= 0 || height <= 0 || width > 16384 || height > 16384 || (long)width * height * 4 > CaptureOracle.MaxBytes)
            throw new InvalidDataException("Rendered content is empty or exceeds the bounded capture size.");
        var pixels = await bitmap.GetPixelsAsync();
        if (pixels.Length != (long)width * height * 4) throw new InvalidDataException("Unexpected rendered BGRA8 buffer size.");
        var raw = new byte[(int)pixels.Length];
        using (var reader = DataReader.FromBuffer(pixels)) reader.ReadBytes(raw);
        using var encoded = new InMemoryRandomAccessStream();
        var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, encoded);
        encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied,
            (uint)width, (uint)height, 96 * scale, 96 * scale, raw);
        await encoder.FlushAsync();
        if (encoded.Size > CaptureOracle.MaxBytes) throw new InvalidDataException("Encoded PNG exceeds the capture limit.");
        encoded.Seek(0);
        var png = new byte[(int)encoded.Size];
        using (var reader = new DataReader(encoded.GetInputStreamAt(0)))
        {
            if (await reader.LoadAsync((uint)png.Length) != png.Length) throw new IOException("Encoded PNG read was incomplete.");
            reader.ReadBytes(png);
        }
        string temporary = Path.Combine(directory, ".capture-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            CheckDirectory(directory);
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { await file.WriteAsync(png); file.Flush(flushToDisk: true); }
            CheckDirectory(directory);
            File.Move(temporary, output, overwrite: false);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        string sha256 = Convert.ToHexString(SHA256.HashData(png)).ToLowerInvariant();
        CaptureAssessment assessment = requiredText is { Count: > 0 }
            ? CaptureOracle.Evaluate(raw, width, height, scale, requiredText)
            : new CaptureAssessment(true, null, CountNonBlackPixels(raw), Array.Empty<CaptureRegionAssessment>());
        var metadata = new CaptureMetadata(width, height, scale, logicalWidth, logicalHeight,
            theme, output, sha256, DateTimeOffset.UtcNow, assessment, Scope);
        if (!assessment.Passed)
            throw new CaptureValidationException("Capture validation failed: " + assessment.Failure + ".", metadata);
        return metadata;
    }

    public static CaptureRegion RequireTextRegion(FrameworkElement root, TextBlock text, string name)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(text);
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Capture region name is required.", nameof(name));
        if (!root.DispatcherQueue.HasThreadAccess || !text.DispatcherQueue.HasThreadAccess)
            throw new InvalidOperationException("Capture regions must be obtained on the owning WinUI thread.");
        if (string.IsNullOrWhiteSpace(text.Text))
            throw new InvalidOperationException("Capture text region requires nonempty text.");
        if (!IsEffectivelyVisible(root) || !IsEffectivelyVisible(text))
            throw new InvalidOperationException("Capture text region requires loaded, effectively visible content.");
        if (text.Foreground is not SolidColorBrush foreground)
            throw new InvalidOperationException("Capture text region requires a SolidColorBrush foreground.");
        var bounds = text.TransformToVisual(root).TransformBounds(
            new Windows.Foundation.Rect(0, 0, text.ActualWidth, text.ActualHeight));
        if (!double.IsFinite(bounds.X) || !double.IsFinite(bounds.Y) ||
            !double.IsFinite(bounds.Width) || !double.IsFinite(bounds.Height) ||
            bounds.Width <= 0 || bounds.Height <= 0 || bounds.Left < 0 || bounds.Top < 0 ||
            bounds.Right > root.ActualWidth || bounds.Bottom > root.ActualHeight)
            throw new InvalidOperationException("Capture text region must have positive bounds fully inside the capture root.");
        return new CaptureRegion(name, bounds.X, bounds.Y, bounds.Width, bounds.Height,
            foreground.Color.R, foreground.Color.G, foreground.Color.B);
    }

    private static bool IsEffectivelyVisible(FrameworkElement element)
    {
        for (FrameworkElement? current = element; current is not null;
            current = VisualTreeHelper.GetParent(current) as FrameworkElement)
            if (!current.IsLoaded || current.Visibility != Visibility.Visible ||
                current.ActualWidth <= 0 || current.ActualHeight <= 0)
                return false;
        return true;
    }

    private static int CountNonBlackPixels(byte[] bgra)
    {
        int count = 0;
        for (int pixel = 0; pixel < bgra.Length; pixel += 4)
            if (bgra[pixel + 3] > 16 &&
                (bgra[pixel] > 8 || bgra[pixel + 1] > 8 || bgra[pixel + 2] > 8))
                count++;
        return count;
    }

    private static async Task SettleRendering(FrameworkElement root)
    {
        var dispatcherTurn = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!root.DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low,
            () => dispatcherTurn.TrySetResult()))
            throw new InvalidOperationException("WinUI dispatcher is unavailable; no capture was written.");
        await dispatcherTurn.Task;
        root.UpdateLayout();

        var layoutChanged = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void LayoutUpdated(object? sender, object args) => layoutChanged.TrySetResult();
        root.LayoutUpdated += LayoutUpdated;
        try
        {
            var timeout = Task.Delay(TimeSpan.FromSeconds(5));
            while (true)
            {
                var quiet = Task.Delay(TimeSpan.FromMilliseconds(250));
                Task completed = await Task.WhenAny(layoutChanged.Task, quiet, timeout);
                if (completed == timeout)
                    throw new TimeoutException("WinUI layout did not remain quiet for 250 ms; no capture was written.");
                if (completed == quiet) break;
                layoutChanged = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }
        finally { root.LayoutUpdated -= LayoutUpdated; }

        var settled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int frames = 0;
        void Rendering(object? sender, object args)
        {
            if (++frames >= 3) settled.TrySetResult();
        }
        CompositionTarget.Rendering += Rendering;
        try
        {
            if (await Task.WhenAny(settled.Task, Task.Delay(TimeSpan.FromSeconds(3))) != settled.Task)
                throw new TimeoutException("Three WinUI rendering frames were not observed; no capture was written.");
            await settled.Task;
        }
        finally { CompositionTarget.Rendering -= Rendering; }
    }

    private static void CheckDirectory(string directory)
    {
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException("Caller-owned QA output directory must already exist.");
        for (DirectoryInfo? part = new(directory); part != null; part = part.Parent)
            if ((part.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Redirected QA output directories are not allowed.");
    }
}
