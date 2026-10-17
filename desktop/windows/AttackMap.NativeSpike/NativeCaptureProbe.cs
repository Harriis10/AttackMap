using System.Security.Cryptography;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;

namespace AttackMap.NativeSpike;

public sealed record CaptureMetadata(int Width, int Height, double Scale, double LogicalWidth,
    double LogicalHeight, string Theme, string OutputPath, string Sha256, DateTimeOffset CapturedAt, string Scope);

/// <summary>Caller-owned QA hook: captures only a loaded in-process WinUI visual tree.</summary>
public static class NativeCaptureProbe
{
    public const string Scope = "In-process WinUI RenderTargetBitmap content after two rendering frames only. Composition-backed effects/surfaces, transparency, theme transitions and selection visuals may be omitted or differ from the displayed window; capture anomalies require independent live-window verification before being classified as UI defects. Excludes window chrome, other apps, desktop, popups outside this tree, Narrator and OS appearance/scaling acceptance. A PNG is visual review material, not C24/C25 acceptance.";
    private const int MaxBytes = 128 * 1024 * 1024;

    public static async Task<CaptureMetadata> Capture(FrameworkElement root, string absolutePngPath)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (!root.DispatcherQueue.HasThreadAccess) throw new InvalidOperationException("Capture must be called on the owning WinUI thread.");
        if (root.XamlRoot == null || !root.IsLoaded || root.ActualWidth <= 0 || root.ActualHeight <= 0)
            throw new InvalidOperationException("Capture requires loaded, laid-out app content.");
        if (!Path.IsPathFullyQualified(absolutePngPath) || absolutePngPath.StartsWith(@"\\", StringComparison.Ordinal) ||
            !string.Equals(Path.GetExtension(absolutePngPath), ".png", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Provide an absolute local PNG path in the caller-owned workspace QA directory.");
        string output = Path.GetFullPath(absolutePngPath), directory = Path.GetDirectoryName(output)!;
        CheckDirectory(directory);
        if (File.Exists(output) || Directory.Exists(output)) throw new IOException("Capture output already exists; use a fresh QA path.");
        root.UpdateLayout();
        await SettleRendering(root);
        if (!root.IsLoaded || root.XamlRoot == null) throw new InvalidOperationException("App content unloaded while capture was settling.");
        double scale = root.XamlRoot.RasterizationScale;
        if (!double.IsFinite(scale) || scale <= 0) throw new InvalidOperationException("Invalid WinUI rasterization scale.");
        double logicalWidth = root.ActualWidth, logicalHeight = root.ActualHeight;
        string theme = root.ActualTheme.ToString();
        var bitmap = new RenderTargetBitmap();
        await bitmap.RenderAsync(root);
        int width = bitmap.PixelWidth, height = bitmap.PixelHeight;
        if (width <= 0 || height <= 0 || width > 16384 || height > 16384 || (long)width * height * 4 > MaxBytes)
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
        if (encoded.Size > MaxBytes) throw new InvalidDataException("Encoded PNG exceeds the capture limit.");
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
        return new CaptureMetadata(width, height, scale, logicalWidth, logicalHeight,
            theme, output, Convert.ToHexString(SHA256.HashData(png)).ToLowerInvariant(), DateTimeOffset.UtcNow, Scope);
    }

    private static async Task SettleRendering(FrameworkElement root)
    {
        var settled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int frames = 0;
        void Rendering(object? sender, object args)
        {
            if (++frames >= 2) settled.TrySetResult();
        }
        CompositionTarget.Rendering += Rendering;
        try
        {
            root.InvalidateArrange();
            if (await Task.WhenAny(settled.Task, Task.Delay(TimeSpan.FromSeconds(3))) != settled.Task)
                throw new TimeoutException("Two WinUI rendering frames were not observed; no capture was written.");
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
