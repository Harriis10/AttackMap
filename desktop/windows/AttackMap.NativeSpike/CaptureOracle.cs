namespace AttackMap.NativeSpike;

public sealed record CaptureRegion(
    string Name, double X, double Y, double Width, double Height,
    byte ForegroundR, byte ForegroundG, byte ForegroundB);

public sealed record CaptureRegionAssessment(
    string Name, int Width, int Height, int SampledPixels,
    int InkPixels, double InkRatio, string? Failure);

public sealed record CaptureAssessment(
    bool Passed, string? Failure,
    int NonBlackPixels, IReadOnlyList<CaptureRegionAssessment> Regions);

public static class CaptureOracle
{
    public const int MaxBytes = 128 * 1024 * 1024;

    public static CaptureAssessment Evaluate(
        ReadOnlySpan<byte> bgra, int width, int height,
        double scale, IReadOnlyList<CaptureRegion> requiredText)
    {
        if (width <= 0 || height <= 0 || width > 16384 || height > 16384)
            return Failure("invalid-dimensions");
        long expectedBytes = (long)width * height * 4;
        if (expectedBytes > MaxBytes) return Failure("capture-too-large");
        if (requiredText is null || requiredText.Count == 0) return Failure("text-regions-required");
        if (bgra.Length != expectedBytes) return Failure("invalid-buffer-length");

        var bounds = new PixelBounds[requiredText.Count];
        for (int index = 0; index < requiredText.Count; index++)
        {
            if (!TryGetBounds(requiredText[index], width, height, scale, out bounds[index]))
                return Failure("invalid-region");
            if (bounds[index].Right > width || bounds[index].Bottom > height ||
                bounds[index].Left >= width || bounds[index].Top >= height)
                return Failure("region-out-of-bounds");
        }

        int nonBlackPixels = 0;
        for (int pixel = 0; pixel < bgra.Length; pixel += 4)
            if (bgra[pixel + 3] > 16 &&
                (bgra[pixel] > 8 || bgra[pixel + 1] > 8 || bgra[pixel + 2] > 8))
                nonBlackPixels++;
        if (nonBlackPixels == 0) return Failure("no-visible-rgb");

        var assessments = new CaptureRegionAssessment[requiredText.Count];
        string? firstFailure = null;
        for (int index = 0; index < requiredText.Count; index++)
        {
            assessments[index] = EvaluateRegion(bgra, width, requiredText[index], bounds[index]);
            firstFailure ??= assessments[index].Failure;
        }
        return new CaptureAssessment(firstFailure is null, firstFailure, nonBlackPixels, assessments);
    }

    private static CaptureAssessment Failure(string failure) =>
        new(false, failure, 0, Array.Empty<CaptureRegionAssessment>());

    private static bool TryGetBounds(CaptureRegion? region, int width, int height,
        double scale, out PixelBounds bounds)
    {
        bounds = default;
        if (region is null || !double.IsFinite(scale) || scale <= 0 ||
            !double.IsFinite(region.X) || !double.IsFinite(region.Y) ||
            !double.IsFinite(region.Width) || !double.IsFinite(region.Height) ||
            region.X < 0 || region.Y < 0 || region.Width <= 0 || region.Height <= 0)
            return false;
        double left = region.X * scale, top = region.Y * scale;
        double right = (region.X + region.Width) * scale;
        double bottom = (region.Y + region.Height) * scale;
        if (!double.IsFinite(left) || !double.IsFinite(top) ||
            !double.IsFinite(right) || !double.IsFinite(bottom))
            return false;
        double pixelLeft = Math.Floor(left), pixelTop = Math.Floor(top);
        double pixelRight = Math.Ceiling(right), pixelBottom = Math.Ceiling(bottom);
        if (pixelRight > width + 1d || pixelBottom > height + 1d ||
            pixelLeft >= width || pixelTop >= height)
        {
            bounds = new PixelBounds(-1, -1, int.MaxValue, int.MaxValue);
            return true;
        }
        bounds = new PixelBounds((int)pixelLeft, (int)pixelTop,
            (int)Math.Min(pixelRight, width), (int)Math.Min(pixelBottom, height));
        return true;
    }

    private static CaptureRegionAssessment EvaluateRegion(ReadOnlySpan<byte> bgra, int imageWidth,
        CaptureRegion region, PixelBounds bounds)
    {
        int regionWidth = bounds.Right - bounds.Left;
        int regionHeight = bounds.Bottom - bounds.Top;
        int sampledPixels = regionWidth * regionHeight;
        Span<int> histogram = stackalloc int[4096];
        histogram.Clear();
        for (int y = bounds.Top; y < bounds.Bottom; y++)
            for (int x = bounds.Left; x < bounds.Right; x++)
            {
                int pixel = (y * imageWidth + x) * 4;
                histogram[Quantize(bgra[pixel + 2], bgra[pixel + 1], bgra[pixel])]++;
            }

        int dominant = 0;
        for (int bin = 1; bin < histogram.Length; bin++)
            if (histogram[bin] > histogram[dominant]) dominant = bin;
        byte backgroundR = (byte)(((dominant >> 8) & 0xF) * 16);
        byte backgroundG = (byte)(((dominant >> 4) & 0xF) * 16);
        byte backgroundB = (byte)((dominant & 0xF) * 16);
        int contrast = Math.Max(Math.Abs(region.ForegroundR - backgroundR),
            Math.Max(Math.Abs(region.ForegroundG - backgroundG), Math.Abs(region.ForegroundB - backgroundB)));
        if (contrast < 48)
            return new CaptureRegionAssessment(region.Name, regionWidth, regionHeight,
                sampledPixels, 0, 0, "insufficient-foreground-contrast");

        int inkPixels = 0;
        for (int y = bounds.Top; y < bounds.Bottom; y++)
            for (int x = bounds.Left; x < bounds.Right; x++)
            {
                int pixel = (y * imageWidth + x) * 4;
                int backgroundDistance = DistanceSquared(bgra[pixel + 2], bgra[pixel + 1], bgra[pixel],
                    backgroundR, backgroundG, backgroundB);
                int expectedDistance = DistanceSquared(bgra[pixel + 2], bgra[pixel + 1], bgra[pixel],
                    region.ForegroundR, region.ForegroundG, region.ForegroundB);
                if (backgroundDistance >= 32 * 32 && expectedDistance < backgroundDistance) inkPixels++;
            }
        int requiredInk = Math.Max(8, (int)Math.Ceiling(sampledPixels * 0.002));
        string? failure = inkPixels >= requiredInk ? null : "missing-text-ink";
        return new CaptureRegionAssessment(region.Name, regionWidth, regionHeight,
            sampledPixels, inkPixels, (double)inkPixels / sampledPixels, failure);
    }

    private static int Quantize(int r, int g, int b) => ((r >> 4) << 8) | ((g >> 4) << 4) | (b >> 4);

    private static int DistanceSquared(int r1, int g1, int b1, int r2, int g2, int b2)
    {
        int red = r1 - r2, green = g1 - g2, blue = b1 - b2;
        return red * red + green * green + blue * blue;
    }

    private readonly record struct PixelBounds(int Left, int Top, int Right, int Bottom);
}

public sealed record CaptureAttempt(string Name, string Outcome, string? Error);

public sealed class CaptureRunState
{
    private readonly List<CaptureAttempt> attempts = [];
    public CaptureRunState(int expected)
    {
        if (expected <= 0) throw new ArgumentOutOfRangeException(nameof(expected));
        Expected = expected;
    }
    public int Expected { get; }
    public IReadOnlyList<CaptureAttempt> Attempts => attempts;
    public int Succeeded => attempts.Count(a => a.Outcome == "passed");
    public int Failed => attempts.Count(a => a.Outcome == "failed");
    public string Status => Failed > 0 ? "failed" :
        Succeeded == Expected ? "internal-capture-passed" : "incomplete";
    public void Success(string name) => attempts.Add(new(name, "passed", null));
    public void Failure(string name, string error) =>
        attempts.Add(new(name, "failed", string.IsNullOrWhiteSpace(error) ? "unspecified capture failure" : error));
}
