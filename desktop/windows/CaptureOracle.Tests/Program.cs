using AttackMap.NativeSpike;

int checks = 0;
void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; }
byte[] Bgra(int width, int height, byte gray)
{
    var pixels = new byte[width * height * 4];
    for (int pixel = 0; pixel < pixels.Length; pixel += 4)
    {
        pixels[pixel] = gray;
        pixels[pixel + 1] = gray;
        pixels[pixel + 2] = gray;
        pixels[pixel + 3] = 255;
    }
    return pixels;
}
void Ink(byte[] pixels, int width, int x, int y, byte gray)
{
    int pixel = (y * width + x) * 4;
    pixels[pixel] = gray;
    pixels[pixel + 1] = gray;
    pixels[pixel + 2] = gray;
}
CaptureRegion Region(double x = 0, double y = 0, double width = 16, double height = 16,
    byte foreground = 255) => new("required-text", x, y, width, height, foreground, foreground, foreground);
CaptureAssessment Evaluate(byte[] pixels, int width, int height, CaptureRegion[] regions, double scale = 1) =>
    CaptureOracle.Evaluate(pixels, width, height, scale, regions);

var black = Evaluate(Bgra(16, 16, 0), 16, 16, [Region()]);
Check(!black.Passed && black.Failure == "no-visible-rgb", "All-black BGRA must fail no-visible-rgb");

var decorationPixels = Bgra(16, 16, 16);
Ink(decorationPixels, 16, 15, 15, 255);
var decoration = Evaluate(decorationPixels, 16, 16, [Region(width: 8, height: 8)]);
Check(!decoration.Passed && decoration.NonBlackPixels > 0 &&
    decoration.Regions.Single().Failure == "missing-text-ink", "Decoration outside text must not satisfy the region");

var whitePixels = Bgra(16, 16, 16);
for (int y = 3; y < 9; y++) { Ink(whitePixels, 16, 4, y, 255); Ink(whitePixels, 16, 5, y, 255); }
var white = Evaluate(whitePixels, 16, 16, [Region()]);
Check(white.Passed && white.Failure == null && white.Regions.Single().InkPixels >= 8,
    "White text ink on a dark dominant background must pass");

var blackTextPixels = Bgra(16, 16, 240);
for (int y = 3; y < 9; y++) { Ink(blackTextPixels, 16, 4, y, 0); Ink(blackTextPixels, 16, 5, y, 0); }
var blackText = Evaluate(blackTextPixels, 16, 16, [Region(foreground: 0)]);
Check(blackText.Passed && blackText.Regions.Single().InkRatio > 0,
    "Black text ink on a light dominant background must pass");

var antialiasedPixels = Bgra(16, 16, 16);
for (int y = 0; y < 8; y++) Ink(antialiasedPixels, 16, 15, y, 176);
var antialiased = Evaluate(antialiasedPixels, 16, 16, [Region()]);
Check(antialiased.Passed && antialiased.Regions.Single().SampledPixels == 256,
    "Antialiased edge ink must pass without exact foreground matches");

var lowContrast = Evaluate(Bgra(16, 16, 100), 16, 16, [Region(foreground: 120)]);
Check(!lowContrast.Passed && lowContrast.Regions.Single().Failure == "insufficient-foreground-contrast",
    "Foreground/background contrast below 48 levels must fail");

var noRegions = Evaluate(whitePixels, 16, 16, []);
Check(!noRegions.Passed && noRegions.Failure == "text-regions-required", "Strict evaluation requires text regions");

var invalidRegions = new[]
{
    Evaluate(whitePixels, 16, 16, [Region(x: -1)]),
    Evaluate(whitePixels, 16, 16, [Region(width: 0)]),
    Evaluate(whitePixels, 16, 16, [Region(y: double.NaN)]),
    Evaluate(whitePixels, 16, 16, [Region(height: double.PositiveInfinity)]),
    Evaluate(whitePixels, 16, 16, [Region()], scale: 0),
    Evaluate(whitePixels, 16, 16, [Region()], scale: double.NaN),
    Evaluate(whitePixels, 16, 16, [Region()], scale: double.PositiveInfinity)
};
Check(invalidRegions.All(result => !result.Passed && result.Failure == "invalid-region"),
    "Negative, zero, nonfinite, and invalid-scale regions must fail invalid-region");

var outOfBounds = new[]
{
    Evaluate(whitePixels, 16, 16, [Region(width: 18)]),
    Evaluate(whitePixels, 16, 16, [Region(x: 15, width: 3)]),
    Evaluate(whitePixels, 16, 16, [Region(width: 9)], scale: 2)
};
Check(outOfBounds.All(result => !result.Passed && result.Failure == "region-out-of-bounds"),
    "Substantively clipped or wrong-scale out-of-bounds regions must fail without clipping");

var invalidDimensions = new[]
{
    Evaluate([], 0, 16, [Region()]),
    Evaluate([], -1, 16, [Region()]),
    Evaluate([], 16, 0, [Region()]),
    Evaluate([], 16385, 1, [Region()]),
    Evaluate([], 1, 16385, [Region()]),
    Evaluate([], 16384, 2049, [Region()])
};
Check(invalidDimensions.All(result => !result.Passed && result.Failure is "invalid-dimensions" or "capture-too-large"),
    "Invalid or excessive dimensions must fail before buffer/pixel iteration");

var invalidLength = Evaluate(new byte[15], 2, 2, [Region(width: 2, height: 2)]);
Check(!invalidLength.Passed && invalidLength.Failure == "invalid-buffer-length",
    "BGRA byte count must exactly match width times height times four");

var retainedFailure = new CaptureRunState(2);
retainedFailure.Failure("first", "missing-text-ink");
retainedFailure.Success("second");
Check(retainedFailure.Status == "failed" && retainedFailure.Attempts.Count == 2 &&
    retainedFailure.Failed == 1 && retainedFailure.Succeeded == 1 &&
    retainedFailure.Attempts[0].Error == "missing-text-ink", "A later success must not erase a failed attempt");

var incomplete = new CaptureRunState(2);
incomplete.Success("first");
var complete = new CaptureRunState(2);
complete.Success("first");
complete.Success("second");
Check(incomplete.Status == "incomplete" && complete.Status == "internal-capture-passed" &&
    complete.Succeeded == 2 && complete.Failed == 0, "Run status must distinguish incomplete from fully passed");

Console.WriteLine($"PASS {checks} capture oracle checks; synthetic BGRA only; no GUI or live acceptance.");
