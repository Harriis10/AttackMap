using System.Security.Cryptography;
using System.Text.Json;
using AttackMap.NativeSpike;

var root = Path.Combine(Path.GetTempPath(), "attackmap-source-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
int checks = 0;
void Check(bool value) { checks++; if (!value) throw new Exception($"Failed check {checks}"); }
SourceLocationResult Read(string file, int? line = 1, string? source_sha256 = null, string? excerpt_sha256 = null) =>
    SourceLocation.Inspect(root, JsonSerializer.Serialize(new { locations = new[] { new { file, line, source_sha256, excerpt_sha256 } } })).Single();
try
{
    var relative = "žluťoučký/" + string.Join('/', Enumerable.Repeat("long-segment-abcdefghij", 12)) + "/source.py";
    var full = Path.Combine(root, relative); Directory.CreateDirectory(Path.GetDirectoryName(full)!); File.WriteAllText(full, "synthetic\n");
    var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(full))).ToLowerInvariant();
    Check(Read(relative).Status == "valid"); Check(Read(relative).Comparison == "unknown");
    Check(Read(relative).Warning == SourceLocation.UnknownWarning);
    Check(Read(relative, source_sha256: hash).Comparison == "unchanged");
    Check(Read(relative, excerpt_sha256: hash).ScanTimeSha256 == null);
    File.AppendAllText(full, "changed\n"); Check(Read(relative, source_sha256: hash).Comparison == "changed");
    Check(Read("../outside.py").Status == "invalid"); Check(Read(full).Status == "invalid");
    Check(Read(relative, 0).Status == "invalid"); Check(Read("missing.py").Status == "missing");
    Check(SourceLocation.Inspect(root, "{\"locations\":[{\"file\":\"a.py\",\"line\":\"bad\"}]}").Single().Status == "invalid");
    Check(SourceLocation.Inspect(root, "{\"locations\":[null]}").Single().Status == "invalid");
    Check(Read(relative, null).Status == "valid");
    Check(SourceLocation.Inspect(root, JsonSerializer.Serialize(new { locations = Enumerable.Repeat(new { file = "missing.py", line = 1 }, 257) })).Last().Status == "truncated");
    Check(Read("žluťoučký").Status != "valid");
    Check(SourceLocation.Inspect(root, JsonSerializer.Serialize(new { locations = new[] { new { file = relative, line = 1 } } }), 2).Single().Status == "too_large");
    var link = Path.Combine(root, "junction");
    try { Directory.CreateSymbolicLink(link, root); Check(Read("junction/" + relative).Status == "unreadable"); }
    catch (UnauthorizedAccessException) { Console.WriteLine("Symlink creation unavailable; no symlink acceptance claimed."); }
    Console.WriteLine($"{checks} source-location checks passed");
}
finally { Directory.Delete(root, true); }
