using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace AttackMap.NativeSpike;

public sealed record SourceLocationResult(string RelativePath, string? FullPath, int? Line,
    string Status, string? ScanTimeSha256, string? LiveSha256, string Comparison, string Warning);

/// <summary>Live source inspection only; never launches an editor or treats an excerpt hash as a file hash.</summary>
public static class SourceLocation
{
    public const string UnknownWarning = "Live file may differ from the scan; no explicit whole-file scan-time SHA-256 is available.";

    public static IReadOnlyList<SourceLocationResult> Inspect(string repositoryRoot, string findingJson, int maxFileBytes = 1_000_000)
    {
        if (maxFileBytes < 1 || maxFileBytes > 16_000_000) throw new ArgumentOutOfRangeException(nameof(maxFileBytes));
        if (findingJson.Length > 4_000_000) throw new ArgumentException("Finding JSON exceeds inspection limit.");
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(repositoryRoot));
        using var document = JsonDocument.Parse(findingJson);
        var output = new List<SourceLocationResult>();
        if (!document.RootElement.TryGetProperty("locations", out var locations) || locations.ValueKind != JsonValueKind.Array) return output;
        foreach (var location in locations.EnumerateArray().Take(256))
        {
            string relative = ""; string? hash = null; int? line = null;
            if (location.ValueKind == JsonValueKind.Object)
            {
                if (location.TryGetProperty("file", out var file) && file.ValueKind == JsonValueKind.String) relative = file.GetString() ?? "";
                if (location.TryGetProperty("line", out var number) && number.ValueKind != JsonValueKind.Null)
                {
                    if (number.ValueKind == JsonValueKind.Number && number.TryGetInt32(out var value)) line = value;
                    else line = 0;
                }
                // SourceSpan.source_sha256 hashes complete captured bytes. excerpt_sha256 and fingerprints do not.
                if (location.TryGetProperty("source_sha256", out var digest) && digest.ValueKind == JsonValueKind.String)
                {
                    var candidate = digest.GetString();
                    if (candidate?.Length == 64 && candidate.All(Uri.IsHexDigit)) hash = candidate.ToLowerInvariant();
                }
            }
            var result = new SourceLocationResult(relative, null, line, "invalid", hash, null, "unknown",
                hash == null ? UnknownWarning : "Live source comparison unavailable; scan-time hash is supplied but not yet compared.");
            try
            {
                var parts = relative.Replace('\\', '/').Split('/');
                if (string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) || relative.Contains(':') || parts.Any(p => p is ".." or "." or "") || line is <= 0 || relative.IndexOf('\0') >= 0)
                { output.Add(result); continue; }
                var full = Path.GetFullPath(Path.Combine(root, Path.Combine(parts)));
                if (!Within(root, full)) { output.Add(result); continue; }
                result = result with { FullPath = full };
                if (!Directory.Exists(root) || !File.Exists(full)) { output.Add(result with { Status = "missing" }); continue; }
                // Reject all reparse components, including the repository itself: no symlink/junction traversal.
                for (var part = new FileInfo(full) as FileSystemInfo; part != null; part = part is FileInfo fi ? fi.Directory : ((DirectoryInfo)part).Parent)
                    if ((part.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse path rejected.");
                using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (OperatingSystem.IsWindows())
                {
                    var buffer = new StringBuilder(32768);
                    uint size = GetFinalPathNameByHandle(stream.SafeFileHandle, buffer, (uint)buffer.Capacity, 0);
                    if (size == 0 || size >= buffer.Capacity) throw new IOException("Cannot verify opened file.");
                    var opened = buffer.ToString();
                    if (opened.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) opened = @"\\" + opened[8..];
                    else if (opened.StartsWith(@"\\?\", StringComparison.Ordinal)) opened = opened[4..];
                    if (!Within(root, opened) || !string.Equals(Path.GetFullPath(opened), full, StringComparison.OrdinalIgnoreCase)) throw new IOException("Opened path mismatch.");
                }
                var bytes = new byte[maxFileBytes + 1]; int read = 0;
                while (read < bytes.Length) { int count = stream.Read(bytes, read, bytes.Length - read); if (count == 0) break; read += count; }
                if (read > maxFileBytes) { output.Add(result with { Status = "too_large" }); continue; }
                var live = Convert.ToHexString(SHA256.HashData(bytes.AsSpan(0, read))).ToLowerInvariant();
                var comparison = hash == null ? "unknown" : hash == live ? "unchanged" : "changed";
                output.Add(result with { Status = "valid", LiveSha256 = live, Comparison = comparison,
                    Warning = hash == null ? UnknownWarning : comparison == "changed" ? "Live file differs from the captured scan-time file." : "Whole-file bytes match the supplied scan-time hash; runtime behavior is unverified." });
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            { output.Add(result with { Status = "unreadable" }); }
        }
        if (locations.GetArrayLength() > 256)
            output.Add(new SourceLocationResult("", null, null, "truncated", null, null, "unknown", "Source inspection limited to the first 256 structured locations."));
        return output;
    }

    private static bool Within(string root, string path) => path.StartsWith(Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar,
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
}
