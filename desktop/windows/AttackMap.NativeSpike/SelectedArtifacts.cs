using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace AttackMap.NativeSpike;

public sealed record ArtifactRecord(string Name, string Role, string Format, string FullPath, string Checksum, long? Size);

/// <summary>Reads only captured, manifest-listed artifacts from the displayed generation as inert text.</summary>
public static class SelectedArtifacts
{
    public static IReadOnlyList<ArtifactRecord> List(ExportSelection selection)
    {
        if (!selection.Verified || selection.ManifestPath == null || selection.ManifestHash == null)
            throw new InvalidDataException("Raw artifacts require a verified selected generation. Legacy imports support canonical JSON export only; run a scan or open a broker result.");
        var directory = Path.GetDirectoryName(Path.GetFullPath(selection.ReportPath))!;
        if (!string.Equals(Path.GetFullPath(selection.ManifestPath), Path.Combine(directory, "artifact-manifest.json"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Selected manifest must belong to the displayed generation.");
        var manifest = ReadBounded(selection.ManifestPath, 1024 * 1024);
        if (ExportSelection.Hash(manifest) != selection.ManifestHash || ExportSelection.Hash(ReadBounded(selection.ReportPath, 64 * 1024 * 1024)) != selection.ReportHash)
            throw new InvalidDataException("Selected report or manifest changed. Reopen the report; previous displayed text is preserved.");
        using var document = JsonDocument.Parse(manifest);
        var root = document.RootElement;
        if (Text(root, "schema_version") != "1.0.0" || Text(root, "artifact_type") != "attackmap_artifact_manifest" || Text(root, "generation_id") != selection.RunId)
            throw new InvalidDataException("Unsupported manifest or selected run identity mismatch.");
        var records = new List<ArtifactRecord>();
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var collection in new[] { "sections", "compatibility_exports" })
        {
            if (!root.TryGetProperty(collection, out var entries) || entries.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Selected manifest artifact lists are missing.");
            foreach (var entry in entries.EnumerateArray())
            {
                if (records.Count >= 512) throw new InvalidDataException("Too many selected artifacts.");
                string name = Text(entry, "name"), relative = Text(entry, "path"), role = Text(entry, "role"), format = Text(entry, "format"), checksum = Text(entry, "checksum");
                if (!Basename(relative) || name.Length is < 1 or > 256 || name.Any(char.IsControl) || !names.Add(name) || !paths.Add(relative))
                    throw new InvalidDataException("Selected manifest has duplicate or unsafe artifact paths/names.");
                if (checksum.Length != 64 || !checksum.All(Uri.IsHexDigit) || role.Length is < 1 or > 128 || role.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-') ||
                    format is not ("json" or "md" or "sarif" or "dot" or "html" or "txt" or "svg") || Path.GetExtension(relative) != "." + format)
                    throw new InvalidDataException("Invalid artifact checksum, format or role.");
                string full = Path.Combine(directory, relative);
                CheckPath(full);
                records.Add(new ArtifactRecord(name, role, format, full, checksum.ToLowerInvariant(), new FileInfo(full).Length));
            }
        }
        var report = records.Where(record => string.Equals(record.FullPath, Path.GetFullPath(selection.ReportPath), StringComparison.OrdinalIgnoreCase)).ToArray();
        if (report.Length != 1 || report[0].Checksum != selection.ReportHash || report[0].Format != "json")
            throw new InvalidDataException("Manifest does not bind the exact displayed report.");
        return records;
    }

    public static Task<string> ReadText(ExportSelection selection, ArtifactRecord record, int limit = 4 * 1024 * 1024) => Task.Run(() =>
    {
        if (limit < 1 || limit > 64 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(limit));
        var listed = List(selection).SingleOrDefault(item => item == record) ?? throw new InvalidDataException("Artifact is not in the selected captured manifest. Refresh the list.");
        var bytes = ReadBounded(listed.FullPath, limit);
        if (ExportSelection.Hash(bytes) != listed.Checksum) throw new InvalidDataException("Selected artifact changed; previous displayed text is preserved.");
        // Recheck selected identity after the artifact read, before returning any text.
        List(selection);
        return new UTF8Encoding(false, true).GetString(bytes);
    });

    private static string Text(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
        ? property.GetString()! : throw new InvalidDataException("Malformed selected manifest field.");

    private static bool Basename(string value) => value.Length is > 0 and <= 255 && value is not ("." or "..") &&
        !value.Any(c => char.IsControl(c) || "\\/:*?\"<>|".Contains(c)) && value == value.TrimEnd(' ', '.');

    private static void CheckPath(string path)
    {
        if (!File.Exists(path)) throw new InvalidDataException("Selected artifact is missing or is not a file.");
        for (FileSystemInfo? part = new FileInfo(path); part != null; part = part is FileInfo file ? file.Directory : ((DirectoryInfo)part).Parent)
            if ((part.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Redirected selected artifact path rejected.");
    }

    private static byte[] ReadBounded(string path, int limit)
    {
        path = Path.GetFullPath(path); CheckPath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (OperatingSystem.IsWindows())
        {
            var buffer = new StringBuilder(32768);
            uint size = GetFinalPathNameByHandle(stream.SafeFileHandle, buffer, (uint)buffer.Capacity, 0);
            if (size == 0 || size >= buffer.Capacity) throw new InvalidDataException("Opened artifact path cannot be verified.");
            var opened = buffer.ToString();
            if (opened.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) opened = @"\\" + opened[8..];
            else if (opened.StartsWith(@"\\?\", StringComparison.Ordinal)) opened = opened[4..];
            if (!string.Equals(opened, path, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Opened artifact path changed.");
        }
        using var output = new MemoryStream();
        var chunk = new byte[16384]; int count;
        while ((count = stream.Read(chunk)) != 0)
        { if (output.Length + count > limit) throw new InvalidDataException("Selected artifact exceeds text preview limit."); output.Write(chunk, 0, count); }
        return output.ToArray();
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
}
