using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace AttackMap.NativeSpike;

public sealed record ExportSelection(string ReportPath, string ReportHash, string? RunId, string? ManifestPath, string? ManifestHash, string? MarkdownPath, string? MarkdownHash)
{
    public bool Verified => RunId != null;
    public string Disclosure => Verified ? $"Displayed run {RunId}; captured manifest integrity checked." : "Legacy import: run identity and manifest integrity unverified. JSON copy only.";
    public string SuggestedName(bool markdown) => "attackmap-" + (Verified ? SafeName(RunId!) : "legacy-unverified") + (markdown ? "-review.md" : "-report.json");
    public string SuggestedName(string renderedExtension) => "attackmap-" + (Verified ? SafeName(RunId!) : "legacy-unverified") + "-review" + renderedExtension;
    public static string SafeName(string value)
    {
        string safe = string.Concat(value.Take(80).Select(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' ? c : '_'));
        return safe.Length == 0 ? "selected-run" : safe;
    }
    public static ExportSelection Capture(string path, string readHash, RunIdentity? identity)
    {
        path = Path.GetFullPath(path);
        if (identity == null) return new(path,readHash,null,null,null,null,null);
        return CaptureManifest(path, readHash, identity.Repository, identity.RunId);
    }
    public static ExportSelection CaptureSavedGeneration(string path, string readHash, string repository)
    {
        path = Path.GetFullPath(path);
        byte[] manifest;
        try { manifest = ReadBounded(Path.Combine(Path.GetDirectoryName(path)!, "artifact-manifest.json"),1024 * 1024); }
        catch (FileNotFoundException) { return new(path,readHash,null,null,null,null,null); }
        return CaptureManifest(path, readHash, repository, null, manifest);
    }
    private static ExportSelection CaptureManifest(string path, string readHash, string repository, string? expectedRun, byte[]? capturedManifest = null)
    {
        string directory = Path.GetDirectoryName(path)!;
        string manifestPath = Path.Combine(directory,"artifact-manifest.json");
        byte[] bytes = capturedManifest ?? ReadBounded(manifestPath,1024 * 1024);
        if (bytes.Length > 1024 * 1024) throw new InvalidDataException("Artifact manifest exceeds 1 MiB.");
        using var document = JsonDocument.Parse(bytes);
        var root = document.RootElement;
        if (root.GetProperty("schema_version").GetString() != "1.0.0" || root.GetProperty("artifact_type").GetString() != "attackmap_artifact_manifest") throw new InvalidDataException("Unsupported artifact manifest; reopen a supported broker result.");
        string? run = root.GetProperty("generation_id").GetString();
        if (string.IsNullOrWhiteSpace(run) || run.Length > 256 || run.Any(char.IsControl) || string.IsNullOrWhiteSpace(repository) ||
            (expectedRun != null && run != expectedRun) || root.GetProperty("run_identity").GetProperty("repo_root").GetString() != repository)
            throw new InvalidDataException("Displayed report identity does not match its manifest.");
        if (Hash(ReadBounded(path,64 * 1024 * 1024)) != readHash)
            throw new InvalidDataException("Displayed report changed while opening its saved generation.");
        var entries = root.GetProperty("compatibility_exports").EnumerateArray().ToList();
        var jsonEntries = entries.Where(entry => entry.GetProperty("path").GetString() == Path.GetFileName(path)).ToArray();
        if (jsonEntries.Length != 1) throw new InvalidDataException("Manifest must identify exactly one displayed JSON artifact.");
        var json = jsonEntries[0];
        if (json.ValueKind == JsonValueKind.Undefined || json.GetProperty("checksum").GetString() != readHash) throw new InvalidDataException("Displayed JSON bytes do not match its manifest.");
        var markdownEntries = entries.Where(entry => entry.GetProperty("path").GetString() == "defensive-review.md").ToArray();
        if (markdownEntries.Length > 1) throw new InvalidDataException("Manifest contains duplicate review artifacts.");
        var markdown = markdownEntries.FirstOrDefault();
        return new(path,readHash,run,manifestPath,Hash(bytes),markdown.ValueKind == JsonValueKind.Undefined ? null : Path.Combine(directory,"defensive-review.md"),markdown.ValueKind == JsonValueKind.Undefined ? null : markdown.GetProperty("checksum").GetString());
    }
    public async Task Export(string destination, bool markdown)
    {
        destination = Path.GetFullPath(destination);
        string source = markdown ? MarkdownPath ?? throw new InvalidDataException("Markdown export requires a displayed broker run whose manifest lists defensive-review.md. Open JSON or run a local scan.") : ReportPath;
        EnsureExportDestination(destination, source);
        if (ManifestPath != null && Hash(ReadBounded(ManifestPath,1024 * 1024)) != ManifestHash) throw new InvalidDataException("Selected run manifest changed. Reopen the report before exporting.");
        byte[] report = ReadBounded(ReportPath,64 * 1024 * 1024);
        if (Hash(report) != ReportHash) throw new InvalidDataException("Displayed report source changed. Reopen it before exporting; destination preserved.");
        byte[] content = markdown ? ReadBounded(source,64 * 1024 * 1024) : report;
        if (markdown && Hash(content) != MarkdownHash) throw new InvalidDataException("Selected Markdown does not match its captured manifest; destination preserved.");
        string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { await File.WriteAllBytesAsync(temporary,content); File.Move(temporary,destination,overwrite:true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    /// <summary>Returns the displayed run's Markdown review after the same
    /// integrity checks as Export, for derived renderings (HTML/PDF).</summary>
    public string ReadVerifiedMarkdown()
    {
        if (MarkdownPath == null || MarkdownHash == null) throw new InvalidDataException("Verified Markdown requires a displayed broker run whose manifest lists defensive-review.md.");
        if (ManifestPath != null && Hash(ReadBounded(ManifestPath,1024 * 1024)) != ManifestHash) throw new InvalidDataException("Selected run manifest changed. Reopen the report before exporting.");
        byte[] report = ReadBounded(ReportPath,64 * 1024 * 1024);
        if (Hash(report) != ReportHash) throw new InvalidDataException("Displayed report source changed. Reopen it before exporting.");
        byte[] content = ReadBounded(MarkdownPath,64 * 1024 * 1024);
        if (Hash(content) != MarkdownHash) throw new InvalidDataException("Selected Markdown does not match its captured manifest.");
        return new UTF8Encoding(false).GetString(content);
    }
    public void EnsureExportDestination(string destination, string source)
    {
        destination = Path.GetFullPath(destination);
        if (string.Equals(destination,source,StringComparison.OrdinalIgnoreCase) || string.Equals(destination,ReportPath,StringComparison.OrdinalIgnoreCase) || string.Equals(destination,ManifestPath,StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Choose an export destination outside the selected source artifacts.");
        if (Verified)
        {
            string relative = Path.GetRelativePath(Path.GetDirectoryName(ReportPath)!,destination);
            if (!Path.IsPathFullyQualified(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar)) throw new InvalidDataException("Export outside the immutable selected generation directory.");
        }
    }
    private static byte[] ReadBounded(string path,int limit)
    {
        using var source = File.OpenRead(path);
        if (source.Length > limit) throw new InvalidDataException("Selected artifact exceeds export size limit.");
        using var output = new MemoryStream();
        var buffer = new byte[16384];
        int count;
        while ((count = source.Read(buffer,0,buffer.Length)) != 0) { if (output.Length + count > limit) throw new InvalidDataException("Selected artifact exceeds export size limit."); output.Write(buffer,0,count); }
        return output.ToArray();
    }
    public static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
