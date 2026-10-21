using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AttackMap.NativeSpike.HistoryPrep;

public sealed class RecentRepositoriesStore(string path)
{
    public IReadOnlyList<RecentRepository> Load() => Read().Document?.Repositories ?? Array.Empty<RecentRepository>();
    private RecentRepositoriesLoad Read()
    {
        if (!File.Exists(path)) return RecentRepositoriesCodec.Decode("{\"SchemaVersion\":1,\"Repositories\":[]}");
        if (new FileInfo(path).Length > 65536) throw new InvalidDataException("Recent repository history exceeds 64 KiB; original preserved.");
        var loaded = RecentRepositoriesCodec.Decode(File.ReadAllText(path));
        if (!loaded.Supported) throw new InvalidDataException(loaded.Notice);
        return loaded;
    }
    public void Remember(string root, string? generation = null, string? hash = null)
    {
        root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var original = Read();
        string identity = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(OperatingSystem.IsWindows() ? root.ToLowerInvariant() : root))).ToLowerInvariant();
        var previous = original.Document!.Repositories.FirstOrDefault(row => row.RepositoryId == identity);
        var selected = previous ?? new RecentRepository(identity, root, Path.GetFileName(root) is { Length: > 0 } name ? name : root);
        if (generation != null && hash != null) selected = selected with { LastGenerationId = generation, LastReportHash = hash };
        var entries = new[] { selected }.Concat(original.Document.Repositories.Where(row => row.RepositoryId != identity)).Take(50).ToArray();
        string raw = RecentRepositoriesCodec.Encode(original, entries);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, raw);
            if (File.Exists(path) && File.ReadAllText(path) != original.OriginalRaw) throw new IOException("Recent history changed during save; original preserved.");
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
