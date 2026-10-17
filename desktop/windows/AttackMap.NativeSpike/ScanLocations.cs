using System.Security.Cryptography;
using System.Text;

namespace AttackMap.NativeSpike;

/// <summary>Stable per-repository scan output locations so generations accumulate for retention (C30).</summary>
public static class ScanLocations
{
    public static string ReportsBase(string repositoryPath) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AttackMap", "NativePreview", "scans", RepositoryKey(repositoryPath), "reports");

    public static string RepositoryKey(string repositoryPath)
    {
        string full = Path.GetFullPath(repositoryPath);
        string normalized = full.ToLowerInvariant(); // mirrors os.path.normcase on Windows
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        var hex = new StringBuilder(hash.Length * 2);
        foreach (byte value in hash) hex.Append(value.ToString("x2"));
        string leaf = Path.GetFileName(full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return $"{SafeName(leaf)}-{hex.ToString(0, 12)}";
    }

    private static string SafeName(string name)
    {
        var cleaned = new string(name.Select(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_').ToArray());
        if (cleaned.Length == 0) return "repo";
        return cleaned.Length > 64 ? cleaned[..64] : cleaned;
    }
}
