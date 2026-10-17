using System.Text.Json;

namespace AttackMap.NativeSpike;

/// <summary>Geometry only. The UI must clamp restored coordinates to the current display work area.</summary>
public sealed record WindowPlacement(int SchemaVersion = 1, int Width = 1280, int Height = 800, int? Left = null, int? Top = null);

public sealed class WindowPlacementStore
{
    private const int MaxBytes = 4096;
    private readonly string path;
    public WindowPlacementStore(string path) => this.path = Path.GetFullPath(path);

    public WindowPlacement Load()
    {
        if (!File.Exists(path)) return new();
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var bytes = new byte[MaxBytes + 1];
        int read = 0;
        while (read < bytes.Length)
        {
            int count = stream.Read(bytes, read, bytes.Length - read);
            if (count == 0) break;
            read += count;
        }
        if (read > MaxBytes) throw new InvalidDataException("Window placement exceeds 4 KiB. Original preserved.");
        using var document = JsonDocument.Parse(bytes.AsMemory(0, read));
        if (document.RootElement.ValueKind != JsonValueKind.Object || !document.RootElement.TryGetProperty("SchemaVersion", out _))
            throw new InvalidDataException("Missing window placement version. Original preserved.");
        var value = document.RootElement.Deserialize<WindowPlacement>() ?? throw new InvalidDataException("Window placement is empty.");
        Validate(value);
        return value;
    }

    public void Save(WindowPlacement value)
    {
        Validate(value);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { stream.Write(bytes); stream.Flush(flushToDisk: true); }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public void Clear() { if (File.Exists(path)) File.Delete(path); }

    private static void Validate(WindowPlacement value)
    {
        if (value.SchemaVersion != 1) throw new InvalidDataException("Unsupported window placement version. Original preserved.");
        if (value.Width is < 1024 or > 16384 || value.Height is < 700 or > 16384)
            throw new InvalidDataException("Window size must be within 1024x700 and 16384x16384.");
        if (value.Left.HasValue != value.Top.HasValue || value.Left is < -1_000_000 or > 1_000_000 || value.Top is < -1_000_000 or > 1_000_000)
            throw new InvalidDataException("Window coordinates must be paired and bounded.");
    }
}
