using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
namespace AttackMap.NativeSpike;

public static class DesktopActionRunner
{
    private static int admission;
    public static bool CleanupBlocked { get; private set; }
    public static readonly string ActionDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", "actions");
    public static async Task<JsonElement> Run(string python, string operation, object payload, string? credential = null, string? outputBase = null, CancellationToken cancellationToken = default)
    {
        if (CleanupBlocked || Interlocked.CompareExchange(ref admission, 1, 0) != 0) throw new InvalidOperationException("An action is active or its cleanup is unverified; admission remains blocked.");
        try { return await RunCore(python, operation, payload, credential, outputBase, cancellationToken); }
        finally { if (!CleanupBlocked) Interlocked.Exchange(ref admission, 0); }
    }
    private static async Task<JsonElement> RunCore(string python, string operation, object payload, string? credential, string? outputBase, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!Path.IsPathFullyQualified(python) || !File.Exists(python)) throw new InvalidDataException("Choose an absolute engine Python path first.");
        string id = Guid.NewGuid().ToString("N");
        string folder = Path.Combine(outputBase ?? ActionDirectory, id);
        Directory.CreateDirectory(folder);
        string request = Path.Combine(folder, "request.json");
        await File.WriteAllTextAsync(request, JsonSerializer.Serialize(new { schema_version = "1.1", request_id = id, operation, output_path = folder, payload }));
        var start = new EngineLaunchSpec(python).CreateStartInfo(EngineBrokerKind.Action, request);
        foreach (var key in new[] { "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID", "ATTACKMAP_ACTION_CREDENTIAL" }) start.Environment.Remove(key);
        if (!string.IsNullOrEmpty(credential) && operation.StartsWith("provider_", StringComparison.Ordinal)) start.Environment["ATTACKMAP_ACTION_CREDENTIAL"] = credential;
        using var process = Process.Start(start) ?? throw new IOException("Desktop action broker did not start.");
        using var cancellation = cancellationToken.Register(() => { try { process.StandardInput.Close(); } catch (IOException) { } catch (InvalidOperationException) { } });
        var drain = Drain(process.StandardError);
        try
        {
            string line = await ReadBounded(process.StandardOutput).WaitAsync(TimeSpan.FromSeconds(75), cancellationToken);
            using var envelopeDocument = JsonDocument.Parse(line);
            var envelope = envelopeDocument.RootElement;
            if (envelope.GetProperty("schema_version").GetString() != "1.1" || envelope.GetProperty("kind").GetString() != "action_result" || envelope.GetProperty("request_id").GetString() != id || envelope.GetProperty("operation").GetString() != operation) throw new InvalidDataException("Desktop action identity mismatch.");
            if (envelope.GetProperty("state").GetString() != "completed") throw new InvalidDataException("Desktop action did not complete. A configuration change may already have applied; its local request snapshot is preserved for review.");
            string result = envelope.GetProperty("result_path").GetString()!;
            string expected = Path.Combine(folder, id + ".result.json");
            if (!string.Equals(Path.GetFullPath(result), expected, StringComparison.OrdinalIgnoreCase) || new FileInfo(result).Length > 64 * 1024 * 1024) throw new InvalidDataException("Invalid desktop action result location or size.");
            byte[] bytes = await File.ReadAllBytesAsync(result);
            string hash = Convert.ToHexString(SHA256.HashData(bytes));
            if (!hash.Equals(envelope.GetProperty("sha256").GetString(), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Desktop action result changed.");
            using var document = JsonDocument.Parse(bytes);
            if (document.RootElement.GetProperty("request_id").GetString() != id || document.RootElement.GetProperty("operation").GetString() != operation) throw new InvalidDataException("Desktop action result identity mismatch.");
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            await drain;
            if (process.ExitCode != 0) throw new InvalidDataException("Desktop action broker exited unsuccessfully after its result. A configuration change may already have applied; its local request snapshot is preserved for review.");
            return document.RootElement.GetProperty("result").Clone();
        }
        finally
        {
            if (!process.HasExited)
            {
                try
                {
                    process.StandardInput.Close(); // EOF tells the broker to clean its owned Job Object.
                    await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                }
                catch (Exception)
                {
                    CleanupBlocked = true;
                    throw new IOException("Desktop action cleanup is unverified. Restart admission remains blocked; inspect the local action snapshot.");
                }
            }
        }
    }

    private static async Task<string> ReadBounded(StreamReader reader)
    {
        var text = new System.Text.StringBuilder();
        var buffer = new char[1];
        while (await reader.ReadAsync(buffer, 0, 1) != 0)
        {
            if (buffer[0] == '\n') return text.ToString();
            if (text.Length >= 32768) throw new InvalidDataException("Action envelope exceeds its limit.");
            text.Append(buffer[0]);
        }
        throw new EndOfStreamException("Desktop action ended without a result.");
    }

    private static async Task Drain(StreamReader reader)
    {
        var buffer = new char[4096];
        while (await reader.ReadAsync(buffer, 0, buffer.Length) != 0) { }
    }
}
