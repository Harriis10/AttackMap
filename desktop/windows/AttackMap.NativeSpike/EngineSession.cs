using System.Diagnostics;
using System.Text.Json;
namespace AttackMap.NativeSpike;

public sealed class EngineSession
{
    private Process? worker;
    private bool cancelling;
    private int admission;
    public bool CleanupBlocked { get; private set; }
    public async Task Run(string python, string repository, string output, long generation, Action<string> progress, Func<string, Task> completed, Action<RunIdentity>? started = null, NativeScanOptions? options = null, string modules = "", Action<EngineProgressSnapshot>? structuredProgress = null)
    {
        if (CleanupBlocked || Interlocked.CompareExchange(ref admission, 1, 0) != 0) throw new InvalidOperationException("A scan is active or cleanup is unverified; restart is blocked.");
        try { await RunCore(python, repository, output, generation, progress, completed, started, options, modules, structuredProgress); }
        finally { if (!CleanupBlocked) Interlocked.Exchange(ref admission, 0); }
    }
    private async Task RunCore(string python, string repository, string output, long generation, Action<string> progress, Func<string, Task> completed, Action<RunIdentity>? started, NativeScanOptions? options, string modules, Action<EngineProgressSnapshot>? structuredProgress)
    {
        if (!Path.IsPathFullyQualified(python) || !File.Exists(python)) throw new InvalidDataException("Choose an absolute Python executable path with AttackMap installed.");
        Directory.CreateDirectory(output);
        string runId = Guid.NewGuid().ToString("N");
        string requestJson = NativeScanRequest.Serialize(runId, repository, output, generation, options ?? new(), modules);
        started?.Invoke(new RunIdentity(runId, repository, generation, DateTimeOffset.UtcNow));
        string requestPath = Path.Combine(output, "native-request.json");
        File.WriteAllText(requestPath, requestJson);
        var start = new EngineLaunchSpec(python).CreateStartInfo(EngineBrokerKind.Worker, requestPath);
        foreach (var key in new[] { "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID", "ATTACKMAP_ACTION_CREDENTIAL" }) start.Environment.Remove(key);
        using var process = Process.Start(start) ?? throw new IOException("Engine broker did not start.");
        worker = process;
        cancelling = false;
        var errors = Drain(process.StandardError);
        var protocol = new EngineProtocol(runId, repository, generation);
        try
        {
            while (await ReadBounded(process.StandardOutput) is string line)
            {
                if (!protocol.ParseAndAccept(line)) continue;
                structuredProgress?.Invoke(protocol.Progress!);
                using var document = JsonDocument.Parse(line);
                var message = document.RootElement;
                if (!protocol.Terminal && !cancelling) progress($"Engine {protocol.CurrentState}: {(message.TryGetProperty("stage", out var stage) ? stage.GetString() : "")}");
            }
            await process.WaitForExitAsync();
            await errors;
            protocol.EnsureTerminal();
            if (process.ExitCode != 0) throw new InvalidDataException("Engine broker exited unsuccessfully after its result. Previous report retained; inspect the run diagnostic.");
            progress($"Engine {protocol.CurrentState}; policy {protocol.PolicyOutcome}; artifacts {protocol.ArtifactReadiness}");
            if (protocol.CurrentState == "completed" && protocol.ArtifactReadiness == "ready")
                await completed(protocol.ArtifactPath!);
        }
        finally
        {
            if (!process.HasExited)
            {
                try { Disconnect(); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
                catch (Exception) { CleanupBlocked = true; throw new IOException("Scan cleanup is unverified. Further scans remain blocked; inspect the selected run diagnostics."); }
            }
            if (process.HasExited) worker = null;
        }
    }
    public void Cancel()
    {
        try { if (worker is { HasExited: false }) { cancelling = true; worker.StandardInput.WriteLine("cancel"); worker.StandardInput.Flush(); } }
        catch (IOException) { } catch (InvalidOperationException) { }
    }
    public void Disconnect()
    {
        try { if (worker is { HasExited: false }) worker.StandardInput.Close(); }
        catch (IOException) { } catch (InvalidOperationException) { }
    }
    private static async Task Drain(StreamReader reader) { var buffer = new char[4096]; while (await reader.ReadAsync(buffer, 0, buffer.Length) != 0) { } }
    private static async Task<string?> ReadBounded(StreamReader reader)
    {
        var text = new System.Text.StringBuilder();
        var buffer = new char[1];
        while (await reader.ReadAsync(buffer, 0, 1) != 0)
        {
            if (buffer[0] == '\n') return text.ToString();
            if (text.Length >= 65536) throw new InvalidDataException("Engine line exceeds 64 KiB limit.");
            text.Append(buffer[0]);
        }
        return text.Length == 0 ? null : text.ToString();
    }
}
