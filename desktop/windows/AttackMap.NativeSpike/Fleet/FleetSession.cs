using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AttackMap.NativeSpike;

public sealed record FleetSessionResult(FleetGeneration Generation, string Outcome, IReadOnlyList<FleetChildStatus> Children, string? IndexPath, string? IndexHash);

/// <summary>Schema 1.4 metadata admission. Artifact hashes are verified separately before result delivery.</summary>
public sealed class FleetProtocol
{
    private readonly FleetGeneration identity;
    private readonly IReadOnlyList<FleetRoot> roots;
    private readonly Dictionary<string, FleetChildStatus> children = new(StringComparer.Ordinal);
    public long Revision { get; private set; } = -1;
    public bool Terminal => Result != null;
    public FleetSessionResult? Result { get; private set; }
    public FleetChildStatus? LastChild { get; private set; }
    public FleetProtocol(FleetGeneration generation, IReadOnlyList<FleetRoot> repositories) { identity = generation; roots = repositories.ToArray(); }
    public bool Accept(string line)
    {
        if (line.Length > 65536) throw new InvalidDataException("Fleet message exceeds 64 KiB.");
        using var document = JsonDocument.Parse(line); var m = document.RootElement;
        Match(m);
        long revision = m.GetProperty("revision").GetInt64();
        if (revision < 0) throw new InvalidDataException("Invalid fleet revision.");
        if (Terminal || revision <= Revision) return false;
        LastChild = null;
        string kind = Text(m,"kind");
        if (kind == "progress")
        {
            if (Text(m,"state") is not ("queued" or "running" or "cancelling")) throw new InvalidDataException("Invalid fleet progress.");
        }
        else if (kind == "fleet_child") { var child = Child(m); Remember(child); LastChild = child; }
        else if (kind == "fleet_terminal")
        {
            var rows = m.GetProperty("children").EnumerateArray().Select(Child).ToArray();
            if (rows.Length != roots.Count || rows.Select(c => c.RepositoryId).Distinct().Count() != roots.Count || rows.Any(c => c.State is "running" or "queued")) throw new InvalidDataException("Incomplete fleet terminal children.");
            foreach (var child in rows) Remember(child);
            string outcome = Text(m,"fleet_outcome"), state = Text(m,"state");
            int completed = rows.Count(c => c.State == "completed");
            bool succeeded = outcome == "succeeded";
            var expected = outcome switch
            {
                "succeeded" => (State: "completed", Execution: "succeeded", Readiness: "ready"),
                "partial" or "failed" => (State: "failed", Execution: "failed", Readiness: "unavailable"),
                "cancelled" => (State: "cancelled", Execution: "cancelled", Readiness: "unavailable"),
                _ => throw new InvalidDataException("Unknown fleet outcome.")
            };
            if (state != expected.State || Text(m,"execution_outcome") != expected.Execution || Text(m,"artifact_readiness") != expected.Readiness)
                throw new InvalidDataException("Fleet terminal state, execution outcome and readiness disagree.");
            if (outcome is not ("succeeded" or "partial" or "failed" or "cancelled") ||
                succeeded && (completed != roots.Count || state != "completed" || Text(m,"artifact_readiness") != "ready" || Text(m,"execution_outcome") != "succeeded") ||
                !succeeded && state == "completed" || outcome == "partial" && (completed == 0 || completed == roots.Count) ||
                (outcome == "cancelled") != (state == "cancelled")) throw new InvalidDataException("Inconsistent fleet outcome.");
            string? path = Optional(m,"index_path"), hash = Optional(m,"index_sha256");
            if ((path == null) != (hash == null) || path != null && (!Path.IsPathFullyQualified(path) || !Hash(hash)) || succeeded && path == null) throw new InvalidDataException("Invalid fleet index reference.");
            Result = new(identity,outcome,rows,path,hash);
        }
        else throw new InvalidDataException("Unknown fleet event.");
        Revision = revision; return true;
    }
    private void Match(JsonElement m)
    {
        if (Text(m,"schema_version") != "1.4" || Text(m,"run_id") != identity.RunId || Text(m,"repository_id") != identity.RepositorySetId || m.GetProperty("generation").GetInt64() != identity.Generation)
            throw new InvalidDataException("Fleet event belongs to another schema, run or repository set.");
    }
    private FleetChildStatus Child(JsonElement m)
    {
        Match(m); string id = Text(m,"child_repository_id"); var root = roots.SingleOrDefault(r => r.RepositoryId == id);
        if (root == null || Text(m,"child_repository_path") != root.RepositoryPath || Text(m,"child_run_id") != FleetSession.ChildRunId(identity,id)) throw new InvalidDataException("Unrelated fleet child identity.");
        string state = Text(m,"state"); string? path = Optional(m,"manifest_path"), hash = Optional(m,"manifest_sha256");
        if (state is not ("queued" or "running" or "completed" or "failed" or "cancelled" or "skipped") ||
            state == "completed" && (path == null || !Path.IsPathFullyQualified(path) || !Hash(hash)) || state != "completed" && (path != null || hash != null)) throw new InvalidDataException("Invalid fleet child completion proof.");
        return new(id,root.RepositoryPath,state,path,hash);
    }
    private void Remember(FleetChildStatus row)
    {
        if (children.TryGetValue(row.RepositoryId,out var previous) && (previous.State is "completed" or "failed" or "cancelled" or "skipped") && previous != row) throw new InvalidDataException("Fleet child changed after terminal state.");
        if (children.TryGetValue(row.RepositoryId,out previous) && previous.State == "running" && row.State == "queued") throw new InvalidDataException("Fleet child progress regressed.");
        children[row.RepositoryId] = row;
    }
    private static bool Hash(string? value) => value?.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static string Text(JsonElement m,string key) => m.GetProperty(key).GetString() ?? throw new InvalidDataException($"Missing fleet {key}.");
    private static string? Optional(JsonElement m,string key) => m.TryGetProperty(key,out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;
}

public sealed class FleetSession
{
    private Process? worker;
    private int admitted;
    public bool CleanupBlocked { get; private set; }
    public static string RepositorySetId(IReadOnlyList<FleetRoot> roots)
    {
        var rows = roots.OrderBy(r => r.RepositoryId,StringComparer.Ordinal).Select(r => "[" + Ascii(r.RepositoryId) + "," + Ascii(Path.GetFullPath(r.RepositoryPath).Replace('/','\\').ToLowerInvariant()) + "]");
        return "fleet:" + Digest("[" + string.Join(",",rows) + "]");
    }
    public static string ChildRunId(FleetGeneration identity,string id) => "child-" + Digest("[" + Ascii(identity.RunId) + "," + identity.Generation + "," + Ascii(id) + "]")[..32];
    private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static string Ascii(string text)
    {
        var s = new StringBuilder("\"");
        foreach (char c in text) s.Append(c switch { '"' => "\\\"", '\\' => "\\\\", '\b' => "\\b", '\f' => "\\f", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t", _ when c < 32 || c > 126 => "\\u" + ((int)c).ToString("x4"), _ => c.ToString() });
        return s.Append('"').ToString();
    }
    public async Task Run(string engine, IReadOnlyList<FleetRoot> repositories,string output,long generation,
        Action<FleetGeneration> started,Action<FleetChildStatus> child,Func<FleetSessionResult,Task> completed,int timeoutSeconds = 600,int maxWorkers = 1)
    {
        if (CleanupBlocked || Interlocked.CompareExchange(ref admitted,1,0) != 0) throw new InvalidOperationException("Fleet active or cleanup unverified.");
        try
        {
            var validation = new FleetWorkspace(); foreach (var root in repositories) validation.Add(root.RepositoryId,root.RepositoryPath);
            var roots = validation.Repositories.ToArray();
            if (roots.Length < 2 || generation < 1 || timeoutSeconds is < 1 or > 86400 || maxWorkers is < 1 or > 4 || !Path.IsPathFullyQualified(output)) throw new InvalidDataException("Invalid fleet request limits or paths.");
            var identity = new FleetGeneration(Guid.NewGuid().ToString("N"),RepositorySetId(roots),generation);
            string runFolder = Path.Combine(output,"native-fleet-" + identity.RunId); Directory.CreateDirectory(runFolder);
            string request = Path.Combine(runFolder,"native-request.json");
            File.WriteAllText(request,JsonSerializer.Serialize(new { schema_version="1.4",kind="fleet_request",run_id=identity.RunId,repository_id=identity.RepositorySetId,generation,revision=0,
                repositories=roots.Select(r => new { repository_id=r.RepositoryId,repository_path=r.RepositoryPath }),output_path=runFolder,max_workers=maxWorkers,options=new { timeout_seconds=timeoutSeconds } }));
            var start = new EngineLaunchSpec(engine).CreateStartInfo(EngineBrokerKind.Worker,request);
            foreach (string key in new[]{"OPENAI_API_KEY","ANTHROPIC_API_KEY","ANTHROPIC_AUTH_TOKEN","OPENAI_BASE_URL","ANTHROPIC_BASE_URL","OPENAI_ORG_ID","OPENAI_PROJECT_ID","ATTACKMAP_ACTION_CREDENTIAL"}) start.Environment.Remove(key);
            var protocol = new FleetProtocol(identity,roots); started(identity);
            using var process = Process.Start(start) ?? throw new IOException("Fleet broker did not start."); worker = process;
            var errors = Drain(process.StandardError);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds + 30));
            try
            {
                while (await ReadLine(process.StandardOutput,deadline.Token) is string line)
                    if (protocol.Accept(line) && protocol.LastChild is { } row) child(row);
                await process.WaitForExitAsync(deadline.Token); await errors;
                if (process.ExitCode != 0 || protocol.Result == null) throw new InvalidDataException("Fleet broker exited without a successful transport terminal.");
                var result = protocol.Result;
                foreach (var row in result.Children.Where(c => c.State == "completed")) await Verify(row.ManifestPath!,row.ManifestHash!,runFolder);
                if (result.IndexPath != null) await Verify(result.IndexPath,result.IndexHash!,runFolder);
                await completed(result);
            }
            finally
            {
                if (!process.HasExited)
                {
                    Disconnect();
                    try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
                    catch (TimeoutException) { CleanupBlocked = true; throw new IOException("Fleet cleanup unverified; further fleet runs blocked."); }
                }
                if (process.HasExited) worker = null;
            }
        }
        finally { if (!CleanupBlocked) Interlocked.Exchange(ref admitted,0); }
    }
    private static async Task Verify(string path,string hash,string root)
    {
        string full = Path.GetFullPath(path);
        if (!full.StartsWith(Path.GetFullPath(root).TrimEnd('\\') + "\\",StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Fleet artifact escaped its owned output.");
        for (string? p = full; p != null; p = Path.GetDirectoryName(p)) if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Redirected fleet artifact.");
        await using var stream = File.OpenRead(full);
        if (stream.Length > 64 * 1024 * 1024 || Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant() != hash) throw new InvalidDataException("Fleet artifact hash changed.");
    }
    public void Cancel() { try { if (worker is { HasExited:false }) { worker.StandardInput.WriteLine("cancel"); worker.StandardInput.Flush(); } } catch (Exception e) when (e is IOException or InvalidOperationException) { } }
    public void Disconnect() { try { if (worker is { HasExited:false }) worker.StandardInput.Close(); } catch (Exception e) when (e is IOException or InvalidOperationException) { } }
    private static async Task Drain(StreamReader reader) { char[] buffer = new char[4096]; while (await reader.ReadAsync(buffer) != 0) { } }
    private static async Task<string?> ReadLine(StreamReader reader,CancellationToken token)
    {
        var text = new StringBuilder(); var buffer = new char[1];
        while (await reader.ReadAsync(buffer.AsMemory(),token) != 0) { if (buffer[0] == '\n') return text.ToString(); if (text.Length >= 65536) throw new InvalidDataException("Fleet message exceeds 64 KiB."); text.Append(buffer[0]); }
        return text.Length == 0 ? null : text.ToString();
    }
}
