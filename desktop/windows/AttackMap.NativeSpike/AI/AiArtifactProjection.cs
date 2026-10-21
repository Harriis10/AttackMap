using System.Text.Json;

namespace AttackMap.NativeSpike;

public sealed record AiArtifactPage(string Mode, string ArtifactName, string State, string Notice, string Markdown, string Metadata);
public sealed record AiArtifactSnapshot(string Generation, IReadOnlyList<AiArtifactPage> Pages);

/// <summary>Pure projection of supplied metadata. No provider calls or source changes.</summary>
public static class AiArtifactProjection
{
    public static readonly string[] Modes = ["review", "hunt", "hunt_verify", "remediate", "triage"];
    public static string ArtifactName(string mode) => mode switch {
        "review" => "defensive-review-llm.md", "hunt" or "hunt_verify" => "vulnerability-hypotheses.md",
        "remediate" => "remediation.md", "triage" => "triage.md", _ => throw new ArgumentException("Unknown AI mode.") };
    public static AiArtifactPage Unavailable(string mode, string reason) => new(mode, ArtifactName(mode), "unavailable", reason, "", "");
    public static AiArtifactPage Project(string mode, string markdown, string metadata, string? runManifest = null)
    {
        using var parsed = JsonDocument.Parse(metadata);
        var root = parsed.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("AI metadata must be an object.");
        string Field(JsonElement value, string key) => value.TryGetProperty(key, out var item) && item.ValueKind != JsonValueKind.Null ? item.GetRawText() : "unknown";
        string Text(string key) => root.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString()! : "unknown";
        int Count(string key) {
            if (!root.TryGetProperty(key, out var item)) return 0;
            if (!item.TryGetInt32(out int count) || count < 0) throw new InvalidDataException("Invalid AI count: " + key);
            return count;
        }
        string backend = Text("backend"), state = "available; completion unknown";
        string requested = "unknown", allowance = Field(root, "allowance"), provider = Field(root, "provider");
        if (runManifest != null)
        {
            using var run = JsonDocument.Parse(runManifest);
            if (run.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Run metadata must be an object.");
            if (run.RootElement.TryGetProperty("desktop_ai", out var ai))
            {
                if (ai.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid desktop AI metadata.");
                requested = Field(ai, "mode");
                if (ai.TryGetProperty("service_parameters", out var service) && service.ValueKind == JsonValueKind.Object) provider = Field(service, "provider");
                if (ai.TryGetProperty("mode", out var requestedMode) && requestedMode.ValueKind == JsonValueKind.String && requestedMode.GetString() == mode)
                {
                    string supplied = ai.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.String ? status.GetString()! : "unknown";
                    state = supplied is "completed" or "partial" or "fallback" or "unavailable" or "not_requested" ? supplied : "unknown";
                    if (state == "completed" && (!ai.TryGetProperty("model_output_available", out var available) || available.ValueKind != JsonValueKind.True)) state = "completion unknown";
                    allowance = Field(ai, "allowance");
                }
            }
        }
        int abstained = Count("abstained_votes"), failed = Count("failed_passes");
        if (backend == "deterministic") state = "deterministic fallback; no completed model response";
        else if (backend is not ("api" or "cli") || Text("model") == "unknown" || string.IsNullOrWhiteSpace(markdown)) state = "unavailable";
        else if (failed > 0 || abstained > 0 || Text("stop_reason") is not ("unknown" or "stop" or "end_turn" or "completed")) state = "partial";
        string references = "unknown", support = "not assessed";
        if (root.TryGetProperty("reference_validation", out var validation) && validation.ValueKind == JsonValueKind.Object)
        { references = Field(validation, "reference_validity"); support = Field(validation, "claim_support"); }
        string notice = $"State (supplied metadata): {state}\nRequested mode: {requested}; displayed section: {mode}\nProvider: {provider}; model: {Text("model")}; backend: {backend}\nUsage status: {Text("usage_status")}; supplied usage: {Field(root, "usage")}\nAllowance: {allowance}\nReference validity: {references}\nClaim support: {support}\nJury abstentions: {(root.TryGetProperty("abstained_votes", out _) ? abstained.ToString() : "unknown")}; failed passes: {(root.TryGetProperty("failed_passes", out _) ? failed.ToString() : "unknown")}; consensus: {Field(root, "consensus")}\nModel judgements are not confirmed vulnerabilities. Missing votes are abstentions; reference validity does not establish claim support. Unknown usage is not zero. Complete supplied metadata follows.";
        return new(mode, ArtifactName(mode), state, notice, markdown, metadata);
    }
}

/// <summary>All reads pass through the existing captured-manifest safety contract.</summary>
public sealed class AiArtifactWorkspace
{
    private readonly Func<ExportSelection, Task<IReadOnlyList<ArtifactRecord>>> listArtifacts;
    public AiArtifactWorkspace() : this(selected => Task.Run(() => SelectedArtifacts.List(selected))) { }
    internal AiArtifactWorkspace(Func<ExportSelection, Task<IReadOnlyList<ArtifactRecord>>> listArtifacts)
    { this.listArtifacts = listArtifacts; }
    private ExportSelection? selection;
    private long epoch;
    private int stopped;
    public bool IsStopped => Volatile.Read(ref stopped) != 0;
    public void Select(ExportSelection? value) { if (IsStopped) return; selection = value; Interlocked.Increment(ref epoch); }
    public void Cancel() { Interlocked.Increment(ref epoch); selection = null; }
    public void Stop() { Interlocked.Exchange(ref stopped, 1); Cancel(); }
    public async Task<AiArtifactSnapshot?> Load()
    {
        if (IsStopped) return null;
        var selected = selection; long captured = Volatile.Read(ref epoch);
        bool Current() => !IsStopped && Volatile.Read(ref epoch) == captured && selection == selected;
        if (selected == null || !selected.Verified) return new("unverified", AiArtifactProjection.Modes.Select(mode => AiArtifactProjection.Unavailable(mode, "Select a manifest-bound generation. Adjacent files from legacy imports are not read.")).ToArray());
        if (!Current()) return null;
        var records = await listArtifacts(selected).ConfigureAwait(false);
        if (!Current()) return null;
        var run = records.SingleOrDefault(r => Path.GetFileName(r.FullPath) == "run-manifest.json");
        string? runText = run == null ? null : await SelectedArtifacts.ReadText(selected, run, 1024 * 1024).ConfigureAwait(false);
        if (!Current()) return null;
        var pages = new List<AiArtifactPage>();
        foreach (string mode in AiArtifactProjection.Modes)
        {
            if (!Current()) return null;
            string name = AiArtifactProjection.ArtifactName(mode);
            var prose = records.SingleOrDefault(r => Path.GetFileName(r.FullPath) == name);
            var meta = records.SingleOrDefault(r => Path.GetFileName(r.FullPath) == Path.ChangeExtension(name, ".meta.json"));
            if (prose == null || meta == null) { pages.Add(AiArtifactProjection.Unavailable(mode, "Selected generation does not supply both this output and its metadata. No output generated retroactively.")); continue; }
            string text = await SelectedArtifacts.ReadText(selected, prose).ConfigureAwait(false);
            if (!Current()) return null;
            string metadata = await SelectedArtifacts.ReadText(selected, meta, 1024 * 1024).ConfigureAwait(false);
            if (!Current()) return null;
            pages.Add(AiArtifactProjection.Project(mode, text, metadata, runText));
        }
        if (!Current()) return null;
        await listArtifacts(selected).ConfigureAwait(false);
        return Current() ? new(selected.RunId!, pages) : null;
    }
}
