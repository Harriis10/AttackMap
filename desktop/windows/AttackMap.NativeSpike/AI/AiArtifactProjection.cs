using System.Text.Json;

namespace AttackMap.NativeSpike;

public sealed record AiArtifactPage(string Mode, string ArtifactName, string State, string Notice, string Markdown, string Metadata)
{
    public string Summary { get; init; } = "";
}
public sealed record AiArtifactSnapshot(string Generation, IReadOnlyList<AiArtifactPage> Pages)
{
    public int ProseReadCount { get; init; }
    public int MetadataReadCount { get; init; }
    public int RunManifestReadCount { get; init; }
    public int ReportIntegrityReadCount { get; init; }
}

/// <summary>Pure projection of supplied metadata. No provider calls or source changes.</summary>
public static class AiArtifactProjection
{
    public static readonly string[] Modes = ["review", "hunt", "hunt_verify", "remediate", "triage"];
    public static string ArtifactName(string mode) => mode switch {
        "review" => "defensive-review-llm.md", "hunt" or "hunt_verify" => "vulnerability-hypotheses.md",
        "remediate" => "remediation.md", "triage" => "triage.md", _ => throw new ArgumentException("Unknown AI mode.") };
    public static AiArtifactPage Unavailable(string mode, string reason) => new(mode, ArtifactName(mode), "unavailable", reason, "", "")
    { Summary = $"{mode} · unavailable\n{reason}" };
    private static string Brief(string value)
    {
        string text = new(value.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
        return string.IsNullOrWhiteSpace(text) ? "unknown" : text.Length > 96 ? text[..96] + "…" : text;
    }
    private static string Scalar(JsonElement value) => value.ValueKind == JsonValueKind.String ? Brief(value.GetString()!) : "unknown";
    private static string ProviderName(JsonElement value) => value.ValueKind == JsonValueKind.String ? Scalar(value)
        : value.ValueKind == JsonValueKind.Object && value.TryGetProperty("provider", out var name) ? Scalar(name) : "unknown";
    private static string AllowanceUsage(JsonElement metadata, string source)
    {
        if (!metadata.TryGetProperty("allowance", out var allowance) || allowance.ValueKind != JsonValueKind.Object) return "";
        string status = allowance.TryGetProperty("usage_status", out var supplied) ? Scalar(supplied) : "unknown";
        if (!allowance.TryGetProperty("token_allowance_kind", out var kind) || kind.ValueKind != JsonValueKind.String || kind.GetString() != "output_tokens")
            return $"\nAllowance usage ({source}): {status}; scope: unknown";
        string unknownCalls = allowance.TryGetProperty("unknown_output_usage_calls", out var count) && count.ValueKind == JsonValueKind.Number
            && count.TryGetInt64(out long number) && number >= 0 ? number.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unknown";
        // The shared ledger settles output reservations only; it cannot prove input or per-call usage.
        return $"\nShared output accounting ({source}): {status}; unknown output-usage calls: {unknownCalls}";
    }
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
        string allowanceUsage = AllowanceUsage(root, "artifact allowance");
        string providerName = root.TryGetProperty("provider", out var suppliedProvider) ? ProviderName(suppliedProvider) : "unknown";
        if (runManifest != null)
        {
            using var run = JsonDocument.Parse(runManifest);
            if (run.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Run metadata must be an object.");
            if (run.RootElement.TryGetProperty("desktop_ai", out var ai))
            {
                if (ai.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid desktop AI metadata.");
                requested = Field(ai, "mode");
                if (ai.TryGetProperty("service_parameters", out var service) && service.ValueKind == JsonValueKind.Object)
                {
                    provider = Field(service, "provider");
                    if (service.TryGetProperty("provider", out var serviceProvider)) providerName = ProviderName(serviceProvider);
                }
                if (ai.TryGetProperty("mode", out var requestedMode) && requestedMode.ValueKind == JsonValueKind.String && requestedMode.GetString() == mode)
                {
                    string supplied = ai.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.String ? status.GetString()! : "unknown";
                    state = supplied is "completed" or "partial" or "fallback" or "unavailable" or "not_requested" ? supplied : "unknown";
                    if (state == "completed" && (!ai.TryGetProperty("model_output_available", out var available) || available.ValueKind != JsonValueKind.True)) state = "completion unknown";
                    if (ai.TryGetProperty("allowance", out var runAllowance) && runAllowance.ValueKind == JsonValueKind.Object)
                    {
                        allowance = runAllowance.GetRawText();
                        allowanceUsage = AllowanceUsage(ai, "run allowance");
                    }
                }
            }
        }
        int abstained = Count("abstained_votes"), failed = Count("failed_passes");
        if (backend == "deterministic") state = "deterministic fallback; no completed model response";
        else if (backend is not ("api" or "cli") || Text("model") == "unknown" || string.IsNullOrWhiteSpace(markdown)) state = "unavailable";
        else if (failed > 0 || abstained > 0 || Text("stop_reason") is not ("unknown" or "stop" or "end_turn" or "completed")) state = "partial";
        string references = "unknown", support = "not assessed";
        string referenceSummary = "unknown", supportSummary = "not assessed", referenceScope = "unknown";
        if (root.TryGetProperty("reference_validation", out var validation) && validation.ValueKind == JsonValueKind.Object)
        {
            references = Field(validation, "reference_validity"); support = Field(validation, "claim_support");
            if (validation.TryGetProperty("reference_validity", out var validity)) referenceSummary = Scalar(validity);
            if (validation.TryGetProperty("claim_support", out var claim)) supportSummary = Scalar(claim).Replace('_', ' ');
            if (validation.TryGetProperty("scope", out var scope)) referenceScope = Scalar(scope).Replace('_', ' ');
        }
        string contextSummary = root.TryGetProperty("citation_context", out var context) && context.ValueKind == JsonValueKind.Object
            && context.TryGetProperty("reference_validity", out var contextValidity) ? Scalar(contextValidity).Replace('_', ' ') : "unknown";
        string citationContext = contextSummary == "unknown" ? "" : $"\nCaptured citation context: {contextSummary} (context only)";
        string notice = $"State (supplied metadata): {state}\nRequested mode: {requested}; displayed section: {mode}\nProvider: {provider}; model: {Text("model")}; backend: {backend}\nUsage status: {Text("usage_status")} (artifact metadata); supplied usage: {Field(root, "usage")}{allowanceUsage}\nAllowance: {allowance}\nReference validity: {references}; scope: {referenceScope}{citationContext}\nClaim support: {support}\nJury abstentions: {(root.TryGetProperty("abstained_votes", out _) ? abstained.ToString() : "unknown")}; failed passes: {(root.TryGetProperty("failed_passes", out _) ? failed.ToString() : "unknown")}; consensus: {Field(root, "consensus")}\nModel judgements are not confirmed vulnerabilities. Missing votes are abstentions; reference validity does not establish claim support. Shared output accounting does not establish input or per-call usage. A checked citation context does not validate references in this output. Unknown usage is not zero. Complete supplied metadata follows.";
        string TokenCount(string name) => root.TryGetProperty("usage", out var usage) && usage.ValueKind == JsonValueKind.Object
            && usage.TryGetProperty(name, out var number) && number.ValueKind == JsonValueKind.Number && number.TryGetInt64(out long count) && count >= 0 ? count.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unknown";
        string jury = mode == "hunt_verify" || abstained > 0 || failed > 0
            ? $"\nJury abstentions: {(root.TryGetProperty("abstained_votes", out _) ? abstained.ToString() : "unknown")}; failed passes: {(root.TryGetProperty("failed_passes", out _) ? failed.ToString() : "unknown")}." : "";
        string summary = $"{mode} · {state}\nProvider: {providerName} ({Brief(backend)}); model: {Brief(Text("model"))}\nUsage: {Brief(Text("usage_status"))} (artifact metadata); input tokens: {TokenCount("input_tokens")}; output tokens: {TokenCount("output_tokens")}{allowanceUsage}\nReference validity: {referenceSummary}; Claim support: {supportSummary}\nReference check scope: {referenceScope}{citationContext}{jury}\nModel judgment only; valid references do not confirm claims. Unknown usage is not zero.";
        return new(mode, ArtifactName(mode), state, notice, markdown, metadata) { Summary = summary };
    }
}

/// <summary>All reads pass through the existing captured-manifest safety contract.</summary>
public sealed class AiArtifactWorkspace
{
    private readonly Func<ExportSelection, Task<IReadOnlyList<ArtifactRecord>>> listArtifacts;
    private readonly Func<ExportSelection, ArtifactRecord, int, Task<string>> readText;
    public AiArtifactWorkspace() : this(selected => Task.Run(() => SelectedArtifacts.List(selected))) { }
    internal AiArtifactWorkspace(
        Func<ExportSelection, Task<IReadOnlyList<ArtifactRecord>>> listArtifacts,
        Func<ExportSelection, ArtifactRecord, int, Task<string>>? readText = null)
    {
        this.listArtifacts = listArtifacts;
        this.readText = readText ?? ((selected, record, limit) => SelectedArtifacts.ReadText(selected, record, limit));
    }
    private ExportSelection? selection;
    private long epoch;
    private int stopped;
    public bool IsStopped => Volatile.Read(ref stopped) != 0;
    public void Select(ExportSelection? value) { if (IsStopped) return; selection = value; Interlocked.Increment(ref epoch); }
    public void Cancel() { Interlocked.Increment(ref epoch); selection = null; }
    public void Stop() { Interlocked.Exchange(ref stopped, 1); Cancel(); }
    public async Task<AiArtifactSnapshot?> Load(string mode)
    {
        if (!AiArtifactProjection.Modes.Contains(mode, StringComparer.Ordinal)) throw new ArgumentException("Unknown AI mode.", nameof(mode));
        if (IsStopped) return null;
        var selected = selection; long captured = Volatile.Read(ref epoch);
        bool Current() => !IsStopped && Volatile.Read(ref epoch) == captured && selection == selected;
        if (selected == null || !selected.Verified) return new("unverified", [AiArtifactProjection.Unavailable(mode, "Select a manifest-bound generation. Adjacent files from legacy imports are not read.")]);
        if (!Current()) return null;
        var records = await listArtifacts(selected).ConfigureAwait(false);
        if (!Current()) return null;
        var run = records.SingleOrDefault(r => Path.GetFileName(r.FullPath) == "run-manifest.json");
        string? runText = run == null ? null : await readText(selected, run, 1024 * 1024).ConfigureAwait(false);
        if (!Current()) return null;
        string name = AiArtifactProjection.ArtifactName(mode);
        var prose = records.SingleOrDefault(r => Path.GetFileName(r.FullPath) == name);
        var meta = records.SingleOrDefault(r => Path.GetFileName(r.FullPath) == Path.ChangeExtension(name, ".meta.json"));
        AiArtifactPage page;
        if (prose == null || meta == null)
            page = AiArtifactProjection.Unavailable(mode, "Selected generation does not supply both this output and its metadata. No output generated retroactively.");
        else
        {
            string text = await readText(selected, prose, 4 * 1024 * 1024).ConfigureAwait(false);
            if (!Current()) return null;
            string metadata = await readText(selected, meta, 1024 * 1024).ConfigureAwait(false);
            if (!Current()) return null;
            page = AiArtifactProjection.Project(mode, text, metadata, runText);
        }
        if (!Current()) return null;
        await listArtifacts(selected).ConfigureAwait(false);
        int proseReads = prose != null && meta != null ? 1 : 0;
        int metadataReads = proseReads;
        int runManifestReads = run != null ? 1 : 0;
        return Current() ? new(selected.RunId!, [page])
        {
            ProseReadCount = proseReads,
            MetadataReadCount = metadataReads,
            RunManifestReadCount = runManifestReads,
            ReportIntegrityReadCount = 2 + 2 * (proseReads + metadataReads + runManifestReads)
        } : null;
    }
}
