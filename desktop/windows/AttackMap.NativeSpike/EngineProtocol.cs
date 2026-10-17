using System.Text.Json;

namespace AttackMap.NativeSpike;

/// <summary>Validates stream metadata, not artifact contents or publication integrity.</summary>
public sealed class EngineProtocol
{
    private readonly string runId;
    private readonly string repository;
    private readonly long generation;
    public string? CurrentState { get; private set; }
    public bool Terminal { get; private set; }
    public long Revision { get; private set; } = -1;
    public string PolicyOutcome { get; private set; } = "not_evaluated";
    public string ArtifactReadiness { get; private set; } = "pending";
    public string? ArtifactPath { get; private set; }
    public double? Percent { get; private set; }

    public EngineProtocol(string runId, string repository, long generation)
    {
        if (string.IsNullOrWhiteSpace(runId) || string.IsNullOrWhiteSpace(repository) || generation < 1)
            throw new ArgumentException("A selected run, repository and positive generation are required.");
        this.runId = runId;
        this.repository = repository;
        this.generation = generation;
    }

    public bool ParseAndAccept(string line)
    {
        if (line.Length > 65536) throw Invalid("Engine message exceeds 64 KiB.");
        try
        {
            using var document = JsonDocument.Parse(line);
            return Accept(document.RootElement);
        }
        catch (JsonException error) { throw new InvalidDataException("Engine returned malformed or truncated JSON. Previous report retained.", error); }
    }

    public bool Accept(JsonElement message)
    {
        if (message.ValueKind != JsonValueKind.Object) throw Invalid("Engine message must be an object.");
        string schema = Text(message, "schema_version");
        if (schema is not ("1.0" or "1.1")) throw Invalid("Unsupported engine schema; supported range is 1.0–1.1. Upgrade the engine or desktop.");
        if (Text(message, "run_id") != runId || Text(message, "repository_id") != repository || Integer(message, "generation") != generation)
            throw Invalid("Engine message does not match the selected run, repository and generation.");
        long incoming = Integer(message, "revision");
        if (incoming < 0) throw Invalid("Engine revision must be nonnegative.");
        if (incoming <= Revision || Terminal) return false;
        string kind = Text(message, "kind");
        string state = Text(message, "state");
        double? percent = null;
        string policy = "not_evaluated", readiness = "pending";
        string? artifact = null;
        if (kind == "progress")
        {
            if (state is not ("queued" or "running" or "cancelling")) throw Invalid("Invalid engine progress state.");
            if (message.TryGetProperty("stage", out var stage) && stage.ValueKind != JsonValueKind.String)
                throw Invalid("Engine stage must be text; a stage named done is still progress.");
            long? completed = OptionalUnits(message, "completed_units");
            long? total = OptionalUnits(message, "total_units");
            if (total.HasValue && (!completed.HasValue || completed > total)) throw Invalid("Bounded progress requires completed units within total units.");
            if (total > 0) percent = 100.0 * completed!.Value / total.Value;
            if ((CurrentState == "running" && state == "queued") ||
                (CurrentState == "cancelling" && state != "cancelling")) return false;
        }
        else if (kind == "terminal")
        {
            string expected = state switch { "completed" => "succeeded", "failed" => "failed", "cancelled" => "cancelled", _ => throw Invalid("Invalid terminal engine state.") };
            if (Text(message, "execution_outcome") != expected) throw Invalid("Terminal state disagrees with execution outcome.");
            policy = OptionalText(message, "policy_outcome", "not_evaluated");
            readiness = OptionalText(message, "artifact_readiness", "unavailable");
            if (policy is not ("not_evaluated" or "passed" or "failed")) throw Invalid("Unknown engine policy outcome.");
            if (readiness is not ("pending" or "ready" or "unavailable")) throw Invalid("Unknown engine artifact readiness.");
            if (state != "completed" && (policy != "not_evaluated" || readiness == "ready"))
                throw Invalid("Failed or cancelled runs cannot publish ready artifacts or a policy result.");
            if (readiness == "ready")
            {
                artifact = Text(message, "artifact_path");
                if (string.IsNullOrWhiteSpace(artifact)) throw Invalid("Ready engine result has no artifact path. Previous report retained.");
            }
        }
        else throw Invalid("Unknown engine message kind; expected progress or terminal.");
        // Commit only after validation, so invalid messages cannot poison revision/state.
        Revision = incoming;
        CurrentState = state;
        Terminal = kind == "terminal";
        PolicyOutcome = policy;
        ArtifactReadiness = readiness;
        ArtifactPath = artifact;
        Percent = percent;
        return true;
    }

    public void EnsureTerminal()
    {
        if (!Terminal) throw Invalid("Engine exited without a terminal result. Previous report retained; inspect the run diagnostic and retry.");
    }

    private static string Text(JsonElement message, string name)
    {
        if (!message.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || value.GetString() is not string text)
            throw Invalid($"Engine message is missing text field {name}.");
        return text;
    }
    private static string OptionalText(JsonElement message, string name, string fallback) => message.TryGetProperty(name, out _) ? Text(message, name) : fallback;
    private static long Integer(JsonElement message, string name)
    {
        if (!message.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out long integer))
            throw Invalid($"Engine message is missing integer field {name}.");
        return integer;
    }
    private static long? OptionalUnits(JsonElement message, string name)
    {
        if (!message.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        long units = Integer(message, name);
        if (units < 0) throw Invalid("Engine progress units must be nonnegative.");
        return units;
    }
    private static InvalidDataException Invalid(string message) => new(message);
}
