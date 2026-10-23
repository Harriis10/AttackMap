using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
namespace AttackMap.NativeSpike;

public sealed record ProviderConfiguration(
    [property: JsonPropertyName("enable_ai")] bool EnableAi = false,
    [property: JsonPropertyName("provider")] string Provider = "openai",
    [property: JsonPropertyName("endpoint")] string? Endpoint = "http://127.0.0.1:1234/v1",
    [property: JsonPropertyName("model")] string? Model = "cyberstag-security-26b-a4b-v1",
    [property: JsonPropertyName("max_calls")] int MaxCalls = 8,
    [property: JsonPropertyName("timeout_seconds")] int TimeoutSeconds = 600,
    [property: JsonPropertyName("output_token_limit")] int OutputTokenLimit = 32000)
{
    [JsonPropertyName("mode"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Mode { get; init; }
    [JsonPropertyName("jury_votes"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public int? JuryVotes { get; init; }
    [JsonPropertyName("effort"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Effort { get; init; }
    [JsonPropertyName("speed"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Speed { get; init; }
    [JsonPropertyName("backend"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Backend { get; init; }
    [JsonIgnore] public bool RequiresSchema13 => Mode != null || JuryVotes != null || Effort != null || Speed != null || Backend != null;
    [JsonIgnore] public string EffectiveMode => EnableAi ? Mode ?? "review" : "none";
    public ProviderConfiguration ForRequest() => EnableAi ? this : this with {
        Mode = null, JuryVotes = null, Effort = null, Speed = null, Backend = null };
    public void ValidateForRequest()
    {
        Validate();
        if (Backend is not (null or "api")) throw new InvalidDataException("CLI backend is unavailable: strict output caps cannot be enforced.");
        if (EnableAi && Mode == "none") throw new InvalidDataException("None mode requires AI to be off.");
        if (JuryVotes != null && EffectiveMode != "hunt_verify") throw new InvalidDataException("Jury votes apply only to Hunt+verify.");
        if (EffectiveMode == "none" && (Effort != null || Speed == "fast")) throw new InvalidDataException("AI tuning requires an enabled mode.");
    }
    public void Validate()
    {
        if (Provider is not ("openai" or "claude")) throw new InvalidDataException("Choose openai or claude.");
        if (MaxCalls is < 1 or > 64 || OutputTokenLimit is < 1 or > 256000) throw new InvalidDataException("AI limits: 1-64 calls, 1-256000 output tokens.");
        if (Model != null && (Model.Length > 200 || Model.Any(char.IsControl))) throw new InvalidDataException("Invalid provider model.");
        if (Mode is not (null or "none" or "review" or "hunt" or "hunt_verify" or "remediate" or "triage") ||
            JuryVotes is < 1 or > 7 || Effort is not (null or "low" or "medium" or "high" or "xhigh" or "max") ||
            Speed is not (null or "standard" or "fast") || Backend is not (null or "api" or "cli"))
            throw new InvalidDataException("Invalid AI mode or tuning preference. Jury range is 1–7.");
        bool extendedLocalAllowance = false;
        if (!string.IsNullOrWhiteSpace(Endpoint))
        {
            if (Endpoint.Length > 2048 || Endpoint.Any(char.IsControl) || !Uri.TryCreate(Endpoint,UriKind.Absolute,out var uri) || uri.Scheme is not ("http" or "https") || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0 || uri.Host.Length == 0 ||
                (uri.Scheme == "http" && uri.Host.Trim('[',']') is not ("localhost" or "127.0.0.1" or "::1"))) throw new InvalidDataException("Use HTTPS or literal loopback HTTP; no URL credentials, query or fragment.");
            // The explicit shared allowance extends only the validated local API path.
            // Match original literal authority too: Uri can normalize numeric IPv4 aliases.
            extendedLocalAllowance = Provider == "openai" && (Backend is null or "api") &&
                uri.Scheme == "http" && uri.Port > 0 && !Endpoint.Contains('?') && !Endpoint.Contains('#') && Regex.IsMatch(Endpoint.Trim(),
                    @"\Ahttp://(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]+)?(?:/|\z)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }
        int timeoutMaximum = extendedLocalAllowance ? 7200 : 3600;
        if (TimeoutSeconds < 1 || TimeoutSeconds > timeoutMaximum)
            throw new InvalidDataException($"AI time allowance must be 1-{timeoutMaximum} seconds; only explicit local OpenAI HTTP API supports up to 7200.");
    }
}
public sealed class ProviderAccessRequest(ProviderConfiguration configuration,string credential)
{
    // Protected provider actions retain their established seven-field contract.
    public ProviderConfiguration Configuration { get; } = configuration with { Mode = null, JuryVotes = null, Effort = null, Speed = null, Backend = null };
    [JsonIgnore] public ProviderConfiguration Preferences { get; } = configuration;
    [JsonIgnore] public string Credential { get; } = credential;
    public override string ToString() => "ProviderAccessRequest (credential redacted)";
}
