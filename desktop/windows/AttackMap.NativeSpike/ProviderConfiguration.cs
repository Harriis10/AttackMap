using System.Text.Json.Serialization;
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
    public void Validate()
    {
        if (Provider is not ("openai" or "claude")) throw new InvalidDataException("Choose openai or claude.");
        if (MaxCalls is < 1 or > 64 || TimeoutSeconds is < 1 or > 3600 || OutputTokenLimit is < 1 or > 256000) throw new InvalidDataException("AI limits: 1-64 calls, 1-3600 seconds, 1-256000 output tokens.");
        if (Model != null && (Model.Length > 200 || Model.Any(char.IsControl))) throw new InvalidDataException("Invalid provider model.");
        if (!string.IsNullOrWhiteSpace(Endpoint))
        {
            if (Endpoint.Length > 2048 || Endpoint.Any(char.IsControl) || !Uri.TryCreate(Endpoint,UriKind.Absolute,out var uri) || uri.Scheme is not ("http" or "https") || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0 || uri.Host.Length == 0 ||
                (uri.Scheme == "http" && uri.Host.Trim('[',']') is not ("localhost" or "127.0.0.1" or "::1"))) throw new InvalidDataException("Use HTTPS or literal loopback HTTP; no URL credentials, query or fragment.");
        }
    }
}
public sealed class ProviderAccessRequest(ProviderConfiguration configuration,string credential)
{
    public ProviderConfiguration Configuration { get; } = configuration;
    [JsonIgnore] public string Credential { get; } = credential;
    public override string ToString() => "ProviderAccessRequest (credential redacted)";
}
