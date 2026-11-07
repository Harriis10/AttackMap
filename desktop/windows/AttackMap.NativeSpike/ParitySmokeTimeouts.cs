using System.Globalization;
using System.Text.Json.Serialization;

namespace AttackMap.NativeSpike;

/// <summary>Explicit QA allowances; normal product defaults and AI coverage are unchanged.</summary>
public sealed record ParitySmokeTimeouts(
    [property: JsonPropertyName("provider_timeout_seconds")] int ProviderTimeoutSeconds = 900,
    [property: JsonPropertyName("scan_timeout_seconds")] int ScanTimeoutSeconds = 1200,
    [property: JsonPropertyName("harness_timeout_seconds")] int HarnessTimeoutSeconds = 1500)
{
    public static ParitySmokeTimeouts Parse(string[] arguments)
    {
        int Seconds(string flag, int fallback)
        {
            int[] positions = Enumerable.Range(0, arguments.Length).Where(index => arguments[index] == flag).ToArray();
            if (positions.Length > 1 || arguments.Any(value => value.StartsWith(flag + "=", StringComparison.Ordinal)))
                throw new InvalidDataException($"Provide {flag} once, followed by whole seconds.");
            if (positions.Length == 0) return fallback;
            int position = positions[0];
            if (position + 1 >= arguments.Length || !int.TryParse(arguments[position + 1], NumberStyles.None, CultureInfo.InvariantCulture, out int seconds))
                throw new InvalidDataException($"{flag} requires whole seconds.");
            return seconds;
        }
        var value = new ParitySmokeTimeouts(Seconds("--qa-provider-timeout", 900),
            Seconds("--qa-scan-timeout", 1200), Seconds("--qa-harness-timeout", 1500));
        value.Validate();
        return value;
    }

    public void Validate()
    {
        new ProviderConfiguration(TimeoutSeconds: ProviderTimeoutSeconds).Validate();
        new NativeScanOptions(TimeoutSeconds: ScanTimeoutSeconds).Validate();
        if (HarnessTimeoutSeconds is < 1 or > 10800 || ProviderTimeoutSeconds > ScanTimeoutSeconds || ScanTimeoutSeconds >= HarnessTimeoutSeconds)
            throw new InvalidDataException("QA timeouts require provider <= scan < harness, with harness at most 10800 seconds.");
    }
}
