namespace AttackMap.NativeSpike;

/// <summary>Explicit fleet allowances; selecting many roots does not silently change resource policy.</summary>
public sealed record FleetExecutionOptions(int TimeoutSeconds = 600, int MaxWorkers = 1)
{
    public void Validate()
    {
        if (TimeoutSeconds is < 1 or > 86400 || MaxWorkers is < 1 or > 4)
            throw new InvalidDataException("Fleet requires a 1–86400 second total allowance and 1–4 workers.");
    }
    public string Notice => $"Fleet allowance: {TimeoutSeconds} s total; at most {MaxWorkers} repository worker(s). " +
        "Each child has its own captured snapshot. Count admission does not prove an OS memory cap.";
}
