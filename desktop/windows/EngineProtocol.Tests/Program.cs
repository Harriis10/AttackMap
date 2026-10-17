using System.Text.Json;
using System.Text.Json.Nodes;
using AttackMap.NativeSpike;

int checks = 0;
void Check(bool valid, string label) { checks++; if (!valid) throw new Exception(label); }
string fixtures = Path.Combine(AppContext.BaseDirectory, "fixtures");
foreach (string file in Directory.GetFiles(Path.Combine(fixtures, "faults"), "*.json"))
{
    using var document = JsonDocument.Parse(File.ReadAllText(file));
    var fixture = document.RootElement;
    var protocol = new EngineProtocol("run-fixture-1", "repo-fixture", 1);
    foreach (var step in fixture.GetProperty("steps").EnumerateArray())
    {
        string expected = step.GetProperty("expect").GetString()!;
        long before = protocol.Revision;
        try
        {
            bool accepted = step.TryGetProperty("raw", out var raw)
                ? protocol.ParseAndAccept(raw.GetString()!) : protocol.Accept(step.GetProperty("message"));
            Check(expected == (accepted ? "accept" : "ignore"), $"{file}: expected {expected}");
        }
        catch (InvalidDataException error)
        {
            Check(expected == "error", $"{file}: unexpected error {error.Message}");
            Check(error.Message.Length > 10, "Errors must explain the invalid boundary");
            Check(protocol.Revision == before, "Invalid message mutated revision");
        }
    }
    if (fixture.TryGetProperty("terminal", out var terminal)) Check(protocol.Terminal == terminal.GetBoolean(), file + " terminal");
    if (fixture.TryGetProperty("state", out var state)) Check(protocol.CurrentState == state.GetString(), file + " state");
    if (fixture.TryGetProperty("percent", out var percent)) Check(protocol.Percent == (percent.ValueKind == JsonValueKind.Null ? null : percent.GetDouble()), file + " percent");
}
foreach (string version in new[] { "1.0", "1.1" })
{
    var protocol = new EngineProtocol("run-fixture-1", "repo-fixture", 1);
    var golden = JsonNode.Parse(File.ReadAllText(Path.Combine(fixtures, $"terminal-policy-failed-{version}.json")))!;
    // artifact_path is a desktop extension; core ready manifests are verified elsewhere.
    golden["artifact_path"] = "generation/report.json";
    Check(protocol.ParseAndAccept(golden.ToJsonString()), "Golden policy result must be accepted");
    Check(protocol.Terminal && protocol.CurrentState == "completed" && protocol.PolicyOutcome == "failed", "Policy failure is completed execution");
    protocol.EnsureTerminal();
}
try { new EngineProtocol("run-fixture-1", "repo-fixture", 1).EnsureTerminal(); throw new Exception("Missing terminal accepted"); }
catch (InvalidDataException error) { Check(error.Message.Contains("Previous report retained"), "EOF error guidance"); }
Console.WriteLine($"EngineProtocol: {checks} checks passed (pure protocol, no UI acceptance claim).");
