using System.Diagnostics;
using System.Text.Json;
using AttackMap.NativeSpike;

string python = Path.GetFullPath(args[0]);
string isolated = Path.Combine(Path.GetFullPath(".pytest_cache"), "provider-roundtrip-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(isolated);
string? previous = Environment.GetEnvironmentVariable("LOCALAPPDATA");
Environment.SetEnvironmentVariable("LOCALAPPDATA", isolated);
var checks = new List<string>();
void Check(bool condition, string label) { if (!condition) throw new Exception(label); checks.Add(label); Console.WriteLine("PASS " + label); }
async Task<JsonElement> Restore()
{
    var start = new ProcessStartInfo(python) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
    start.ArgumentList.Add("-c");
    start.ArgumentList.Add("from attackmap.desktop_provider import load_configuration; print(load_configuration().model_dump_json())");
    using var process = Process.Start(start)!;
    string value = await process.StandardOutput.ReadToEndAsync();
    await process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));
    if (process.ExitCode != 0) throw new Exception("Restore process failed; diagnostics omitted");
    using var parsed = JsonDocument.Parse(value); return parsed.RootElement.Clone();
}
try
{
    string configPath = Path.Combine(isolated, "AttackMap", "NativePreview", "provider.json");
    var fresh = await Restore();
    Check(!fresh.GetProperty("enable_ai").GetBoolean() && !File.Exists(configPath), "Fresh isolated restore defaults AI off and creates no settings");
    var config = new ProviderConfiguration(MaxCalls: 3, OutputTokenLimit: 1000);
    var saved = await DesktopActionRunner.Run(python, "provider_save", new { configuration = config }, outputBase: Path.Combine(isolated, "actions"));
    Check(saved.GetProperty("status").GetString() == "saved" && !saved.GetProperty("credential_saved").GetBoolean(), "Actual runner saves credential-free configuration");
    using var disk = JsonDocument.Parse(await File.ReadAllTextAsync(configPath));
    Check(disk.RootElement.GetProperty("schema_version").GetInt32() == 1 && disk.RootElement.GetProperty("configuration").EnumerateObject().All(property => !property.Name.Contains("key") && !property.Name.Contains("credential")), "Saved versioned configuration has no credential fields");
    var restored = await Restore();
    Check(restored.GetProperty("max_calls").GetInt32() == 3 && restored.GetProperty("output_token_limit").GetInt32() == 1000 && !restored.GetProperty("enable_ai").GetBoolean() && restored.GetProperty("endpoint").GetString() == config.Endpoint && restored.GetProperty("model").GetString() == config.Model, "Fresh process restores exact safe settings with AI off");
    var connected = await DesktopActionRunner.Run(python, "provider_check", new { configuration = config }, outputBase: Path.Combine(isolated, "actions"));
    Check(connected.GetProperty("status").GetString() == "connected" && connected.GetProperty("selected_model_listed").GetBoolean(), "Explicit loopback model listing contains selected model");
    var afterCheck = await Restore();
    Check(!afterCheck.GetProperty("enable_ai").GetBoolean(), "Connection check does not enable AI");
    await File.WriteAllTextAsync(args[1], JsonSerializer.Serialize(new { scope = "Actual DesktopActionRunner and Python provider backend; explicit local models listing only, no repository inputs", isolatedLocalAppData = isolated, endpoint = config.Endpoint, model = config.Model, checks, limitations = new[] { "No generation request", "No manual provider panel/dialog acceptance", "No DPAPI credential storage test", "Restore/save paths contain no network operation in inspected production code" } }, new JsonSerializerOptions { WriteIndented = true }));
}
finally { Environment.SetEnvironmentVariable("LOCALAPPDATA", previous); }
