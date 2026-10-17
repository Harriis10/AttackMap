using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AttackMap.NativeSpike;

if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Actual Windows protected storage is required.");
string frozen = Path.GetFullPath(args[0]), python = Path.GetFullPath(args[1]), proofPath = Path.GetFullPath(args[2]);
if (File.Exists(proofPath)) throw new IOException("Use fresh proof path.");
string isolated = Path.Combine(Path.GetFullPath(".pytest_cache"), "protected-provider-store-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(isolated);
string blobPath = Path.Combine(isolated, "AttackMap", "llm-openai.key");
string nonce = "synthetic-qa-" + Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
string? previousLocal = Environment.GetEnvironmentVariable("LOCALAPPDATA");
var checks = new List<string>();
void Check(bool passed, string name) { if (!passed) throw new Exception(name); checks.Add(name); Console.WriteLine("PASS " + name); }
int protectedLength = 0;
try
{
    Environment.SetEnvironmentVariable("LOCALAPPDATA", isolated);
    var saved = await DesktopActionRunner.Run(frozen, "provider_save", new { configuration = new ProviderConfiguration() }, credential: nonce, outputBase: Path.Combine(isolated, "actions"));
    Check(saved.GetProperty("credential_saved").GetBoolean() && saved.GetProperty("status").GetString() == "saved", "Frozen provider save reports protected credential saved");
    byte[] blob = await File.ReadAllBytesAsync(blobPath); protectedLength = blob.Length;
    Check(blob.AsSpan().IndexOf(Encoding.UTF8.GetBytes(nonce)) < 0 && blob.AsSpan().IndexOf(Encoding.Unicode.GetBytes(nonce)) < 0, "Protected blob excludes plaintext synthetic credential");
    byte[] dpapiHeader = Convert.FromHexString("01000000D08C9DDF0115D1118C7A00C04FC297EB");
    Check(blob.AsSpan().StartsWith(dpapiHeader), "Actual Windows DPAPI blob header present");
    var start = new ProcessStartInfo(python) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
    start.ArgumentList.Add("-c");
    start.ArgumentList.Add("import os,json; from attackmap.ui.secrets import load_llm_key; from attackmap.desktop_provider import load_configuration; value=load_llm_key('openai',allow_environment=False); print(json.dumps({'roundtrip_matches':value==os.environ.pop('ATTACKMAP_QA_EXPECTED'),'ai_off':not load_configuration().enable_ai}))");
    start.Environment["LOCALAPPDATA"] = isolated;
    start.Environment["ATTACKMAP_QA_EXPECTED"] = nonce;
    foreach (string key in new[] { "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ATTACKMAP_ACTION_CREDENTIAL" }) start.Environment.Remove(key);
    using var load = Process.Start(start)!;
    var loadedOutput = load.StandardOutput.ReadToEndAsync(); var loadedError = load.StandardError.ReadToEndAsync();
    await load.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));
    string output = await loadedOutput, error = await loadedError;
    Check(load.ExitCode == 0 && !output.Contains(nonce) && !error.Contains(nonce), "Existing production load API process exits without credential disclosure");
    using var loaded = JsonDocument.Parse(output);
    Check(loaded.RootElement.GetProperty("roundtrip_matches").GetBoolean(), "Production load_llm_key protected roundtrip matches synthetic input");
    Check(loaded.RootElement.GetProperty("ai_off").GetBoolean(), "Protected save and restore retain AI off");
    string configPath = Path.Combine(isolated, "AttackMap", "NativePreview", "provider.json");
    using var config = JsonDocument.Parse(await File.ReadAllTextAsync(configPath));
    Check(!config.RootElement.GetProperty("configuration").GetProperty("enable_ai").GetBoolean() && !config.RootElement.GetProperty("configuration").EnumerateObject().Any(property => property.Name.Contains("credential") || property.Name.Contains("key")), "Safe configuration JSON has no credential fields");
    foreach (string file in Directory.GetFiles(isolated, "*.json", SearchOption.AllDirectories)) Check(!(await File.ReadAllTextAsync(file)).Contains(nonce), "No synthetic credential in isolated JSON snapshot " + Path.GetFileName(file));
    Check(!saved.GetRawText().Contains(nonce), "Returned action JSON excludes synthetic credential");
}
finally
{
    Environment.SetEnvironmentVariable("LOCALAPPDATA", previousLocal);
    // Only the synthetic blob in the fresh owned directory is removed; no personal store is visited.
    if (File.Exists(blobPath)) File.Delete(blobPath);
}
Check(!File.Exists(blobPath), "Owned synthetic protected credential blob removed");
await File.WriteAllTextAsync(proofPath, JsonSerializer.Serialize(new { scope = "Actual frozen provider_save via production DesktopActionRunner, actual Windows DPAPI, isolated production load_llm_key API process", frozen, frozenSha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(frozen))), isolatedLocalAppData = isolated, protectedLength, credentialBlobRemoved = true, endpoint = "http://127.0.0.1:1234/v1", model = "cyberstag-security-26b-a4b-v1", checks, loadApiSourceSha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync("src/attackmap/ui/secrets.py"))), limitations = new[] { "No provider_load desktop action exists; load uses existing production Python load_llm_key(allow_environment=False)", "No independent cryptographic decrypt implementation", "No personal protected store access, real keys or connection/model request", "No native panel, dialog, keyboard, Narrator or installer acceptance claim" } }, new JsonSerializerOptions { WriteIndented = true }));
