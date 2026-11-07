using AttackMap.NativeSpike;
using System.Text.Json;
int checks = 0;
var defaults = new ProviderConfiguration();
defaults.Validate();
Check(!defaults.EnableAi && defaults.Endpoint == "http://127.0.0.1:1234/v1" && defaults.Model == "cyberstag-security-26b-a4b-v1", "disabled local defaults");
Check(defaults.MaxCalls == 8 && defaults.TimeoutSeconds == 600 && defaults.OutputTokenLimit == 32000,"bounded default allowances");
var request = new ProviderAccessRequest(defaults,"CREDENTIAL_SENTINEL");
Check(!JsonSerializer.Serialize(request).Contains("CREDENTIAL_SENTINEL") && !request.ToString().Contains("CREDENTIAL_SENTINEL"),"transient credential excluded from JSON and diagnostics");
using (var json = JsonDocument.Parse(JsonSerializer.Serialize(defaults))) Check(json.RootElement.GetProperty("output_token_limit").GetInt32() == 32000 && !json.RootElement.GetProperty("enable_ai").GetBoolean(),"wire names exact");
foreach(var invalid in new[] { defaults with { MaxCalls=0 }, defaults with { MaxCalls=65 }, defaults with { TimeoutSeconds=0 }, defaults with { TimeoutSeconds=3601 }, defaults with { OutputTokenLimit=0 }, defaults with { OutputTokenLimit=256001 }, defaults with { Provider="other" }, defaults with { Endpoint="http://remote.example/v1" }, defaults with { Endpoint="https://user:secret@remote.example/v1" }, defaults with { Endpoint="https://remote.example/v1?key=secret" }, defaults with { Endpoint="https://remote.example/v1#secret" } })
{
 bool rejected=false; try { invalid.Validate(); } catch(InvalidDataException) { rejected=true; } Check(rejected,"invalid config rejected");
}
var explicitOptIn = defaults with { EnableAi=true, Provider="claude", Endpoint=null, Model=null, MaxCalls=1, TimeoutSeconds=1, OutputTokenLimit=1 };
explicitOptIn.Validate();
Check(JsonSerializer.Deserialize<ProviderConfiguration>(JsonSerializer.Serialize(explicitOptIn)) == explicitOptIn,"explicit safe config roundtrip");
Console.WriteLine($"PASS {checks} provider configuration checks; no network requests");
void Check(bool passed,string name) { if(!passed)throw new Exception(name); checks++; }
