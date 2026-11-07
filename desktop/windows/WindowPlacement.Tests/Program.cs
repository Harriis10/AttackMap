using System.Text.Json;
using AttackMap.NativeSpike;

var root = Path.Combine(Path.GetTempPath(), "attackmap-placement-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
var path = Path.Combine(root, "žluťoučký", "window.json");
var store = new WindowPlacementStore(path);
int checks = 0;
void Check(bool value) { checks++; if (!value) throw new Exception($"Failed check {checks}"); }
void Reject(Action action)
{
    bool rejected = false;
    try { action(); } catch (Exception e) when (e is InvalidDataException or JsonException) { rejected = true; }
    Check(rejected);
}
try
{
    Check(store.Load() == new WindowPlacement());
    var value = new WindowPlacement(Width: 1600, Height: 1000, Left: -1920, Top: 50);
    store.Save(value); Check(new WindowPlacementStore(path).Load() == value);
    var before = File.ReadAllBytes(path);
    foreach (var invalid in new[] { value with { Width = 1023 }, value with { Height = 699 }, value with { Width = 16385 }, value with { Height = 16385 }, value with { Left = null }, value with { Top = 1_000_001 }, value with { SchemaVersion = 2 } })
    { Reject(() => store.Save(invalid)); Check(File.ReadAllBytes(path).SequenceEqual(before)); }
    Check(!Directory.GetFiles(Path.GetDirectoryName(path)!, "*.tmp").Any());
    store.Save(new WindowPlacement(Width: 1024, Height: 700)); Check(store.Load().Width == 1024);
    store.Save(new WindowPlacement(Width: 16384, Height: 16384, Left: -1_000_000, Top: 1_000_000)); Check(store.Load().Top == 1_000_000);
    foreach (var bad in new[] { "{}", "null", "{", "{\"SchemaVersion\":2}", "{\"SchemaVersion\":1,\"Width\":1}", new string(' ', 4097) })
    { File.WriteAllText(path, bad); Reject(() => store.Load()); Check(File.ReadAllText(path) == bad); }
    store.Clear(); Check(!File.Exists(path)); store.Clear(); Check(store.Load() == new WindowPlacement());
    Console.WriteLine($"{checks} window-placement checks passed; no UI/work-area acceptance claimed");
}
finally { Directory.Delete(root, true); }
