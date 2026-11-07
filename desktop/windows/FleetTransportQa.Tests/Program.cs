using AttackMap.NativeSpike;

string root = Path.Combine(Path.GetTempPath(), "attackmap-fleet-qa-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
int checks = 0;
try
{
    string output = Directory.CreateDirectory(Path.Combine(root, "output")).FullName;
    string package = Directory.CreateDirectory(Path.Combine(root, "package")).FullName;
    string engine = Path.Combine(package, "attackmap.exe"); File.WriteAllText(engine, "not launched");
    string corpus = Directory.CreateDirectory(Path.Combine(root, "shared_datastores")).FullName;
    Directory.CreateDirectory(Path.Combine(corpus, "reader")); Directory.CreateDirectory(Path.Combine(corpus, "writer"));
    string reader = Path.Combine(corpus, "reader", "config.yaml"), writer = Path.Combine(corpus, "writer", "config.json");
    File.WriteAllText(reader, "test reader"); File.WriteAllText(writer, "test writer");
    string[] Args(string? destination = null, string? selectedEngine = null, string? selectedCorpus = null) =>
        ["native.exe", "--fleet-transport-smoke", destination ?? output, selectedEngine ?? engine, selectedCorpus ?? corpus];
    void Check(bool condition) { if (!condition) throw new Exception("QA test failed at " + checks); checks++; }
    void Reject(Action action)
    {
        bool rejected = false;
        try { action(); } catch (Exception error) when (error is ArgumentException or IOException or InvalidDataException) { rejected = true; }
        Check(rejected);
    }
    Check(FleetTransportQaInputs.Read(["native.exe"], package) == null);
    Check(FleetTransportQaInputs.Read(Args(), package) == output);
    Check(!Directory.EnumerateFileSystemEntries(output).Any());
    Check(File.ReadAllText(reader) == "test reader" && File.ReadAllText(writer) == "test writer");
    if (args.Length == 1)
    {
        string realCorpus = Path.GetFullPath(args[0]);
        var before = Directory.GetFiles(realCorpus, "*", SearchOption.AllDirectories).ToDictionary(path => path,
            path => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path))));
        Check(FleetTransportQaInputs.Read(Args(selectedCorpus: realCorpus), package) == output);
        var after = Directory.GetFiles(realCorpus, "*", SearchOption.AllDirectories).ToDictionary(path => path,
            path => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path))));
        Check(before.Count == 2 && before.Count == after.Count && before.All(item => after.GetValueOrDefault(item.Key) == item.Value));
    }
    Reject(() => FleetTransportQaInputs.Read([.. Args(), "--keep-open"], package));
    Reject(() => FleetTransportQaInputs.Read(Args("relative-output"), package));
    Reject(() => FleetTransportQaInputs.Read(Args("\\\\server\\share\\output"), package));
    Reject(() => FleetTransportQaInputs.Read(Args(output + ":stream"), package));
    Reject(() => FleetTransportQaInputs.Read(Args(Path.Combine(output, "..", "output")), package));
    Reject(() => FleetTransportQaInputs.Read(Args("\\\\?\\" + output), package));
    Reject(() => FleetTransportQaInputs.Read(Args(corpus), package));
    string nested = Directory.CreateDirectory(Path.Combine(corpus, "qa")).FullName;
    Reject(() => FleetTransportQaInputs.Read(Args(nested), package));
    string insidePackage = Directory.CreateDirectory(Path.Combine(package, "qa")).FullName;
    Reject(() => FleetTransportQaInputs.Read(Args(insidePackage), package));
    Reject(() => FleetTransportQaInputs.Read(Args(selectedEngine: Path.Combine(package, "missing.exe")), package));
    File.WriteAllText(Path.Combine(output, "existing-proof.json"), "preserve");
    Reject(() => FleetTransportQaInputs.Read(Args(), package));
    Check(File.ReadAllText(Path.Combine(output, "existing-proof.json")) == "preserve");
    string fresh = Directory.CreateDirectory(Path.Combine(root, "fresh")).FullName;
    File.Delete(writer);
    Reject(() => FleetTransportQaInputs.Read(Args(fresh), package));
    Console.WriteLine($"PASS {checks} QA input admission checks; no app, engine or scan launched.");
}
finally
{
    // Only the exact randomly named test-owned directory is removed.
    string resolved = Path.GetFullPath(root);
    string expectedParent = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
    if (Path.GetDirectoryName(resolved) != expectedParent || !Path.GetFileName(resolved).StartsWith("attackmap-fleet-qa-tests-", StringComparison.Ordinal))
        throw new IOException("Refusing cleanup outside test-owned temporary directory.");
    Directory.Delete(resolved, recursive: true);
}
