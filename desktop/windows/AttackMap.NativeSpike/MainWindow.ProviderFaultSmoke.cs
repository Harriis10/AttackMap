using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.UI.Xaml;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    // Explicit opt-in only. The constructor routes the stores before any restore;
    // APPDATA/LOCALAPPDATA alone do not redirect Windows known-folder APIs.
    private ProviderFaultQa? providerFaultQa;
    private sealed record ProviderFaultQa(string Root, string Case, string Nonce, string Endpoint, string ExecutionScope,
        string Engine, string EngineSha256, string Seed, string SeedSha256, string FixtureSha256)
    {
        public string Repository => Path.Combine(Root, "fixture-repository");
        public string ActionDirectory => Path.Combine(Root, "actions");
        public string SettingsPath => Path.Combine(Root, "settings.json");
        public string WindowPath => Path.Combine(Root, "window.json");
        public string RecentPath => Path.Combine(Root, "recent-repositories.json");
    }

    private static ProviderFaultQa? ReadProviderFaultSmokeArguments(string[] arguments)
    {
        int index = Array.IndexOf(arguments, "--provider-fault-smoke");
        if (index < 0) return null;
        if (index != 1 || arguments.Length != 3) throw new ArgumentException("Provider fault QA requires exactly one absolute configuration path.");
        string configPath = ProviderFaultLocalPath(arguments[2]);
        if (!File.Exists(configPath) || new FileInfo(configPath).Length > 16384) throw new InvalidDataException("Invalid provider fault configuration.");
        using var parsed = JsonDocument.Parse(File.ReadAllBytes(configPath));
        var root = parsed.RootElement;
        string[] fields = ["schema_version", "scope", "execution_scope", "root", "case", "nonce", "endpoint", "engine", "engine_sha256", "seed", "seed_sha256", "fixture_sha256"];
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != fields.Length ||
            root.EnumerateObject().Select(item => item.Name).Distinct(StringComparer.Ordinal).Count() != fields.Length ||
            root.EnumerateObject().Any(item => !fields.Contains(item.Name)) || root.GetProperty("schema_version").GetInt32() != 1 ||
            root.GetProperty("scope").GetString() != "controlled-provider-fault-fixture")
            throw new InvalidDataException("Unsupported provider fault configuration.");
        string Text(string name) => root.GetProperty(name).GetString() ?? throw new InvalidDataException("Missing QA field.");
        var qa = new ProviderFaultQa(ProviderFaultLocalPath(Text("root")), Text("case"), Text("nonce"), Text("endpoint"), Text("execution_scope"),
            ProviderFaultLocalPath(Text("engine")), Text("engine_sha256"), ProviderFaultLocalPath(Text("seed")), Text("seed_sha256"), Text("fixture_sha256"));
        if (qa.Case is not ("unavailable" or "malformed" or "pending-cancel") || qa.ExecutionScope is not ("packaged" or "source-preview") || !Regex.IsMatch(qa.Nonce, "\\A[a-f0-9]{32}\\z") ||
            !Uri.TryCreate(qa.Endpoint, UriKind.Absolute, out var endpoint) || endpoint.Scheme != "http" || endpoint.Host != "127.0.0.1" ||
            endpoint.Port is <= 1024 or 1234 || endpoint.AbsolutePath != "/v1" || endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0 ||
            qa.Endpoint != $"http://127.0.0.1:{endpoint.Port}/v1") throw new InvalidDataException("QA requires its own literal loopback fixture endpoint.");
        if (!Directory.Exists(qa.Root) || configPath != Path.Combine(qa.Root, "fault-config.json") ||
            (qa.ExecutionScope == "packaged" && !string.Equals(qa.Engine, Path.Combine(AppContext.BaseDirectory, "engine", "attackmap.exe"), StringComparison.OrdinalIgnoreCase)) ||
            !string.Equals(Path.GetFileName(qa.Engine), "attackmap.exe", StringComparison.OrdinalIgnoreCase) || ProviderFaultOverlaps(qa.Root, Path.GetDirectoryName(qa.Engine)!) ||
            !File.Exists(qa.Engine) || !File.Exists(qa.Seed) || !Directory.Exists(qa.Repository) ||
            ProviderFaultOverlaps(qa.Root, AppContext.BaseDirectory) || ProviderFaultOverlaps(qa.Root, Path.GetDirectoryName(qa.Seed)!))
            throw new InvalidDataException("QA paths must be owned, separate from package and seed, and use the bundled engine.");
        foreach (string path in new[] { qa.Repository, qa.ActionDirectory, qa.SettingsPath, qa.WindowPath, qa.RecentPath,
            Path.Combine(qa.Root, "native-proof.json"), Path.Combine(qa.Repository, "app.py") }) ProviderFaultLocalPath(path);
        if (File.Exists(qa.SettingsPath) || File.Exists(qa.WindowPath) || File.Exists(qa.RecentPath) || Directory.Exists(qa.ActionDirectory) ||
            Directory.Exists(Path.Combine(qa.Root, "baseline-reports")) || Directory.Exists(Path.Combine(qa.Root, "fault-reports")) ||
            File.Exists(Path.Combine(qa.Root, "native-proof.json")) || File.Exists(Path.Combine(qa.Root, "native-started.json")))
            throw new IOException("Provider fault QA requires fresh state and output paths.");
        using var owner = JsonDocument.Parse(File.ReadAllBytes(ProviderFaultLocalPath(Path.Combine(qa.Root, "fixture-owner.json"))));
        if (owner.RootElement.GetProperty("nonce").GetString() != qa.Nonce || owner.RootElement.GetProperty("endpoint").GetString() != qa.Endpoint ||
            ProviderFaultHash(qa.Engine) != qa.EngineSha256 || ProviderFaultHash(qa.Seed) != qa.SeedSha256 ||
            ProviderFaultHash(Path.Combine(qa.Repository, "app.py")) != qa.FixtureSha256)
            throw new InvalidDataException("Provider fault input identity mismatch.");
        return qa;
    }

    private static string ProviderFaultLocalPath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal) || path.Any(char.IsControl))
            throw new InvalidDataException("Absolute local QA paths required.");
        string full = Path.GetFullPath(path);
        if (full[Path.GetPathRoot(full)!.Length..].Any(c => c is ':' or '*' or '?' or '"' or '<' or '>' or '|') ||
            new DriveInfo(Path.GetPathRoot(full)!).DriveType != DriveType.Fixed)
            throw new InvalidDataException("Fixed-drive QA paths without alternate streams required.");
        if (!string.Equals(path.TrimEnd(Path.DirectorySeparatorChar), full.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Canonical QA paths required.");
        for (string? current = full; current != null; current = Path.GetDirectoryName(current))
        {
            try { if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Redirected QA paths rejected."); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
        return full;
    }

    private static bool ProviderFaultOverlaps(string first, string second)
    {
        first = Path.GetFullPath(first).TrimEnd(Path.DirectorySeparatorChar);
        second = Path.GetFullPath(second).TrimEnd(Path.DirectorySeparatorChar);
        return first.Equals(second, StringComparison.OrdinalIgnoreCase) || first.StartsWith(second + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            second.StartsWith(first + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string ProviderFaultHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private sealed record ProviderFaultSelection(string Path, string Sha256, string Run, string? ArtifactManifestPath, string? ArtifactManifestSha256);
    private ProviderFaultSelection CaptureProviderFaultSelection()
    {
        var selected = exportSelection ?? throw new InvalidDataException("A verified selected generation is required.");
        if (!selected.Verified || selected.ReportHash != displayedReadHash || selected.RunId != displayedRun ||
            ProviderFaultHash(selected.ReportPath) != displayedReadHash) throw new InvalidDataException("Displayed generation identity mismatch.");
        _ = SelectedArtifacts.List(selected);
        return new(selected.ReportPath, displayedReadHash, displayedRun, selected.ManifestPath, selected.ManifestHash);
    }

    private async void ProviderFaultSmokeLoaded(object sender, RoutedEventArgs args)
    {
        ((FrameworkElement)Content).Loaded -= ProviderFaultSmokeLoaded;
        var qa = providerFaultQa ?? throw new InvalidOperationException("QA was not routed before startup.");
        var checks = new Dictionary<string, bool>();
        ProviderFaultSelection? baseline = null, selected = null;
        string? failure = null, aiState = null;
        bool cancelRequestedAfterHttp = false;
        try
        {
            using (var stream = new FileStream(Path.Combine(qa.Root, "native-started.json"), FileMode.CreateNew))
                JsonSerializer.Serialize(stream, new { qa.Nonce, scope = "controlled-provider-fault-fixture", personalSettingsRead = false });
            if (!await LoadReport(qa.Seed)) throw new InvalidDataException("Seed report failed to load.");
            PythonPath.Text = qa.Engine;
            repositoryPath = qa.Repository;
            presentation.SelectRepository(repositoryPath);
            ApplyScanOptions(new NativeScanOptions(TimeoutSeconds: 120, Provider: new ProviderConfiguration(EnableAi: false)), "python-web,config");
            await RunSelectedRepository(Path.Combine(qa.Root, "baseline-reports"));
            if (!scanProgress.Terminal || scanProgress.State != "completed" || displayedRepository != qa.Repository) throw new InvalidDataException("Deterministic fixture baseline did not complete.");
            baseline = CaptureProviderFaultSelection();
            var previousExport = exportSelection;
            var previousRows = all;
            long previousRevision = findingRevision;
            var provider = new ProviderConfiguration(EnableAi: true, Endpoint: qa.Endpoint, Model: "attackmap-fixture-no-model", MaxCalls: 1, TimeoutSeconds: 30)
                { Mode = "review", Backend = "api", Speed = "standard" };
            ApplyScanOptions(new NativeScanOptions(TimeoutSeconds: 120, Provider: provider), "python-web,config");
            Task scan = RunSelectedRepository(Path.Combine(qa.Root, "fault-reports"));
            if (qa.Case == "pending-cancel")
            {
                var until = System.Diagnostics.Stopwatch.StartNew();
                while (!File.Exists(Path.Combine(qa.Root, "received.json")) && !scan.IsCompleted && until.Elapsed < TimeSpan.FromSeconds(60)) await Task.Delay(50);
                if (!File.Exists(Path.Combine(qa.Root, "received.json")) || scan.IsCompleted) throw new InvalidDataException("Cancellation requires an observed pending fixture POST.");
                using var received = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(qa.Root, "received.json")));
                if (received.RootElement.GetProperty("nonce").GetString() != qa.Nonce) throw new InvalidDataException("Fixture marker identity mismatch.");
                CancelScan(this, new RoutedEventArgs());
                cancelRequestedAfterHttp = true;
            }
            await scan;
            checks["nativeTerminal"] = scanProgress.Terminal;
            checks["cleanupRestoresAdmission"] = !scanning && !engine.CleanupBlocked && !DesktopActionRunner.CleanupBlocked && !fleetSession.CleanupBlocked && ScanButton.IsEnabled && !CancelButton.IsEnabled;
            checks["seedAndEngineUnchanged"] = ProviderFaultHash(qa.Seed) == qa.SeedSha256 && ProviderFaultHash(qa.Engine) == qa.EngineSha256;
            checks["baselineBytesUnchanged"] = ProviderFaultHash(baseline.Path) == baseline.Sha256 && ProviderFaultHash(baseline.ArtifactManifestPath!) == baseline.ArtifactManifestSha256;
            if (qa.Case == "pending-cancel")
            {
                checks["cancelledAfterObservedPost"] = cancelRequestedAfterHttp && scanProgress.State == "cancelled";
                string releasePath = Path.Combine(qa.Root, "release-fixture.json");
                using (var release = new FileStream(releasePath + ".tmp", FileMode.CreateNew)) JsonSerializer.Serialize(release, new { nonce = qa.Nonce });
                File.Move(releasePath + ".tmp", releasePath); // Publish a complete marker to the HTTP owner.
                await Task.Delay(500); // Release the deliberately late fixture response before checking stale publication.
                selected = CaptureProviderFaultSelection();
                checks["previousSelectionPreserved"] = selected == baseline && ReferenceEquals(exportSelection, previousExport) && ReferenceEquals(all, previousRows) && findingRevision == previousRevision;
            }
            else
            {
                checks["deterministicGenerationPublished"] = scanProgress.State == "completed" && displayedRepository == qa.Repository;
                selected = CaptureProviderFaultSelection();
                checks["newGenerationBound"] = selected.Run != baseline.Run && selected.Path != baseline.Path;
                await parityViewBinding;
                var page = await AiArtifacts.SelectMode("review");
                aiState = page?.State;
                Navigation.SelectedItem = Navigation.MenuItems[4];
                AiArtifactsExpander.IsExpanded = true;
                checks["reportsShowsUnavailable"] = page is { Mode: "review", State: "unavailable" };
                string export = Path.Combine(qa.Root, "selected-report-export.json");
                await exportSelection!.Export(export, false);
                checks["selectedExportMatches"] = ProviderFaultHash(export) == selected.Sha256;
            }
        }
        catch (Exception error) { failure = error.GetType().Name + ": " + error.Message; }
        finally
        {
            // The controller independently requires native exit, an empty owned Job,
            // joined HTTP threads, request evidence and artifact metadata before PASS.
            try
            {
                using var stream = new FileStream(Path.Combine(qa.Root, "native-proof.json"), FileMode.CreateNew);
                JsonSerializer.Serialize(stream, new { scope = "controlled-provider-fault-fixture", qa.ExecutionScope, qa.Case, qa.Nonce, qa.Endpoint,
                    baseline, selected, checks, failure, aiState, cancelRequestedAfterHttp, progressState = scanProgress.State,
                    progressTerminal = scanProgress.Terminal, status = Status.Text, personalSettingsRead = false,
                    acceptedWp017Live = false, acceptedManualUi = false, acceptedRelease = false },
                    new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
            }
            finally { Close(); }
        }
    }
}
