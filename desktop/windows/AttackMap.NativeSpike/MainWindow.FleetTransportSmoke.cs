using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

// QA-only: host wiring is explicit; never restores personal state or substitutes an engine.
public sealed partial class MainWindow
{
    private string? fleetTransportQaDirectory;
    private JsonElement? fleetTransportQaPreflight;

    private static string? ReadFleetTransportSmokeDirectory(string[] arguments) =>
        FleetTransportQaInputs.Read(arguments, AppContext.BaseDirectory);

    // Called only with the actual RunFleet preflight request and broker response.
    private void CaptureFleetTransportPreflight(JsonElement request, JsonElement response)
    {
        if (fleetTransportQaDirectory == null) return;
        fleetTransportQaPreflight = JsonSerializer.SerializeToElement(new { request, response,
            expected_identity = capabilityCache.Current?.ExpectedIdentity });
        using var stream = new FileStream(Path.Combine(fleetTransportQaDirectory, "preflight.json"), FileMode.CreateNew);
        JsonSerializer.Serialize(stream, fleetTransportQaPreflight);
    }

    private async void FleetTransportSmokeLoaded(object sender, RoutedEventArgs args)
    {
        ((FrameworkElement)Content).Loaded -= FleetTransportSmokeLoaded;
        string[] arguments = Environment.GetCommandLineArgs();
        string directory = fleetTransportQaDirectory ?? throw new InvalidOperationException("QA isolation was not initialized.");
        string corpus = Path.GetFullPath(arguments[4]);
        string? failure = null;
        var checks = new List<object>();
        object? actualRequest = null;
        object? terminal = null;
        object? fixtureIdentity = null;
        var started = DateTimeOffset.UtcNow;
        void Check(string name, bool passed)
        {
            checks.Add(new { name, passed });
            if (!passed) throw new InvalidDataException("Fleet transport QA failed: " + name);
        }
        try
        {
            using (var claim = new FileStream(Path.Combine(directory, "started"), FileMode.CreateNew)) { }
            var fixtureFiles = new[] { Path.Combine(corpus, "reader", "config.yaml"), Path.Combine(corpus, "writer", "config.json") };
            var fixtureHashes = fixtureFiles.ToDictionary(path => path, path => ExportSelection.Hash(File.ReadAllBytes(path)));
            fixtureIdentity = fixtureHashes;
            Check("empty_workspace", Fleet.Workspace.Repositories.Count == 0 && !WorkspaceBusy());
            PythonPath.Text = Path.GetFullPath(arguments[3]);
            Fleet.WatchRequested = false;
            foreach (string id in new[] { "reader", "writer" }) Fleet.Workspace.Add(id, Path.Combine(corpus, id));
            Fleet.SetExecutionOptions(new FleetExecutionOptions(TimeoutSeconds: 180, MaxWorkers: 1));
            Fleet.Refresh();
            ApplyScanOptions(new NativeScanOptions(Cve: false, TimeoutSeconds: 180,
                IsolatedAnalyzers: true, TimeBudgetSeconds: 30), "config");
            Check("network_options_disabled", !Provider.ReadConfiguration().EnableAi && !ReadScanOptions().Cve);
            Navigation.SelectedItem = Navigation.MenuItems.OfType<NavigationViewItem>().Single(item => item.Content?.ToString() == "Fleet");
            await RunFleet(Fleet.SelectedRoots.ToArray(), verificationOutput: Path.Combine(directory, "reports"));
            Check("actual_supported_preflight_captured", fleetTransportQaPreflight is { } proof &&
                proof.GetProperty("response").GetProperty("supported").GetBoolean());
            var identity = Fleet.Workspace.Active ?? throw new InvalidDataException("No fleet was launched.");
            string requestPath = Path.Combine(directory, "reports", "native-fleet-" + identity.RunId, "native-request.json");
            byte[] requestBytes = await File.ReadAllBytesAsync(requestPath);
            using var parsed = JsonDocument.Parse(requestBytes);
            var request = parsed.RootElement;
            var options = request.GetProperty("options");
            actualRequest = new { path = requestPath, sha256 = ExportSelection.Hash(requestBytes), payload = request.Clone() };
            terminal = new { identity, Fleet.Workspace.Outcome, children = Fleet.Workspace.Children.ToArray() };
            Check("actual_worker_options", options.GetProperty("isolated_analyzers").GetBoolean() &&
                options.GetProperty("time_budget_seconds").GetInt32() == 30 && options.GetProperty("timeout_seconds").GetInt32() == 180 &&
                !options.GetProperty("cve").GetBoolean() && request.GetProperty("modules").EnumerateArray().Select(item => item.GetString()).SequenceEqual(new[] { "config" }) &&
                request.GetProperty("max_workers").GetInt32() == 1);
            Check("actual_request_identity", request.GetProperty("run_id").GetString() == identity.RunId &&
                request.GetProperty("repository_id").GetString() == identity.RepositorySetId &&
                request.GetProperty("generation").GetInt64() == identity.Generation);
            var preflightRequest = fleetTransportQaPreflight!.Value.GetProperty("request");
            Check("preflight_matches_worker_selection", preflightRequest.GetProperty("options").GetRawText() == options.GetRawText() &&
                preflightRequest.GetProperty("modules").GetRawText() == request.GetProperty("modules").GetRawText() &&
                preflightRequest.GetProperty("repositories").GetRawText() == request.GetProperty("repositories").GetRawText() &&
                preflightRequest.GetProperty("repository_id").GetString() == identity.RepositorySetId);
            Check("verified_terminal_two_children", Fleet.Workspace.IsCurrent && !Fleet.Workspace.IsRunning &&
                Fleet.Workspace.Outcome == "succeeded" && Fleet.Workspace.Children.Count == 2 &&
                Fleet.Workspace.Children.All(child => child.State == "completed" && child.ManifestHash?.Length == 64));
            Check("native_cleanup_settled", !scanning && !fleetRunning && !fleetSession.CleanupBlocked && !DesktopActionRunner.CleanupBlocked);
            Check("fixture_bytes_unchanged", fixtureHashes.All(item => ExportSelection.Hash(File.ReadAllBytes(item.Key)) == item.Value));
        }
        catch (Exception error) { failure = error.ToString(); Environment.ExitCode = 1; }
        finally
        {
            try
            {
                using var stream = new FileStream(Path.Combine(directory, "native-fleet-transport.json"), FileMode.CreateNew);
                JsonSerializer.Serialize(stream, new { passed = failure == null, started, ended = DateTimeOffset.UtcNow,
                    acceptanceScope = "Native fleet transport only; no summary-load, pixel or manual UI acceptance",
                    failure, checks, actualRequest, terminal, fixtureIdentity, engineIdentity = capabilityCache.Current?.ExpectedIdentity,
                    cleanupBlocked = fleetSession.CleanupBlocked || DesktopActionRunner.CleanupBlocked,
                    cleanupScope = "Native broker completion and cleanup flags; external owned-process census still required",
                    manualVisualAcceptance = false, liveProviderCalls = 0 }, new JsonSerializerOptions { WriteIndented = true });
                stream.Flush(flushToDisk: true);
            }
            finally { Close(); }
        }
    }
}
