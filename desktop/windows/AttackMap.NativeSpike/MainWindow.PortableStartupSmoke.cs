using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.UI.Xaml;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    // Opt-in QA of the normal startup branch: no settings injection, option
    // reset or explicit engine argument may mask a restored legacy path.
    private async void VerifyPortableStartup(object sender, RoutedEventArgs args)
    {
        ((FrameworkElement)Content).Loaded -= VerifyPortableStartup;
        string[] arguments = Environment.GetCommandLineArgs();
        int index = Array.IndexOf(arguments, "--verify-portable-startup");
        string directory = Path.GetFullPath(arguments[index + 1]);
        object? result = null;
        string? failure = null;
        try
        {
            if (!Directory.Exists(directory) || File.Exists(Path.Combine(directory, "normal-startup.json")))
                throw new IOException("Create a fresh caller-owned QA directory.");
            var saved = settings.Load();
            byte[]? before = File.Exists(LocalSettingsStore.DefaultPath) ? File.ReadAllBytes(LocalSettingsStore.DefaultPath) : null;
            string bundle = Path.Combine(AppContext.BaseDirectory, "engine", "attackmap.exe");
            string selected = PythonPath.Text;
            bool legacyExists = File.Exists(saved.PythonPath) && !string.Equals(saved.PythonPath, bundle, StringComparison.OrdinalIgnoreCase);
            if (selected != bundle || arguments.Contains("--expect-existing-legacy-engine") && !legacyExists)
                throw new InvalidDataException("Normal startup did not select the bundle over the expected existing legacy engine.");
            var restoredOptions = ReadScanOptions();
            bool requestedScan = arguments.Contains("--verify-scan");
            if (requestedScan)
            {
                var provider = restoredOptions.Provider;
                if (provider?.EnableAi == true && (provider.Provider != "openai" || provider.Endpoint != "http://127.0.0.1:1234/v1" || provider.Model != "cyberstag-security-26b-a4b-v1"))
                    throw new InvalidDataException("This explicit QA scan permits only the configured local CyberStag model.");
                ScanRepository(ScanButton, new RoutedEventArgs());
                var elapsed = System.Diagnostics.Stopwatch.StartNew();
                while (scanning && elapsed.Elapsed < TimeSpan.FromSeconds(restoredOptions.TimeoutSeconds + 30)) await Task.Delay(200);
                if (scanning || scanProgress.State != "completed" || !scanProgress.Terminal || exportSelection?.Verified != true)
                    throw new InvalidDataException("Normal Start scan did not complete: " + Status.Text);
            }
            byte[]? after = File.Exists(LocalSettingsStore.DefaultPath) ? File.ReadAllBytes(LocalSettingsStore.DefaultPath) : null;
            bool preserved = before == null ? after == null : after != null && before.SequenceEqual(after);
            if (!preserved) throw new InvalidDataException("Global saved settings changed during verification.");
            object? capture = null;
            string? captureFailure = null;
            try { await ReadinessRenderBarrier(); capture = await CaptureStrict((FrameworkElement)Content, Path.Combine(directory, "normal-startup.png")); }
            catch (Exception error) { captureFailure = error.GetType().Name; }
            result = new { passed = true, normalStartupBranch = true, explicitEngineArgument = false, settingsOverride = false,
                personalSettingsRead = true, settingsFilePreserved = preserved, savedEngine = saved.PythonPath, savedEngineExists = legacyExists,
                selectedEngine = selected, restoredOptions, restoredRepository = repositoryPath, restoredModules = ModulesOption.Text,
                startScanHandlerInvoked = requestedScan, scanCompleted = requestedScan && scanProgress.State == "completed", run = displayedRun,
                report = displayedReportPath, reportHash = displayedReadHash, progressState = scanProgress.State, status = Status.Text,
                nativeExecutable = Environment.ProcessPath,
                nativeExeSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!))).ToLowerInvariant(),
                nativeDllSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "AttackMap.NativeSpike.dll")))).ToLowerInvariant(),
                engineSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(bundle))).ToLowerInvariant(),
                capture, captureFailure, acceptedManualUi = false, acceptedAccessibility = false };
        }
        catch (Exception error) { failure = error.ToString(); }
        finally
        {
            try { File.WriteAllText(Path.Combine(directory, "normal-startup.json"), JsonSerializer.Serialize(new { result, failure }, new JsonSerializerOptions { WriteIndented = true })); }
            finally { Close(); }
        }
    }
}
