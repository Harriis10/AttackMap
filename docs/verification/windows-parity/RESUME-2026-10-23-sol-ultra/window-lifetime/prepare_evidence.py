"""Prepare hash-bound proposals and a source-extracted, non-WinUI regression harness.

This script never edits product source. Run from this evidence directory's
repository checkout. Existing proposals are refused rather than overwritten.
"""
from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = ROOT / "desktop/windows/AttackMap.NativeSpike/MainWindow.xaml.cs"
EXPECTED = "caf33b7d20e835a70bf8c8e8fd4da5a3dd4f15e04586861d03227101972a2663"
RELATIVE = SOURCE.relative_to(ROOT).as_posix()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise RuntimeError(f"Expected one preimage: {before!r}")
    return text.replace(before, after, 1)


def method(text: str, signature: str) -> str:
    # Next same-indentation method, including any braces inside interpolated text.
    start = text.index("    private " + signature)
    end = text.find("\n    private ", start + len(signature))
    if end < 0:
        raise RuntimeError(f"No following method after {signature}")
    return text[start:end].rstrip()


def write_fresh(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def patch(before: str, after: str) -> bytes:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="a/" + RELATIVE, tofile="b/" + RELATIVE, n=3,
    )).encode()


def extract_class(source: str, variant: str) -> str:
    methods = "\n\n".join(method(source, signature) for signature in (
        "async Task<bool> LoadReport(string path, RunIdentity? identity = null)",
        "async Task LoadData()",
        "void Navigate(NavigationView sender, NavigationViewSelectionChangedEventArgs args)",
        "void NetworkOptionChanged(object sender, RoutedEventArgs args)",
        "void CaptureWindowPlacement()",
    ))
    early = "ready = false; ++generation; actionLifetime.Cancel();"
    late_before = "actionLifetime.Cancel(); keyboardBindings?.Dispose(); engine.Disconnect();"
    late_after = "keyboardBindings?.Dispose(); engine.Disconnect();"
    before_parity = source.index("        InitializeParityWorkspace();")
    has_early = source.find("Closed += (_, _) => { " + early + " };")
    if variant != "Baseline" and not 0 <= has_early < before_parity:
        raise RuntimeError("Early invalidation must precede parity/workspace registration")
    late = late_before if variant == "Baseline" else late_after
    if source.count("Closed += (_, _) => { " + late + " };") != 1:
        raise RuntimeError("Late cleanup body changed")
    # Only the first and cleanup callbacks are extracted from production. The
    # middle callback is an explicit observer standing in for existing parity /
    # workspace subscriber order, not a native cleanup implementation.
    prefix = f"        {early}\n" if variant != "Baseline" else ""
    wrapper = f"""
public sealed class {variant}Window : WindowFixture, IWindowScenario
{{
    public Task<bool> Load(string path) => LoadReport(path);
    public Task Fixture() => LoadData();
    public void SendNavigation() => Navigate(Navigation, new() {{ SelectedItem = new NavigationViewItem {{ Content = "Overview" }} }});
    public void SendNetwork() => NetworkOptionChanged(this, new());
    public void SendPlacement() => CaptureWindowPlacement();
    public void Close()
    {{
{prefix}        ObserveMiddleClosedSubscriber();
        {late}
    }}
{methods}
}}
"""
    return wrapper


def main() -> None:
    raw = SOURCE.read_bytes()
    if sha(raw) != EXPECTED:
        raise RuntimeError("Shared MainWindow preimage changed; root must review/rebase")
    before = raw.decode("utf-8").replace("\r\n", "\n")
    core = replace_once(before, "        InitializeComponent();\n        InitializeParityWorkspace();",
        "        InitializeComponent();\n        Closed += (_, _) => { ready = false; ++generation; actionLifetime.Cancel(); };\n        InitializeParityWorkspace();")
    core = replace_once(core,
        "        Closed += (_, _) => { actionLifetime.Cancel(); keyboardBindings?.Dispose(); engine.Disconnect(); };",
        "        Closed += (_, _) => { keyboardBindings?.Dispose(); engine.Disconnect(); };")
    # Both ready-guarded handlers use exactly this guard in the inspected source.
    if core.count("        if (!ready) return;") != 2:
        raise RuntimeError("Navigate/NetworkOptionChanged ready guards changed")
    core = core.replace("        if (!ready) return;", "        if (!ready || actionLifetime.IsCancellationRequested) return;")
    core = replace_once(core,
        "    private async Task<bool> LoadReport(string path, RunIdentity? identity = null)\n    {\n        long current",
        "    private async Task<bool> LoadReport(string path, RunIdentity? identity = null)\n    {\n        if (actionLifetime.IsCancellationRequested) return false;\n        long current")
    core = replace_once(core,
        '            if (current == generation) Status.Text = $"Report import failed',
        '            if (!actionLifetime.IsCancellationRequested && current == generation) Status.Text = $"Report import failed')
    optional = replace_once(core,
        "    private async Task LoadData()\n    {\n        long current",
        "    private async Task LoadData()\n    {\n        if (actionLifetime.IsCancellationRequested) return;\n        long current")
    optional = replace_once(optional,
        '            Status.Text = $"Fixture unavailable ({error.GetType().Name}). Generate it and retry Load fixture.";',
        '            if (!actionLifetime.IsCancellationRequested && current == generation) Status.Text = $"Fixture unavailable ({error.GetType().Name}). Generate it and retry Load fixture.";')
    optional = replace_once(optional,
        "        if (!placementPersistenceEnabled || ((FrameworkElement)Content).XamlRoot == null",
        "        if (actionLifetime.IsCancellationRequested || !placementPersistenceEnabled || ((FrameworkElement)Content).XamlRoot == null")
    outputs = {
        "MainWindow.before.cs.txt": raw,
        "MainWindow.core.cs.txt": core.replace("\n", "\r\n").encode(),
        "MainWindow.core-plus-optional.cs.txt": optional.replace("\n", "\r\n").encode(),
        "core.patch": patch(before, core),
        "optional-after-core.patch": patch(core, optional),
    }
    template = (HERE / "Harness.template.cs.txt").read_text(encoding="utf-8")
    outputs["harness/ExtractedWindows.cs"] = ("using System.Text.Json;\nnamespace LifetimeRegression;\n" +
        "\n".join(extract_class(source, name) for source, name in (
            (before, "Baseline"), (core, "Core"), (optional, "Optional")))).encode()
    outputs["harness/Program.cs"] = template.encode()
    outputs["harness/NativeStandins.cs"] = b'''namespace Microsoft.UI.Windowing;
public enum OverlappedPresenterState { Restored }
public class OverlappedPresenter { public OverlappedPresenterState State => OverlappedPresenterState.Restored; }
'''
    outputs["harness/LifetimeRegression.csproj"] = b'''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable>
    <RestoreSources></RestoreSources><RestoreIgnoreFailedSources>true</RestoreIgnoreFailedSources>
  </PropertyGroup>
</Project>
'''
    outputs["harness/NuGet.Config"] = b'<configuration><packageSources><clear /></packageSources></configuration>\n'
    pins = {
        "base_commit": "507bddacd72a246a136ca2d46faad2aa661806c1",
        "source": RELATIVE,
        "preimage_sha256": sha(raw),
        "core_postimage_sha256": sha(outputs["MainWindow.core.cs.txt"]),
        "optional_postimage_sha256": sha(outputs["MainWindow.core-plus-optional.cs.txt"]),
        "artifacts_sha256": {name: sha(data) for name, data in outputs.items()},
        "other_inspected_sources_sha256": {
            str(path.relative_to(ROOT)).replace("\\", "/"): sha(path.read_bytes())
            for path in (ROOT / "desktop/windows/AttackMap.NativeSpike" / name for name in (
                "MainWindow.Parity.cs", "MainWindow.Workspaces.cs", "App.xaml.cs", "NativeAccessibility.cs"))
        },
        "scope": "Isolated compiled method-body regression with fake controls/read boundaries; no WinUI, provider, GUI, native build, or package acceptance",
    }
    for name, data in outputs.items():
        write_fresh(HERE / name, data)
    write_fresh(HERE / "pins.json", (json.dumps(pins, indent=2) + "\n").encode())
    print(json.dumps({"source_preimage_unchanged": sha(SOURCE.read_bytes()) == EXPECTED,
        "patches": {key: sha(outputs[key]) for key in ("core.patch", "optional-after-core.patch")}}))


if __name__ == "__main__":
    main()
