"""Capture the completed analyzer slice over the prior verified baseline."""
import json
import shutil
import sys
from pathlib import Path

from verify_python_batch import ROOT, OUT, WORK, run
from verify_native import sha

CANDIDATE = WORK / "candidate-source"
NATIVE = ["AnalyzerSelectionModel.cs", "AnalyzerSelectionView.cs", "ScanProgressModel.cs",
          "ScanProgressView.cs", "MainWindow.AnalyzerSmoke.cs", "NativeCaptureProbe.cs"]
CORE = ["ecosystem_python.py", "python_route_binding.py", "python_django_routes.py",
        "scanner.py", "analyzer_run_ledger.py", "analyzers.py", "pipeline.py"]


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def copy_bound(relative, origin=ROOT):
    source, target = origin / relative, CANDIDATE / relative
    before = sha(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    assert sha(source) == sha(target) == before
    return before


def prepare():
    CANDIDATE.mkdir()
    baseline = json.loads((OUT / "baseline-captured-source.json").read_text())
    for relative, expected in baseline["files"].items():
        assert copy_bound(relative, Path(baseline["destination"])) == expected
    overlay = {"desktop/windows/AttackMap.NativeSpike/" + name: copy_bound("desktop/windows/AttackMap.NativeSpike/" + name) for name in NATIVE}
    overlay["desktop/windows/fixtures/findings.json"] = copy_bound("desktop/windows/fixtures/findings.json")
    save("candidate-native-inputs.json", dict(source=str(CANDIDATE), baseline="baseline-captured-source.json", overlay=overlay,
         scope="Prior verified baseline plus current analyzer UI only; concurrent fleet sources deliberately excluded"))


def native(label):
    project = CANDIDATE / "desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj"
    inputs = {str(path.relative_to(CANDIDATE)): sha(path) for path in project.parent.rglob("*")
              if path.is_file() and not any(part in {"bin", "obj"} for part in path.parts)}
    save(label + "-inputs-before.json", inputs)
    empty = WORK / label / "empty-feed"
    empty.mkdir(parents=True)
    dotnet = ROOT / ".tools/dotnet/dotnet.exe"
    run(label + "-restore", [dotnet, "restore", project, "-r", "win-x64", "--source", empty,
                             "--ignore-failed-sources", "-p:NuGetAudit=false"])
    output = WORK / label / "publish"
    folder = run(label, [dotnet, "publish", project, "--no-restore", "-c", "Release", "-r", "win-x64",
        "--self-contained", "true", "-o", output, "-p:NuGetAudit=false", "-p:UseSharedCompilation=false", "-nodeReuse:false"], timeout=600)
    after = {path: sha(CANDIDATE / path) for path in inputs}
    save(label + "-inputs-after.json", after)
    assert after == inputs
    save(label + "-build-proof.json", dict(inputs=inputs, output=str(output), inputs_unchanged=True,
         payload={str(path.relative_to(output)): sha(path) for path in output.rglob("*") if path.is_file()},
         scope="Native analyzer UI captured-source build; runtime/visual verification separate"))


def seal():
    changes = {"src/attackmap/" + name: copy_bound("src/attackmap/" + name) for name in CORE}
    save("candidate-python-inputs.json", dict(source=str(CANDIDATE), overlay=changes,
         scope="Captured analyzer delta over verified baseline; excludes concurrent fleet changes"))


def refresh_native():
    overlay = {"desktop/windows/AttackMap.NativeSpike/" + name: copy_bound("desktop/windows/AttackMap.NativeSpike/" + name) for name in NATIVE}
    save("candidate-native-final-inputs.json", dict(source=str(CANDIDATE), overlay=overlay))


def freeze(label):
    run(label, [ROOT / ".venv/Scripts/python.exe", ROOT / "docs/verification/windows-parity/WP024/fresh_freeze.py",
        "--root-released", "--repo", CANDIDATE, "--output", WORK / label,
        "--freeze-python", ROOT / ".tools/wp024-freeze-venv/Scripts/python.exe",
        "--dotnet", ROOT / ".tools/dotnet/dotnet.exe",
        "--analyzer-audit", ROOT / "docs/verification/windows-parity/WP024/cached-analyzer-audit-2026-10-21.json",
        "--wheelhouse", ROOT / ".tools/wp024-wheelhouse", "--build"], timeout=1200)


if __name__ == "__main__":
    operation = sys.argv[1]
    if operation == "prepare": prepare()
    elif operation == "native": native(sys.argv[2])
    elif operation == "seal": seal()
    elif operation == "refresh-native": refresh_native()
    elif operation == "freeze": freeze(sys.argv[2])
    else: raise SystemExit("Unknown operation")
