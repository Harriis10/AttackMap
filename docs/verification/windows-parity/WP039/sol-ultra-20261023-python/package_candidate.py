"""Build and inspect this exact unsigned bundled candidate, without installing it."""
import json
import sys
from candidate import ROOT, OUT, WORK, CANDIDATE, run, save
from verify_candidate import FREEZE, ENGINE, NATIVE, read
from verify_native import sha


def package():
    # Verify the native bytes again before handing them to the package builder.
    proof = read(OUT / "native-analyzers-03-build-proof.json")
    assert proof["inputs"] == {key: sha(CANDIDATE / key) for key in proof["inputs"]}
    assert proof["payload"] == {str(path.relative_to(NATIVE.parent)): sha(path)
        for path in NATIVE.parent.rglob("*") if path.is_file()}
    captured_native = read(OUT / "candidate-native-inputs.json")
    fixture = "desktop/windows/fixtures/findings.json"
    assert sha(CANDIDATE / fixture) == captured_native["overlay"][fixture]
    run("package-build", [r"C:\Program Files\PowerShell\7\pwsh.exe", "-NoProfile", "-File",
        CANDIDATE / "tools/package_native_windows.ps1", "-PublishDirectory", NATIVE.parent,
        "-OutputDirectory", WORK / "packages", "-EngineDirectory", ENGINE.parent,
        "-EngineVerificationPath", WORK / "frozen-qualification/engine-verification.json",
        "-Profile", "RequiredBundled", "-ReleaseLockPath", FREEZE / "release-lock.json",
        "-SourceRoot", CANDIDATE, "-PythonExecutable", ROOT / ".venv/Scripts/python.exe"], timeout=1200)
    packages = list((WORK / "packages").glob("*/package-manifest.json"))
    assert len(packages) == 1
    folder = packages[0].parent
    run("package-sbom", [ROOT / ".venv/Scripts/python.exe", CANDIDATE / "tools/generate_release_sbom.py",
        "--package", folder, "--output", OUT / "package-sbom", "--engine-venv", ROOT / ".tools/wp024-freeze-venv"])
    save("package-location.json", dict(package=str(folder), zip=str(folder.with_suffix(".zip")),
        zip_sha256=sha(folder.with_suffix(".zip")), manifest_sha256=sha(packages[0]),
        scope="Unsigned development package, captured analyzer slice; no global installation or clean-host/manual acceptance"))


if __name__ == "__main__":
    package()
