import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

root = Path.cwd()
proof = root / "docs/verification/windows-parity/WP024/startscan-fix-20261022"
build = proof / "build"
native = root / "desktop/windows/artifacts/integrated-20261022-portable-startscan-fix"
original = root / "desktop/windows/artifacts/AttackMap-Windows-Portable-20261022/AttackMap-Windows"
candidate = root / ".tmp/portable-startscan-candidate-20261022"
run = proof / "normal-startup"
run.mkdir()
audit = run / "http-audit"
audit.mkdir()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


native_proof = json.loads((build / "build-inputs-after.json").read_text())
assert native_proof["inputs_unchanged"] is True
native_proof["build_id"] = "integrated-20261022-portable-startscan-fix"
(build / "native-build.json").write_text(json.dumps(native_proof, indent=2) + "\n", encoding="utf-8")
shutil.copytree(native, candidate, ignore=shutil.ignore_patterns("*.pdb", "*.log"))
shutil.copytree(original / "engine", candidate / "engine")
(candidate / "portable-manifest.json").write_text(json.dumps({
    "schema_version": 1, "kind": "portable-development-preview",
    "runtime": {"engine": "engine/attackmap.exe"}}) + "\n", encoding="utf-8")
for name in ("AttackMap.NativeSpike.exe", "AttackMap.NativeSpike.dll"):
    assert sha(candidate / name) == native_proof["artifacts"][name]["sha256"]
assert sha(candidate / "engine/attackmap.exe") == "ee90e44a35d283326fe3821666e71b33fbd0a1eb3aa6844e827d9d4206ea7195"
settings = Path(os.environ["LOCALAPPDATA"]) / "AttackMap/NativePreview/settings.json"
settings_hash = sha(settings)
environment = dict(os.environ)
for key in list(environment):
    if key.upper().startswith(("PYTHON", "VIRTUAL_ENV", "CONDA", "OPENAI_", "ANTHROPIC_", "ATTACKMAP_QA_")):
        environment.pop(key)
environment["PATH"] = environment["SYSTEMROOT"] + "\\System32;" + environment["SYSTEMROOT"]
environment.update(ATTACKMAP_QA_HTTP_AUDIT_DIR=str(audit), ATTACKMAP_QA_HTTP_AUDIT_NONCE="startscanfix")
args = [str(candidate / "AttackMap.NativeSpike.exe"), "--verify-portable-startup", str(run),
        "--verify-scan", "--expect-existing-legacy-engine"]
mode = ctypes.windll.kernel32.SetErrorMode(0x8003)
started = time.monotonic()
try:
    with (run / "stdout.log").open("xb") as out, (run / "stderr.log").open("xb") as err:
        process = subprocess.Popen(args, cwd=candidate, env=environment, stdout=out, stderr=err)
        (run / "started.json").write_text(json.dumps({"pid": process.pid, "arguments": args,
            "PATH": environment["PATH"], "settings_sha256_before": settings_hash}, indent=2) + "\n", encoding="utf-8")
        try:
            process.wait(timeout=1500)
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
            process.wait(timeout=15)
            raise
    result = {"exit_code": process.returncode, "seconds": time.monotonic() - started,
              "pid": process.pid, "exited": process.poll() is not None,
              "settings_file_preserved": settings_hash == sha(settings)}
    (run / "process.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    smoke = json.loads((run / "normal-startup.json").read_text())
    assert process.returncode == 0 and smoke["failure"] is None, smoke
    observed = smoke["result"]
    assert observed["passed"] and observed["normalStartupBranch"] and observed["savedEngineExists"]
    assert observed["settingsFilePreserved"] and result["settings_file_preserved"]
    assert observed["startScanHandlerInvoked"] and observed["scanCompleted"]
    assert observed["selectedEngine"] == str(candidate / "engine/attackmap.exe")
    assert sha(Path(observed["report"])) == observed["reportHash"]
    print(json.dumps({**result, "passed": True, "run": observed["run"], "report": observed["report"],
                      "engine": observed["selectedEngine"], "ai_enabled": observed["restoredOptions"]["provider"]["enable_ai"],
                      "cve_enabled": observed["restoredOptions"]["cve"]}, indent=2), flush=True)
finally:
    ctypes.windll.kernel32.SetErrorMode(mode)
