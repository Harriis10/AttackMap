import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

root = Path.cwd()
app = Path(r"C:\Projects\FINISHED\AttackMap-Windows-Portable-20261022")
proof = root / "docs/verification/windows-parity/WP024/startscan-fix-20261022/finished-startup"
proof.mkdir()
audit = proof / "http-audit"
audit.mkdir()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


manifest = json.loads((app / "portable-manifest.json").read_text())
assert manifest["startup_engine_selection"] == "bundled_on_portable_startup"
for name, row in manifest["files"].items():
    assert (app / name).stat().st_size == row["size_bytes"] and sha(app / name) == row["sha256"], name
environment = dict(os.environ)
for key in list(environment):
    if key.upper().startswith(("PYTHON", "VIRTUAL_ENV", "CONDA", "OPENAI_", "ANTHROPIC_", "ATTACKMAP_QA_")):
        environment.pop(key)
environment["PATH"] = environment["SYSTEMROOT"] + "\\System32;" + environment["SYSTEMROOT"]
environment.update(ATTACKMAP_QA_HTTP_AUDIT_DIR=str(audit), ATTACKMAP_QA_HTTP_AUDIT_NONCE="finishedfix")
arguments = [str(app / "AttackMap.NativeSpike.exe"), "--verify-portable-startup", str(proof),
             "--verify-scan", "--expect-existing-legacy-engine"]
mode = ctypes.windll.kernel32.SetErrorMode(0x8003)
started = time.monotonic()
try:
    with (proof / "stdout.log").open("xb") as stdout, (proof / "stderr.log").open("xb") as stderr:
        child = subprocess.Popen(arguments, cwd=app, env=environment, stdout=stdout, stderr=stderr)
        (proof / "started.json").write_text(json.dumps({"pid": child.pid, "arguments": arguments,
            "PATH": environment["PATH"], "files_verified_before_launch": len(manifest["files"])}, indent=2) + "\n", encoding="utf-8")
        try:
            child.wait(timeout=1500)
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"], capture_output=True)
            child.wait(timeout=15)
            raise
    result = {"exit_code": child.returncode, "seconds": time.monotonic() - started,
              "pid": child.pid, "exited": child.poll() is not None}
    (proof / "process.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    observed = json.loads((proof / "normal-startup.json").read_text())
    assert child.returncode == 0 and observed["failure"] is None, observed
    observed = observed["result"]
    assert observed["passed"] and observed["scanCompleted"] and observed["startScanHandlerInvoked"]
    assert observed["normalStartupBranch"] and not observed["settingsOverride"] and not observed["explicitEngineArgument"]
    assert observed["savedEngineExists"] and observed["settingsFilePreserved"]
    assert observed["nativeExecutable"] == str(app / "AttackMap.NativeSpike.exe")
    assert observed["selectedEngine"] == str(app / "engine/attackmap.exe")
    assert sha(Path(observed["report"])) == observed["reportHash"]
    print(json.dumps({"passed": True, **result, "run": observed["run"], "report": observed["report"],
        "engine": observed["selectedEngine"], "global_settings_preserved": True}, indent=2), flush=True)
finally:
    ctypes.windll.kernel32.SetErrorMode(mode)
