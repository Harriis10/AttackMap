"""One root-authorized focused deterministic pytest run with immutable evidence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent / "newlong-core-tests-01"
OUT.mkdir(exist_ok=False)
TESTS = ["test_provider_options.py", "test_local_provider_timeouts.py", "test_ai_budget.py",
    "test_llm_review.py", "test_hunt_harness.py", "test_run_contract.py", "test_fleet_schema_contract.py",
    "test_desktop_fleet.py", "test_desktop_ai_modes.py", "test_desktop_options.py", "test_desktop_action_review.py"]
def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
def snapshot():
    paths = set((ROOT / "src").rglob("*.py")) | set((ROOT / "tests").glob("test_*.py"))
    paths.update((ROOT / "schemas").glob("run-*.schema.json"))
    paths.add(ROOT / "tools/run_wp017_native_modes.py")
    for name in ("ProviderConfiguration.cs", "ProviderSettingsView.cs", "ParitySmokeTimeouts.cs"):
        paths.add(ROOT / "desktop/windows/AttackMap.NativeSpike" / name)
    return {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths) if path.is_file()}

before = snapshot()
save("source-hashes-before.json", before)
command = [str(ROOT / ".venv/Scripts/python.exe"), "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
    "--basetemp", str(OUT / "pytest-temp"), "--junitxml", str(OUT / "results.xml"),
    *["tests/" + name for name in TESTS]]
save("command.json", dict(command=command, cwd=str(ROOT), timeout_seconds=600,
    scope="Focused deterministic Python verification; no live provider, native GUI or build requested"))
environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
started = time.monotonic()
code, error = None, None
try:
    with (OUT / "pytest.stdout.txt").open("xb") as stdout, (OUT / "pytest.stderr.txt").open("xb") as stderr:
        process = subprocess.run(command, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr, timeout=600)
        code = process.returncode
except BaseException as exc:
    error = repr(exc)
finally:
    after = snapshot()
    save("source-hashes-after.json", after)
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    suites = []
    junit = OUT / "results.xml"
    if junit.exists():
        for suite in ET.parse(junit).getroot().iter("testsuite"):
            suites.append({key: int(suite.get(key, "0")) for key in ("tests", "errors", "failures", "skipped")})
    total = {key: sum(s[key] for s in suites) for key in ("tests", "errors", "failures", "skipped")}
    total["passed"] = total["tests"] - total["errors"] - total["failures"] - total["skipped"]
    summary = dict(passed=code == 0 and not error and not changed and bool(suites), exit_code=code, error=error,
        seconds=round(time.monotonic() - started, 3), counts=total, source_unchanged=not changed,
        changed_source_files=changed, hashed_files=len(before), scope="Deterministic focused tests only; no live model acceptance")
    save("summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    print((OUT / "pytest.stdout.txt").read_text(encoding="utf-8", errors="replace")[-18000:], flush=True)
if error:
    raise RuntimeError(error)
raise SystemExit(0 if summary["passed"] else code or 1)
