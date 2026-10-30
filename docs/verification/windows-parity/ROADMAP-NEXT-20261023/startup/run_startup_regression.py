"""Exercise the compiled startup gate in fresh profiles; never build or call AI."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as runtime


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_case(native: Path, output: Path, name: str, ai: bool, cve: bool, explicit: bool) -> dict:
    folder = output / name
    folder.mkdir()
    environment = runtime.child_environment(folder / "environment")
    settings = folder / "settings.json"
    if explicit:
        runtime.save(settings, dict(SchemaVersion=1, PythonPath="", RepositoryPath="", Modules="",
            Options=dict(cve=cve, provider=dict(enable_ai=ai, provider="openai",
                endpoint="http://127.0.0.1:1234/v1", model="cyberstag-security-26b-a4b-v1",
                max_calls=8, timeout_seconds=600, output_token_limit=32000))))
    settings_before = digest(settings) if settings.exists() else None
    observations: list[dict] = []
    original_job = runtime.WindowsJob

    class StartupJob(original_job):
        def cleanup(self):
            from ctypes import wintypes

            class Accounting(ctypes.Structure):
                _fields_ = [("times", ctypes.c_longlong * 4), ("faults", wintypes.DWORD),
                    ("total", wintypes.DWORD), ("active", wintypes.DWORD),
                    ("terminated", wintypes.DWORD)]

            try:
                value = Accounting()
                if not self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(value),
                        ctypes.sizeof(value), None):
                    raise ctypes.WinError(ctypes.get_last_error())
                observations.append(dict(total_processes=value.total, active_before_cleanup=value.active,
                    terminated_processes=value.terminated,
                    method="JobObjectBasicAccountingInformation; app assigned while suspended"))
            finally:
                super().cleanup()

    failure = None
    runtime.WindowsJob = StartupJob
    try:
        runtime.launch([str(native), "--startup-smoke", str(settings)], folder, environment, 120)
    except Exception as error:
        failure = str(error)
    finally:
        runtime.WindowsJob = original_job
    smoke_file = Path(str(settings) + ".result.json")
    smoke = runtime.read(smoke_file) if smoke_file.is_file() else None
    process_file = folder / "process.json"
    process = runtime.read(process_file) if process_file.is_file() else None
    settings_after = digest(settings) if settings.exists() else None
    expected_pass = not ai and not cve
    no_dispatch = len(observations) == 1 and observations[0]["total_processes"] == 1
    checks = dict(
        runtime_completed=failure is None,
        gate_matches_expected=isinstance(smoke, dict) and smoke.get("passed") is expected_pass,
        restored_ai_matches_input=isinstance(smoke, dict) and smoke.get("aiEnabled") is ai,
        restored_cve_matches_input=isinstance(smoke, dict) and smoke.get("cveEnabled") is cve,
        no_automatic_scan=isinstance(smoke, dict) and smoke.get("automaticScan") is False,
        no_broker_dispatch=no_dispatch,
        caller_settings_preserved=settings_before == settings_after,
        owned_process_exited=isinstance(process, dict) and process.get("exit_code") == 0
            and process.get("exited") is True and process.get("timed_out") is False
            and process.get("owned_tree_cleanup_verified") is True,
    )
    result = dict(name=name, passed=all(checks.values()), checks=checks, expected_gate_pass=expected_pass,
        settings_path=str(settings), settings_sha256_before=settings_before,
        settings_sha256_after=settings_after, smoke=smoke, process=process,
        job_accounting=observations, failure=failure)
    runtime.save(folder / "verification.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    runtime.require(os.name == "nt", "This runner requires Windows Job Objects")
    native, output = arguments.native.resolve(), arguments.output.resolve()
    runtime.require(native.is_file(), "Native executable is missing")
    engine = native.parent / "engine/attackmap.exe"
    runtime.require(engine.is_file(), "Startup smoke needs the candidate's actual bundled engine")
    runtime.require(not output.exists(), "Use a fresh output directory; retained evidence is never overwritten")
    output.mkdir(parents=True)
    paths = [native, native.with_suffix(".dll"), engine]
    runtime.require(all(path.is_file() for path in paths), "Native/engine identity files are missing")
    before = {str(path): digest(path) for path in paths}
    results = [run_case(native, output, *case) for case in (
        ("fresh-defaults", False, False, False),
        ("disabled-provider-object", False, False, True),
        ("enabled-ai-negative", True, False, True),
        ("enabled-cve-negative", False, True, True),
    )]
    after = {str(path): digest(path) for path in paths}
    summary = dict(passed=all(result["passed"] for result in results) and before == after,
        native=str(native), bundled_engine=str(engine), payload_identity_before=before,
        payload_identity_after=after, identity_files_unchanged=before == after, cases=results,
        manual_startup_acceptance=False, accessibility_acceptance=False,
        scope="Compiled opt-in startup gate only. Full-run cumulative Job accounting requires no child process, "
            "including children that exited before app close. All scan/provider dispatch routes use a child broker. "
            "Not packet-level monitoring, normal personal-profile startup, clean-host, full WP023 or release acceptance.")
    runtime.save(output / "summary.json", summary)
    runtime.require(summary["passed"], "Startup regression failed; inspect summary.json")
    print(json.dumps(dict(passed=True, cases=len(results), evidence=str(output / "summary.json"))))


if __name__ == "__main__":
    main()
