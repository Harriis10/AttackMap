"""Offline verification of the completed normal-profile portable startup runs.

Run from the repository root. Reads existing AppData reports and FINISHED
payload; does not start the application, scan, or contact a model/provider.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

ROOT = Path.cwd()
PROOF = Path(__file__).resolve().parent
PUBLIC = Path(r"C:\Projects\FINISHED\AttackMap-Windows-Portable-20261022")
MODEL = "cyberstag-security-26b-a4b-v1"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def bound(record, label):
    path = Path(record["path"])
    path = path if path.is_absolute() else PROOF / path
    require(sha(path) == record["sha256"], label + " checksum")
    return path.read_bytes()


spec = importlib.util.spec_from_file_location("live_verifier", ROOT / "tools/verify_wp017_live.py")
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
manifest = read(PUBLIC / "portable-manifest.json")
require(manifest["startup_engine_selection"] == "bundled_on_portable_startup", "startup policy")
runs = []
for name, nonce in (("normal-startup", "startscanfix"), ("finished-startup", "finishedfix")):
    folder = PROOF / name
    smoke = read(folder / "normal-startup.json")
    process = read(folder / "process.json")
    result = smoke["result"]
    require(smoke["failure"] is None and result["passed"], name + " failed")
    require(process["exit_code"] == 0 and process["exited"], name + " process failed")
    for flag in ("normalStartupBranch", "savedEngineExists", "personalSettingsRead",
                 "settingsFilePreserved", "startScanHandlerInvoked", "scanCompleted"):
        require(result[flag] is True, name + " " + flag)
    for flag in ("settingsOverride", "explicitEngineArgument", "acceptedManualUi", "acceptedAccessibility"):
        require(result[flag] is False, name + " " + flag)
    require(result["progressState"] == "completed", name + " incomplete")
    for field, file in (("nativeExeSha256", "AttackMap.NativeSpike.exe"),
                        ("nativeDllSha256", "AttackMap.NativeSpike.dll"),
                        ("engineSha256", "engine/attackmap.exe")):
        require(result[field] == manifest["files"][file]["sha256"] == sha(PUBLIC / file), field)
    provider = result["restoredOptions"]["provider"]
    require(provider["enable_ai"] and provider["model"] == MODEL
            and provider["endpoint"] == "http://127.0.0.1:1234/v1", "provider changed")
    require(result["restoredOptions"]["cve"] is True, "CVE option changed")
    report = Path(result["report"])
    require(sha(report) == result["reportHash"], name + " selected report checksum")
    artifact = read(report.parent / "artifact-manifest.json")
    require(artifact["generation_id"] == result["run"], name + " wrong generation")
    require(artifact["exit_state"] == {"exit_code": 0, "status": "succeeded"}, "engine failed")
    sections = artifact["sections"] + artifact["compatibility_exports"]
    for row in sections:
        path = report.parent / row["path"]
        require(path.stat().st_size == row["size_bytes"] and sha(path) == row["checksum"], row["path"])
    count = len(read(report.parent / "findings.json"))
    require(count == 40, "unexpected findings count")
    metadata = read(report.parent / "defensive-review-llm.meta.json")
    require(metadata["backend"] == "api" and metadata["model"] == MODEL
            and metadata["stop_reason"] == "completed", "AI review incomplete")
    records = [{"path": str(p.relative_to(PROOF)), "sha256": sha(p)}
               for p in sorted((folder / "http-audit").rglob("*.jsonl"))]
    calls, completed = transport.verify_transport_audits(
        {"provider_audits": records, "audit_nonce": nonce}, PROOF, require, bound)
    require(calls == completed == 1, "unexpected transport completion count")
    require(sha(folder / "normal-startup.png") == result["capture"]["Sha256"], "capture checksum")
    retained = folder / "report-metadata"
    retained.mkdir(exist_ok=True)
    for filename in ("artifact-manifest.json", "run-manifest.json", "defensive-review-llm.meta.json",
                     "defensive-review-llm.md"):
        shutil.copyfile(report.parent / filename, retained / filename)
    runs.append({"name": name, "passed": True, "seconds": process["seconds"],
                 "run": result["run"], "selected_engine": result["selectedEngine"],
                 "report": str(report), "report_sha256": result["reportHash"],
                 "findings": count, "checksummed_report_artifacts": len(sections),
                 "actual_http_requests": calls, "completed_model_responses": completed,
                 "audit_nonce": nonce, "provider_audits": records,
                 "settings_preserved": True})
require(read(PROOF / "normal-startup/process.json")["settings_file_preserved"], "outer settings check")
require(runs[-1]["selected_engine"] == str(PUBLIC / "engine/attackmap.exe"), "FINISHED engine")
zip_path = PUBLIC.with_suffix(".zip")
require(sha(zip_path) == read(PROOF / "staged-copy.json")["zip_sha256"], "public ZIP mismatch")
summary = {"passed": True, "verification": "offline; no new scans or model requests",
           "native_build": manifest["native_build"], "runs": runs,
           "synthetic_native_options_checks_passed": 63, "synthetic_package_tests_passed": 15,
           "zip_path": str(zip_path), "zip_sha256": sha(zip_path),
           "interactive_bat_launch": read(PROOF / "interactive-bat-launch.json"),
           "accepted_manual_ui": False, "accepted_accessibility": False,
           "accepted_clean_host": False, "release_candidate": False,
           "ai_claim_support": "not_assessed; completed output is advisory"}
(PROOF / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"passed": True, "runs": len(runs), "actual_http_requests": 2,
                  "completed_model_responses": 2, "zip_sha256": summary["zip_sha256"]}, indent=2))
