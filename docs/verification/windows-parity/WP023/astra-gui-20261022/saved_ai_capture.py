"""Capture an existing manifest-bound AI report; default is read-only preflight.

No scan/provider request is requested. Pixel validation is not visual acceptance.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as harness

GUI_PATH = Path(__file__).with_name("run-gui-checkpoint.py")
spec = importlib.util.spec_from_file_location("saved_ai_gui_guard", GUI_PATH)
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)
require, read, record, save = harness.require, harness.read, harness.record, harness.save
LIMITS = dict(requested_scans=0, requested_provider_calls=0, accepted_visual=False,
              accepted_accessibility=False, accepted_wp017=False, accepted_wp023=False,
              accepted_release=False)


def generation_identity(report, mode):
    """Verify and pin the complete published generation, not just report bytes."""
    report = harness.local_path(report)
    require(report.name == "attackmap-report.json" and isinstance(read(report).get("scan"), dict),
            "Canonical report with scan required")
    folder = report.parent
    manifest_path = harness.local_path(folder / "artifact-manifest.json")
    manifest_record = record(manifest_path)
    manifest = read(manifest_path)
    require(manifest.get("artifact_type") == "attackmap_artifact_manifest"
            and manifest.get("generation_id") == folder.name
            and manifest.get("exit_state", {}).get("status") == "succeeded",
            "Unsuccessful or mismatched generation manifest")
    sections, exports = manifest.get("sections"), manifest.get("compatibility_exports")
    require(isinstance(sections, list) and isinstance(exports, list) and sections + exports,
            "Missing generation artifact inventory")
    files, folded = {}, set()
    for row in sections + exports:
        require(isinstance(row, dict), "Malformed artifact row")
        name = harness.relative_name(row.get("path"))
        require("/" not in name and name.casefold() not in folded
                and name != manifest_path.name, "Unsafe/duplicate generation artifact")
        folded.add(name.casefold())
        path = harness.local_path(folder / name)
        require(path.is_file() and type(row.get("size_bytes")) is int
                and path.stat().st_size == row["size_bytes"], "Artifact size mismatch: " + name)
        identity = record(path)
        require(identity["sha256"] == row.get("checksum"), "Artifact checksum mismatch: " + name)
        files[name] = identity
    artifact = harness.gate.MODES[mode]
    metadata = Path(artifact).with_suffix(".meta.json").name
    require({report.name, "run-manifest.json", artifact, metadata} <= files.keys(),
            "Selected report/run/AI artifact/metadata absent from manifest")
    require(record(manifest_path) == manifest_record, "Generation manifest changed while checking")
    return dict(generation=folder.name, manifest=manifest_record, files=files,
                selected_artifact=files[artifact], selected_metadata=files[metadata])


def inputs(plan):
    return dict(package=harness.package_identity(plan["app"], plan["manifest_sha256"], plan["release_lock"]),
                generation=generation_identity(plan["report"], plan["mode"]),
                runner=record(Path(__file__).resolve()), helper=record(Path(harness.__file__).resolve()),
                capture_guard=record(GUI_PATH))


def unchanged(plan):
    current = inputs(plan)
    require(current == plan["inputs"], "Package/source/generation/runner inputs changed")
    return dict(unchanged=True, **current)


def preflight(args):
    app, lock, report, output = map(harness.local_path,
        (args.app, args.release_lock, args.report, args.output))
    require(not output.exists() and output.parent.is_dir(), "Fresh output under existing parent required")
    require(app.parent.name == "app" and (app.parent.parent / "package-manifest.json").is_file(),
            "Original RequiredBundled production package required")
    for source in (app.parent.parent, report.parent, lock.parent, Path(r"C:\tmp\juice-shop")):
        require(not output.is_relative_to(source) and not source.is_relative_to(output), "Output overlaps input")
    require(isinstance(args.manifest_sha256, str) and len(args.manifest_sha256) == 64,
            "Explicit reviewed manifest SHA256 pin required")
    phase = output / "capture"
    plan = dict(stage="preflight-only", processes_started=0, app=str(app), release_lock=str(lock),
                manifest_sha256=args.manifest_sha256, report=str(report), mode=args.mode,
                output=str(output), phase=str(phase), timeout_seconds=600,
                command=[str(app), "--capture-smoke", str(report), str(phase), "--capture-ai-mode", args.mode],
                **LIMITS)
    plan["inputs"] = inputs(plan)
    return plan


def verify_capture(folder, plan):
    require(not list(folder.glob("*-failure.json")), "Native capture failure proof exists")
    manifest = read(folder / "capture-manifest.json")
    captures = manifest.get("captures")
    require(manifest.get("aiMode") == plan["mode"] and manifest.get("providerCalled") is False
            and manifest.get("selectedReportSha256") == plan["inputs"]["generation"]["files"]["attackmap-report.json"]["sha256"],
            "Wrong saved mode/report/provider state")
    require(type(manifest.get("expected")) is int and type(manifest.get("completed")) is int
            and manifest["expected"] == manifest["completed"] == 4
            and isinstance(captures, list) and len(captures) == 4, "Incomplete saved AI captures")
    result = gui.captures_check(captures, folder, {"Reports"})
    require({item["view"] for item in result["measured"]} == {"Reports"}, "Unexpected capture view")
    return result


def run(plan):
    require(os.name == "nt", "Windows execution required")
    unchanged(plan)  # Recheck before creating evidence or launching anything.
    output, folder = Path(plan["output"]), Path(plan["phase"])
    output.mkdir()
    save(output / "preflight.json", plan)
    folder.mkdir()
    try:
        save(output / "inputs-before.json", unchanged(plan))
        environment = harness.child_environment(folder)
        try:
            harness.launch(plan["command"], folder, environment, plan["timeout_seconds"])
        finally:
            try:
                save(output / "inputs-after.json", unchanged(plan))
            except BaseException as error:
                save(output / "identity-failure.json", dict(passed=False, error=str(error)))
                raise
        process = read(folder / "process.json")
        require(all(process.get(key) is True for key in
                    ("exited", "owned_job_assigned", "owned_tree_cleanup_verified"))
                and process.get("exit_code") == 0 and process.get("timed_out") is False,
                "Native process failed or cleanup unverified")
        capture = verify_capture(folder, plan)
        result = dict(passed=True, stage="executed", mode=plan["mode"],
                      capture_validation=capture, inputs_unchanged=True,
                      evidence=[record(path) for path in sorted(folder.iterdir()) if path.is_file()], **LIMITS)
        save(output / "summary.json", result)
        return result
    except BaseException as error:
        save(output / "failure.json", dict(passed=False, error=str(error), **LIMITS))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("app", "release-lock", "manifest-sha256", "report", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--mode", choices=tuple(harness.gate.MODES), required=True)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    plan = preflight(args)
    print(json.dumps(run(plan) if args.run else plan, indent=2))


if __name__ == "__main__":
    main()
