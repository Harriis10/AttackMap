"""Opt-in full-product source-build preview of a retained AI generation.

This is explicitly not a package/live-model/release acceptance runner.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools"))
import generate_release_lock as locks
import run_wp017_native_modes as native

SAVED = ROOT / "docs/verification/windows-parity/WP023/astra-gui-20261022/saved_ai_capture.py"
spec = importlib.util.spec_from_file_location("retained_ai_preview_checks", SAVED)
saved = importlib.util.module_from_spec(spec)
spec.loader.exec_module(saved)


def inputs(plan):
    publish = Path(plan["publish"])
    build = native.read(Path(plan["build_proof"]))
    current = locks.release_inputs(ROOT)
    native.require(build.get("inputs_unchanged") is True
                   and build.get("inputs") == current["release_inputs"],
                   "Successful full build with unchanged exact source inputs required")
    native.require(current["release_inputs_sha256"] == build["release_inputs_sha256"],
                   "Source build no longer matches current release inputs")
    native.require(isinstance(build.get("artifacts"), dict)
                   and set(build["artifacts"]) == {native.APP_NAME, "AttackMap.NativeSpike.dll"},
                   "Full build must pin the actual application and DLL")
    native.require(isinstance(build.get("native_extra_inputs"), dict)
                   and build["native_extra_inputs"], "Linked native input proof required")
    for name, digest in build["native_extra_inputs"].items():
        path = native.local_path(ROOT / native.relative_name(name))
        native.require(native.sha(path) == digest, "Linked native input changed: " + name)
    for name, row in build["artifacts"].items():
        path = publish / name
        native.require(path.stat().st_size == row["bytes"] and native.sha(path) == row["sha256"],
                       "Native executable/DLL differs from full build proof")
    return dict(build=native.record(Path(plan["build_proof"])),
                native={name: native.record(publish / name) for name in build["artifacts"]},
                release_inputs_sha256=current["release_inputs_sha256"],
                generation=saved.generation_identity(plan["report"], plan["mode"]),
                runner=native.record(Path(__file__)), saved_helper=native.record(SAVED),
                pixel_guard=native.record(saved.GUI_PATH), harness=native.record(Path(native.__file__)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("publish", "build-proof", "report", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mode", choices=tuple(native.gate.MODES), required=True)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    publish, proof, report, output = map(native.local_path,
                                        (args.publish, args.build_proof, args.report, args.output))
    native.require(not output.exists() and output.parent.is_dir(), "Fresh output parent required")
    for source in (publish, proof.parent, report.parent, native.REPOSITORY):
        native.require(not output.is_relative_to(source) and not source.is_relative_to(output),
                       "Output overlaps a source/input root")
    phase = output / "capture"
    plan = dict(publish=str(publish), build_proof=str(proof), report=str(report), mode=args.mode,
                output=str(output), phase=str(phase),
                command=[str(publish / native.APP_NAME), "--capture-smoke", str(report), str(phase),
                         "--capture-ai-mode", args.mode],
                scope="Full-product native source-build preview; retained artifacts, no engine/provider run",
                requested_scans=0, requested_provider_calls=0, package_accepted=False,
                accepted_visual=False, accepted_accessibility=False, accepted_release=False)
    plan["inputs"] = inputs(plan)
    if not args.run:
        print(json.dumps(dict(plan, stage="preflight-only", processes_started=0)))
        return
    output.mkdir()
    phase.mkdir()
    native.save(output / "inputs-before.json", plan)
    try:
        try:
            native.launch(plan["command"], phase, native.child_environment(phase), 600)
        finally:
            after = inputs(plan)
            native.save(output / "inputs-after.json", after)
            native.require(after == plan["inputs"], "Preview inputs changed")
        result = saved.verify_capture(phase, plan)
        manifest = native.read(phase / "capture-manifest.json")
        summaries = manifest.get("aiSummaryProofs")
        native.require(isinstance(summaries, list) and len(summaries) == 4,
                       "Every AI frame must prove actual summary visibility")
        native.require({row.get("filename") for row in summaries}
                       == {Path(row["OutputPath"]).name for row in manifest["captures"]},
                       "Summary visibility proof does not match the captured frames")
        for row in summaries:
            native.require(row.get("selected") == "Reports"
                           and row.get("Text", "").startswith("Selected generation: " + plan["inputs"]["generation"]["generation"] + "\n")
                           and row.get("bounds", {}).get("FullyWithinClippedViewport") is True,
                           "Actual selected-generation summary is clipped or mismatched")
        native.save(output / "summary.json", dict(passed=True, scope=plan["scope"],
                    capture_validation=result, inputs_unchanged=True,
                    requested_scans=0, requested_provider_calls=0, package_accepted=False,
                    accepted_visual=False, accepted_accessibility=False, accepted_release=False))
        print(json.dumps(dict(passed=True, output=str(output), captures=4, new_model_responses=0)))
    except BaseException as error:
        native.save(output / "failure.json", dict(passed=False, error=str(error), scope=plan["scope"]))
        raise


if __name__ == "__main__":
    main()
