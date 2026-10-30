"""Open one saved generation for UI review, without requesting a scan/provider.

Default is preflight only. Use --run after the exclusive live mode batch ends.
The window remains open until explicitly closed, bounded by the owned Job timeout.
"""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as harness


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("app", "release-lock", "manifest-sha256", "report", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    app, report, output = map(harness.local_path, (args.app, args.report, args.output))
    harness.require(60 <= args.timeout_seconds <= 3600, "Bounded review timeout required")
    harness.require(not output.exists() and output.parent.is_dir(), "Fresh output required")
    for source in (app.parent.parent, report.parent, Path(r"C:\tmp\juice-shop")):
        harness.require(not output.is_relative_to(source) and not source.is_relative_to(output),
                        "Output overlaps input or real repository")
    harness.require(report.name == "attackmap-report.json", "Canonical saved report required")
    generation = {name: harness.record(report.parent / name) for name in
                  ("attackmap-report.json", "artifact-manifest.json", "run-manifest.json")}
    package = harness.package_identity(app, args.manifest_sha256, args.release_lock)
    helper = harness.record(Path(harness.__file__).resolve())
    runner = harness.record(Path(__file__).resolve())
    command = [str(app), "--show-report", str(report)]
    plan = dict(command=command, generation=generation, package=package, helper=helper,
                runner=runner, timeout_seconds=args.timeout_seconds,
                requested_scans=0, requested_provider_calls=0,
                accepted_visual=False, accepted_wp017=False)
    if not args.run:
        print(json.dumps(dict(stage="preflight-only", command=command,
                             processes_started=0, timeout_seconds=args.timeout_seconds)))
        return
    output.mkdir()
    harness.save(output / "inputs-before.json", plan)
    try:
        environment = harness.child_environment(output)
        harness.launch(command, output, environment, args.timeout_seconds)
    finally:
        after = dict(generation={name: harness.record(report.parent / name) for name in generation},
                     package=harness.package_identity(app, args.manifest_sha256, args.release_lock),
                     helper=harness.record(Path(harness.__file__).resolve()),
                     runner=harness.record(Path(__file__).resolve()))
        unchanged = all(after[key] == plan[key] for key in after)
        harness.save(output / "inputs-after.json", dict(**after, unchanged=unchanged))
        harness.require(unchanged, "Review inputs changed")
    process = harness.read(output / "process.json")
    harness.require(process.get("exit_code") == 0 and process.get("timed_out") is False
                    and process.get("owned_tree_cleanup_verified") is True,
                    "Review process did not close normally with verified cleanup")
    harness.save(output / "summary.json", dict(process_exited_cleanly=True,
                 requested_scans=0, requested_provider_calls=0, inputs_unchanged=True,
                 accepted_visual=False, accepted_wp017=False,
                 note="Separate observed UI evidence is required; launcher success is not visual acceptance."))
    print("Saved-report window closed; owned process cleanup verified.")


if __name__ == "__main__":
    main()
