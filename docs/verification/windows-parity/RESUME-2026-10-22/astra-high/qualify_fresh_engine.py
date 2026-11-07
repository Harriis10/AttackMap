"""Actual fresh frozen broker checks; output is new-only and never upgrades old proof."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import generate_release_lock as lock_tool
import run_wp017_native_modes as native


def inventory(folder):
    return [dict(path=p.relative_to(folder).as_posix(), size_bytes=p.stat().st_size,
                 sha256=native.sha(p)) for p in sorted(folder.rglob("*")) if p.is_file()]


def qualify(freeze, output):
    freeze, output = freeze.resolve(), output.resolve()
    native.require(not output.exists(), "Choose a fresh proof directory")
    engine = freeze / "dist/attackmap/attackmap.exe"
    build = native.read(freeze / "build-proof.json")
    lock_path = freeze / "release-lock.json"
    lock = native.read(lock_path)
    inputs = lock_tool.release_inputs(ROOT)
    for key in ("source_checksums_sha256", "release_inputs_sha256", "analyzer_requirements_sha256"):
        native.require(inputs[key] == lock[key], "Current source differs from fresh lock: " + key)
    native.require(native.sha(lock_path) == build["release_lock_sha256"], "Build lock differs")
    native.require(inventory(engine.parent) == build["payload_files"], "Frozen payload differs before run")
    native.require(native.sha(engine) == build["exe_sha256"], "Engine executable differs")
    output.mkdir(parents=True)
    environment = native.child_environment(output)
    native.require(not any((Path(part) / "python.exe").exists() for part in environment["PATH"].split(";")), "Python unexpectedly on child PATH")
    commands = []

    def command(label, arguments, timeout=180):
        folder = output / label
        folder.mkdir()
        started = time.monotonic()
        process, assigned, clean = None, False, False
        job = native.WindowsJob()
        try:
            with (folder / "stdout.log").open("xb") as out, (folder / "stderr.log").open("xb") as err:
                with native.inherited_error_mode():
                    process = subprocess.Popen([str(engine), *arguments], cwd=engine.parent, env=environment,
                        stdin=subprocess.PIPE, stdout=out, stderr=err,
                        creationflags=subprocess.CREATE_NO_WINDOW | 0x4)
                native.save(folder / "started.json", dict(pid=process.pid, arguments=[str(engine), *arguments]))
                job.assign(process)
                assigned = True
                job.resume(process)
                process.wait(timeout=timeout)
        finally:
            try:
                if assigned:
                    job.cleanup()
                    clean = True
                elif process is not None:
                    process.kill()  # Still suspended: it has not created descendants.
                if process is not None:
                    process.wait(timeout=15)
                    process.stdin.close()
            finally:
                job.close()
                result = dict(arguments=[str(engine), *arguments], pid=process.pid if process else None,
                    exit_code=process.returncode if process else None, seconds=time.monotonic() - started,
                    owned_tree_cleanup_verified=clean, child_path=environment["PATH"])
                native.save(folder / "process.json", result)
                commands.append(result)
        native.require(result["exit_code"] == 0 and clean, label + " failed or cleanup unverified")
        return (folder / "stdout.log").read_text(encoding="utf-8-sig"), result

    version_text, _ = command("version", ["--version"])
    modules_text, _ = command("modules", ["modules", "--json"])
    modules = json.loads(modules_text)
    capabilities_text, _ = command("capabilities", ["capabilities"])
    capabilities = json.loads(capabilities_text)
    native.require(len(modules) >= 15, "Missing frozen analyzers")
    native.require({"desktop-worker", "desktop-action"} <= set(capabilities["commands"]), "Missing broker commands")
    native.require(capabilities["engine_identity"]["runtime_kind"] == "Frozen"
        and Path(capabilities["engine_identity"]["path"]) == engine
        and capabilities["engine_identity"]["sha256"] == native.sha(engine), "Wrong capabilities executable identity")

    repository = Path(r"C:\tmp\juice-shop")
    run_id = uuid.uuid4().hex
    report_root = output / "reports"
    request_path = output / "scan-request.json"
    native.save(request_path, dict(schema_version="1.1", kind="request", run_id=run_id,
        repository_id=str(repository), generation=1, revision=0, repository_path=str(repository),
        output_path=str(report_root), modules=[], options=dict(recall=False, strict_analyzers=False,
        no_suppress=False, cve=False, secrets_history=0, timeout_seconds=600)))
    events_text, scan_process = command("scan", ["desktop-worker", "--request", str(request_path)], 660)
    events = [json.loads(line) for line in events_text.splitlines() if line.strip()]
    terminal = events[-1]
    native.require(terminal.get("kind") == "terminal" and terminal.get("run_id") == run_id
        and terminal.get("repository_id") == str(repository) and terminal.get("generation") == 1
        and terminal.get("state") == "completed" and terminal.get("execution_outcome") == "succeeded"
        and terminal.get("artifact_readiness") == "ready", "Frozen scan did not publish ready terminal")
    report = report_root / run_id / "attackmap-report.json"
    native.require(terminal.get("artifact_path") == str(report), "Terminal artifact path differs from published report")
    manifest_path = report.parent / "artifact-manifest.json"
    manifest = native.read(manifest_path)
    native.require(manifest.get("generation_id") == run_id, "Wrong generation manifest")
    rows = manifest.get("sections", []) + manifest.get("compatibility_exports", [])
    native.require(rows and manifest.get("exit_state", {}).get("status") == "succeeded", "Incomplete manifest")
    seen = set()
    for row in rows:
        name = native.relative_name(row["path"])
        native.require("/" not in name and name not in seen, "Unsafe or duplicate artifact")
        seen.add(name)
        path = native.local_path(report.parent / name)
        native.require(path.stat().st_size == row["size_bytes"] and native.sha(path) == row["checksum"], "Artifact checksum mismatch: " + name)
    native.require(report.name in seen, "Report absent from manifest")
    current = native.read(report_root / "current-generation.json")
    native.require(current.get("generation") == run_id and current.get("manifest_sha256") == native.sha(manifest_path),
        "Atomic current pointer mismatch")

    action_id = uuid.uuid4().hex
    action_root = output / "action-result"
    action_path = output / "action-request.json"
    native.save(action_path, dict(schema_version="1.1", request_id=action_id, operation="compare",
        output_path=str(action_root), payload=dict(baseline_path=str(report), current_path=str(report))))
    action_text, action_process = command("compare", ["desktop-action", "--request", str(action_path)])
    action_terminal = json.loads(action_text)
    native.require(action_terminal.get("request_id") == action_id and action_terminal.get("state") == "completed", "Compare action failed")
    action_result = action_root / (action_id + ".result.json")
    native.require(Path(action_terminal["result_path"]) == action_result and native.sha(action_result) == action_terminal["sha256"], "Compare result identity mismatch")
    compared = native.read(action_result)["result"]
    native.require(compared["comparison_version"] == "1.0", "Unsupported comparison schema")
    for side in ("baseline", "current"):
        native.require(compared[side]["report_path"] == str(report) and compared[side]["report_sha256"] == native.sha(report), "Compare report binding mismatch")

    native.require(inventory(engine.parent) == build["payload_files"], "Frozen payload changed during run")
    native.require(lock_tool.release_inputs(ROOT) == inputs, "Source changed during runtime qualification")
    native.require(native.sha(lock_path) == build["release_lock_sha256"], "Release lock changed during runtime qualification")
    proof = dict(scope="Fresh frozen engine direct broker/compare qualification on developer Windows; no GUI, AI, clean-host or release acceptance",
        version=version_text.strip(), exe_sha256=native.sha(engine), payload_files=build["payload_files"],
        capabilities=capabilities, release_lock_sha256=native.sha(lock_path),
        checks=dict(modules_discovered=len(modules), native_broker_commands_present=True,
            scan_atomic_current_ready=True, frozen_compare_action_ready=True),
        scan=dict(**scan_process, terminal=terminal, report=native.record(report), manifest=native.record(manifest_path)),
        action=dict(**action_process, terminal=action_terminal, result=native.record(action_result)),
        limitations=["Unsigned development engine; actual native consumer/UI qualification recorded separately.",
            "AI and CVE disabled; real repository deterministic scan. Not a clean Windows host."],
        commands=commands)
    for key in ("source_checksums_sha256", "release_inputs_sha256", "analyzer_requirements_sha256"):
        proof[key] = lock[key]
    native.save(output / "engine-verification.json", proof)
    print(json.dumps(dict(passed=True, proof=str(output / "engine-verification.json"), run_id=run_id,
        report=str(report), modules=len(modules), actual_model_responses=0)), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    qualify(args.freeze, args.output)
