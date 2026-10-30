"""Finalize only the verified WP042/WP039 batch; preserve unrelated plan updates."""
import collections
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

import verify_batch as batch

ROOT, OUT, WORK = batch.ROOT, batch.EVIDENCE, batch.WORK


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    proof = read(OUT / "native-final-run4-proof.json")
    assert proof["failure"] is None and proof["result"]["passed"] and proof["result"]["scanCompleted"]
    preview = read(WORK / "native-final-preview5/analyzer-smoke.json")
    assert preview["failure"] is None and preview["result"]["passed"] and not preview["result"]["scanCompleted"]
    save(OUT / "native-final-preview5-proof.json", preview)
    assert read(OUT / "juice-shop-verification.json")["passed"]
    assert read(OUT / "catalog-verification.json")["checks_passed"]
    native_build = read(OUT / "native-final5/build-proof.json")
    assert native_build["inputs_unchanged"]
    native_inputs = native_build["inputs_after"]["release_inputs"]
    native_mismatch = [name for name, digest in native_inputs.items() if sha(ROOT / name) != digest]
    assert not native_mismatch, native_mismatch
    runtime_native = read(OUT / "native-final4/build-proof.json")["inputs_after"]["release_inputs"]
    qa_difference = sorted(name for name in runtime_native.keys() | native_inputs.keys() if runtime_native.get(name) != native_inputs.get(name))
    assert qa_difference == ["desktop/windows/AttackMap.NativeSpike/MainWindow.AnalyzerSmoke.cs", "desktop/windows/AttackMap.NativeSpike/NativeCaptureProbe.cs"]
    frozen_inputs = read(WORK / "engine-final/source-checksums.json")
    frozen_mismatch = [name for name, digest in frozen_inputs.items() if sha(ROOT / name) != digest]
    assert not frozen_mismatch, frozen_mismatch
    copies = {"build-proof.json": "engine-build-proof.json", "analyzer-installed-attestation.json": "analyzer-installed-attestation.json",
              "source-checksums.json": "engine-source-checksums.json", "release-lock.json": "engine-release-lock.json"}
    for source, destination in copies.items():
        shutil.copyfile(WORK / "engine-final" / source, OUT / destination)
    captures = OUT / "captures"
    captures.mkdir(exist_ok=True)
    source_captures = sorted(path for path in (WORK / "native-final-preview5").glob("*.png") if path.name != "1600x1000-Dark-Ledger.png")
    source_captures.append(WORK / "native-final-run4/1600x1000-Dark-Ledger.png")
    assert len(source_captures) == 6
    for path in source_captures:
        shutil.copyfile(path, captures / path.name)
    capture_hashes = {p.name: sha(p) for p in sorted(captures.glob("*.png"))}
    assert len(set(capture_hashes.values())) == 6, "Unexpected identical captures; require visual review"
    save(OUT / "capture-origins.json", dict(scope="Five final5 preview images and one populated actual-scan ledger from final4; identical product view/model sources; separate QA helpers",
        images=[dict(name=p.name, source=str(p), sha256=sha(p)) for p in source_captures], native_input_difference=qa_difference))
    processes = {p.parent.name: read(p) for p in OUT.glob("*/process.json")}
    assert all(p["exited"] and p["owned_tree_cleanup_verified"] for p in processes.values())
    failed_commands = {name: p for name, p in processes.items() if p["exit_code"] != 0}
    baseline = read(OUT / "baseline.json")
    source_hashes = {name: sha(ROOT / name) for name in baseline["source_hashes"] if (ROOT / name).is_file()}
    new_files = ["src/attackmap/analyzer_run_ledger.py", "desktop/windows/AttackMap.NativeSpike/MainWindow.AnalyzerSmoke.cs",
                 "tests/test_analyzer_run_ledger.py", "tests/test_pipeline_analyzer_ledger.py",
                 "tests/test_ecosystem_node_atproto_routes.py", "tests/test_desktop_analyzer_profiles.py",
                 "schemas/run-request.schema.json", "schemas/run-progress.schema.json",
                 "schemas/run-terminal.schema.json", "schemas/run-manifest.schema.json"]
    source_hashes.update({name: sha(ROOT / name) for name in new_files})
    changed = {name: digest for name, digest in source_hashes.items() if baseline["source_hashes"].get(name) != digest}
    preserved = ["desktop/windows/AiArtifacts.Tests/Program.cs", "desktop/windows/AttackMap.NativeSpike/AI/AiArtifactProjection.cs",
                 "desktop/windows/AttackMap.NativeSpike/MainWindow.Capture.cs", "src/attackmap/ecosystem_php.py"]
    assert all(source_hashes[name] == baseline["source_hashes"][name] for name in preserved)
    diff_hash = hashlib.sha256(json.dumps(changed, sort_keys=True).encode()).hexdigest()
    save(OUT / "changed-source-hashes.json", changed)
    suite = ET.parse(OUT / "integrated-tests.xml").getroot().find("testsuite")
    assert suite is not None and suite.attrib["failures"] == suite.attrib["errors"] == "0"
    assert int(suite.attrib["tests"]) == 510 and int(suite.attrib["skipped"]) == 2
    backlog_path = ROOT / "docs/windows-parity-backlog.json"
    backlog = read(backlog_path)
    counts = dict(collections.Counter(t["status"] for t in backlog["tasks"]))
    evidence_path = OUT.relative_to(ROOT).as_posix()
    checkpoint = "Druhá dávka Sol 6.1 ultra ověřena: native profily/request 1.5, per-run ledger, bounded Node/ATProto WS/auth fix; 508 PASS + 2 SKIP, 597 native kontrol, source/frozen/native Juice Shop a scoped vizuální review. WP042/WP039 zůstávají IN_PROGRESS; whole-task/manual/package/maturity brány otevřené."
    backlog["planning_status"] = "2026-10-23 " + checkpoint
    backlog["run_state"] = "SCOPED_BATCH_COMPLETE"
    backlog["resume_note"] = evidence_path + "/README.md"
    owned = {"/root", "/root/analyzer_catalog", "/root/analyzer_profiles", "/root/php_routes"}
    leases = backlog["active_execution_leases"]
    released = [lease for lease in leases if lease["owner"] in owned]
    if not released and (OUT / "final-verification.json").exists():
        released = read(OUT / "final-verification.json")["leases_released"]
    backlog["active_execution_leases"] = [lease for lease in leases if lease["owner"] not in owned]
    backlog["latest_execution_update"] = dict(date="2026-10-23", tasks=["WP042", "WP039"], status="SCOPED_BATCH_COMPLETE",
                                               evidence=evidence_path + "/README.md", whole_task_acceptance=False)
    by_id = {task["id"]: task for task in backlog["tasks"]}
    for name in ("WP039", "WP042"):
        assert by_id[name]["status"] == "IN_PROGRESS"
        if evidence_path + "/README.md" not in by_id[name]["evidence"]:
            by_id[name]["evidence"].append(evidence_path + "/README.md")
    by_id["WP039"]["execution_scope"] = "Previous PHP parent/child slice preserved. Node/ATProto WS streamMethod and fail-closed auth correction with 68 focused PASS, same-input pairs, two actual old/new frozen scans and Juice Shop non-regression. No upstream pin change; duplicate-route identity, Python expansion, dependencies and C27/C38 remain open."
    by_id["WP042"]["execution_scope"] = "Native versioned profile selection/persistence/request1.5, current provenance/collision view and selected-report run ledger implemented. 508 Python PASS+2 SKIP,597 native checks,actual source/frozen/native Juice Shop non-regression and six native renders independently reviewed.15 plugins/21 effective/3 shadowed retained. Package/SBOM,manual/whole-task/dependency acceptance remain open."
    save(backlog_path, backlog)
    paragraph = "**Druhá implementační dávka ověřena 23. 10. 2026:** " + checkpoint + " [Výsledky a další krok](verification/windows-parity/WP042/sol-ultra-20261023-batch2/README.md). Leases této dávky jsou uvolněné. Starší checkpointy níže zůstávají datované."
    for filename in ("README.md", "roadmap-windows-parity-2026-10-20.md", "windows-parity-todo.md"):
        path = ROOT / "docs" / filename
        text = path.read_text(encoding="utf-8")
        heading, rest = text.split("\n", 1)
        if "**Druhá implementační dávka" not in text:
            path.write_text(heading + "\n\n" + paragraph + "\n" + rest, encoding="utf-8")
    todo_path = ROOT / "docs/windows-parity-todo.md"
    todo = todo_path.read_text(encoding="utf-8")
    for task, message in (("wp039", "Node/ATProto streamMethod/WS a konzervativní per-route auth jsou implementované; paired i actual frozen before/after PASS, bez tvrzení úplné deduplikace nebo maturity."),
                          ("wp042", "Native profile picker/persistence/request1.5, aktuální původ/kolize a reportový execution ledger jsou implementované a ověřené; package/SBOM a whole-task/manual brány zůstávají otevřené.")):
        start = todo.index('<a id="' + task + '"></a>')
        end = todo.find('<a id="', start + 1)
        section = todo[start:end if end >= 0 else len(todo)]
        note = "- Druhá dávka 23. 10. Sol / ultra: " + message + " [Důkazy](verification/windows-parity/WP042/sol-ultra-20261023-batch2/README.md).\n"
        section_new = section if note in section else section.rstrip() + "\n" + note + "\n\n"
        todo = todo[:start] + section_new + todo[end if end >= 0 else len(todo):]
    todo_path.write_text(todo, encoding="utf-8")
    statuses_match = True
    for task in backlog["tasks"]:
        start = todo.index('<a id="' + task["id"].lower() + '"></a>')
        fragment = todo[start:]
        match = re.search(r"stav: ([A-Z_]+)", fragment)
        statuses_match &= bool(match and match[1] == task["status"])
    assert statuses_match
    check = subprocess.run(["git", "-c", "core.safecrlf=false", "diff", "--check"], cwd=ROOT, capture_output=True, text=True)
    assert check.returncode == 0, check.stdout
    result = dict(scope="Scoped batch source/build/runtime verification; no whole-task release acceptance", changed_source_sha256=diff_hash,
                  changed_sources=changed, preserved_prior_dirty_sources=preserved,
                  native_final_inputs_match_current=True, engine_input_mismatches=frozen_mismatch,
                  native_QA_capture_selector_updated_after_engine_build=True,
                  engine_python_inputs_match_current=True, captures=capture_hashes, owned_processes=processes,
                  failed_command_records=failed_commands, failed_gui_attempts=["native-final-run", "native-final-run2"],
                  failed_visual_capture_attempts=["native-final-run4", "native-final-run5"],
                  accepted_functional_gui_run="native-final-run4", accepted_visual_preview="native-final-preview5",
                  runtime_vs_preview_native_input_difference=qa_difference, git_diff_check_passed=True,
                  task_count=len(backlog["tasks"]), task_status_counts=counts, task_statuses_match=True,
                  leases_released=released, other_active_leases=backlog["active_execution_leases"], whole_task_acceptance=False)
    save(OUT / "final-verification.json", result)
    commands = {}
    for path in OUT.glob("*/command.json"):
        try:
            commands[path.parent.name] = read(path)
        except json.JSONDecodeError:
            commands[path.parent.name] = dict(unparsed_record=str(path), sha256=sha(path),
                status="Retained malformed preliminary command record; not executable verification evidence")
    test_files = sorted({case.attrib.get("classname", "") for case in suite.findall("testcase")})
    documentation = ["docs/README.md", "docs/roadmap-windows-parity-2026-10-20.md", "docs/windows-parity-todo.md",
                     "docs/windows-parity-backlog.json", "docs/run-contract.md", "docs/ecosystem/analyzer-profiles.md",
                     "docs/ecosystem/analyzer-catalog.md", evidence_path + "/"]
    save(OUT / "handoff.json", dict(task_id=["WP042", "WP039"], owner="/root", base_commit=baseline["head"],
        final_commit_or_diff_hash=dict(kind="changed-source-paths-and-byte-sha256-map", sha256=diff_hash, commit_created=False),
        paths_changed=sorted(set(changed) | set(documentation)), leases_released=True, tests_executed=dict(integrated="508 PASS / 2 SKIP", files=test_files,
        native="597 checks across six console projects", commands=commands, adapters="87 PASS (overlapping)"),
        tests_not_executed=["full repository regression", "manual keyboard/Narrator/high-contrast", "macOS", "new package/SBOM/release validation", "live AI"],
        live_provider_calls=0, manual_checks="Agent visual inspection of five final5 preview renders plus final4 populated scan ledger; identical product sources, differing QA helpers; no human acceptance",
        package_id="No new portable/release package; frozen engine, native-final4 runtime and native-final5 preview bound separately",
        run_ids=[Path(row["after_report"]).parent.name for row in read(OUT / "juice-shop-verification.json")["comparisons"]],
        owned_process_ids=[p["pid"] for p in processes.values()],
        evidence=evidence_path + "/README.md", limitations=["C27/C38 corpus and dependencies remain open", "Python cross-file mounts/class views remain open", "route identity fusion incomplete", "runtime pin authenticity not verified", "final5 combined post-scan capture failed; usable preview5 and actual-run4 evidence kept separate"],
        next_action="Reproduce Python mount/Django class-view/re_path gap on effective pinned implementation; qualify a bounded update or local alternative."))
    broken = []
    for document in [OUT / "README.md", ROOT / "docs/README.md", todo_path, ROOT / "docs/roadmap-windows-parity-2026-10-20.md"]:
        for link in re.findall(r"\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
            if link.startswith(("http:", "https:", "#", "mailto:")):
                continue
            target = link.split("#", 1)[0]
            if target and not (document.parent / target).exists():
                broken.append(dict(document=str(document), link=link))
    save(OUT / "final-plan-validation.json", dict(tasks=len(backlog["tasks"]), task_statuses_match=True,
        local_links_exist=not broken, errors=broken, active_leases=backlog["active_execution_leases"], whole_task_acceptance=False))
    assert not broken, broken
    print(json.dumps(dict(passed=True, task_count=len(backlog["tasks"]), changed_source_count=len(changed), captures=len(capture_hashes), whole_task_acceptance=False)))


if __name__ == "__main__":
    main()
