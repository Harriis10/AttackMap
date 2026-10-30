"""Reconcile only this analyzer slice after all scoped verification gates pass."""
import json
from collections import Counter
from pathlib import Path
from candidate import ROOT, OUT, WORK, save
from verify_candidate import read
from verify_native import sha

proof = read(OUT / "packaged-catalog-final-verification.json")
assert proof["passed"] and proof["zip_payload_equal_to_manifest"]
assert read(OUT / "integration-test-proof.json")["tests"] == 338
assert read(OUT / "juice-shop-verification.json")["passed"]
django = read(OUT / "python-django-frozen-final/summary.json")
assert django["pass_count"] == django["case_count"] == 17
mounts = read(OUT / "python-mounts-frozen-final.json")
assert mounts["passed"] and len(mounts["cases"]) == 8
visual = read(OUT / "python-django-native-visual-review.json")
assert visual["image_count"] == 8 and visual["all_images_hash_match"]
assert visual["outcome"] == "scoped_visual_pass_with_viewport_limitations"
native = read(OUT / "native-analyzers-final-01-proof.json")
assert native["failure"] is None and native["result"]["passed"] and native["result"]["scanCompleted"]
for name in ("candidate-python-inputs.json", "candidate-native-final-inputs.json"):
    for relative, expected in read(OUT / name)["overlay"].items():
        assert sha(ROOT / relative) == expected, relative + " changed after release"

labels = ["source-final-juice", "native-analyzers-03", "native-analyzers-03-restore",
          "engine-analyzers-final", "native-analyzers-final-01", "package-build", "package-sbom"]
labels += ["packaged-catalog-final-" + label for label in ("modules", "catalog", "profiles", "capabilities")]
processes = {label: read(OUT / label / "process.json") for label in labels}
for path in (WORK / "frozen-qualification").glob("*/process.json"):
    processes["frozen-qualification/" + path.parent.name] = read(path)
assert all(row["exit_code"] == 0 and row["owned_tree_cleanup_verified"] for row in processes.values())
save("final-process-cleanup.json", {"scope": "Owned final integration jobs only; unrelated workloads untouched", "jobs": processes})

evidence = "docs/verification/windows-parity/WP039/sol-ultra-20261023-python/README.md"
backlog_path = ROOT / "docs/windows-parity-backlog.json"
before = backlog_path.read_bytes()
backlog = json.loads(before.decode("utf-8-sig"))
unrelated = {row["id"]: dict(row) for row in backlog["tasks"] if row["id"] not in {"WP039", "WP042"}}
other_leases = [row for row in backlog["active_execution_leases"] if row["owner"] != "/root/analyzer-python-integration"]
for row in backlog["tasks"]:
    if row["id"] not in {"WP039", "WP042"}:
        continue
    if evidence not in row["evidence"]:
        row["evidence"].append(evidence)
    if row["id"] == "WP042":
        row["status"] = "IMPLEMENTED"
        row["execution_scope"] = "Native profile/provenance and discovery failure UI, ledger1.1 timings/counts/lifecycle/live activity implemented. 338 focused Python PASS,164 native model checks,17+8 actual frozen Python cases,three source/frozen/native Juice Shop before-after comparisons and8 native captures independently reviewed. Same captured native03/frozen6045194 candidate packaged:15 official distributions/21 effective/24 candidates/3 PHP shadowed,4 profiles,779 ZIP entries verified,SBOM776 payload files. Upstream Python update documented no-go with local WP039 alternative. Dependency/manual/clean-host/release and C27/C38 gates remain open; no full fleet/moving-checkout acceptance."
    else:
        assert row["status"] == "IN_PROGRESS"
        row["execution_scope"] = "Prior PHP parent-child and Node/ATProto slices preserved. Python exact import/object mount binding, conservative auth guards, bounded prefix resolution and Django path/include/re_path/class-view surfaces implemented. 338 integrated PASS; actual frozen Python profile17Django+8mount/auth cases PASS; Juice Shop non-regression. Pinned-plugin false route surfaces/duplicates, general dynamic routing,class/DRF auth and C27/C38/dependencies remain open."
backlog["active_execution_leases"] = other_leases
backlog["latest_execution_update"] = dict(date="2026-10-23", tasks=["WP042", "WP039"], status="ANALYZER_IMPLEMENTATION_AND_SCOPED_PACKAGE_VERIFIED", evidence=evidence, whole_task_acceptance=False)
assert {row["id"]: row for row in backlog["tasks"] if row["id"] not in {"WP039", "WP042"}} == unrelated
assert len(backlog["tasks"]) == len({row["id"] for row in backlog["tasks"]}) == 44
assert backlog_path.read_bytes() == before, "Active plan changed while preparing reconciliation"
backlog_path.write_text(json.dumps(backlog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

notice = "**Třetí dávka analyzérů ověřena 23. 10. 2026:** WP042 je IMPLEMENTED: nativní profily/provenance/chyby discovery, podrobný ledger 1.1 a živý průběh, nový source-bound Windows ZIP se SBOM. 338 Python PASS, 164 native kontrol, 17 + 8 skutečných frozen Python případů, tři shodná before/after porovnání Juice Shopu a osm vizuálně zkontrolovaných snímků. WP039 zůstává IN_PROGRESS kvůli C27/C38, závislostem a deklarovaným omezením; ruční/release acceptance se nepřiznává. [Výsledky a balíček](verification/windows-parity/WP039/sol-ultra-20261023-python/README.md). Vlastní lease je uvolněná; souběžná fleet práce zůstává zachovaná."
for name in ("README.md", "roadmap-windows-parity-2026-10-20.md"):
    path = ROOT / "docs" / name
    original = path.read_text(encoding="utf-8")
    first, remainder = original.split("\n", 1)
    assert "Třetí dávka analyzérů ověřena" not in original
    path.write_text(first + "\n\n" + notice + "\n" + remainder, encoding="utf-8")
todo = ROOT / "docs/windows-parity-todo.md"
original = todo.read_text(encoding="utf-8")
marker = "### WP042 — Efektivní katalog analyzérů, profily a aktualizace"
before_card, card = original.split(marker, 1)
card = card.replace("checkpoint: K8; stav: IN_PROGRESS.", "checkpoint: K8; stav: IMPLEMENTED.", 1)
text = before_card + marker + card
anchor = "- Druhá dávka 23. 10. Sol / ultra:"
lines = text.splitlines()
current = None
updated = []
for line in lines:
    if line.startswith("### WP"):
        current = line.split()[1]
    updated.append(line)
    if line.startswith(anchor) and current in {"WP039", "WP042"}:
        detail = "Bounded Python mount/auth a Django URLconf rozšíření, 17 + 8 actual frozen případů PASS; C27/C38 a unsupported scope otevřené." if current == "WP039" else "Podrobný ledger/live activity a native discovery chyby dokončené; stejný engine/UI kandidát prošel runtime, osmi vizuálními kontrolami a package/SBOM inventářem. Stav IMPLEMENTED, závislosti a ruční/release brány otevřené."
        updated.append("- Třetí dávka 23. 10. Sol / ultra: " + detail + " [Důkazy a balíček](verification/windows-parity/WP039/sol-ultra-20261023-python/README.md).")
todo.write_text("\n".join(updated) + "\n", encoding="utf-8")
save("completion.json", dict(status="IMPLEMENTATION_AND_SCOPED_INTEGRATION_COMPLETE", wp042="IMPLEMENTED", wp039="IN_PROGRESS", whole_task_acceptance=False, evidence=evidence, source_overlay_unchanged=True, other_leases_preserved=other_leases, task_status_counts=dict(Counter(row["status"] for row in backlog["tasks"])), package=read(OUT / "delivery.json"), processes_verified=len(processes)))
print("Scoped completion recorded; unrelated task records and leases preserved.")
