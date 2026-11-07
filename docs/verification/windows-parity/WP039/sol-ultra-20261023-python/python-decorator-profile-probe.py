"""Actual installed python@1.0 selection/extraction on two inert negatives."""
from __future__ import annotations
import hashlib, inspect, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from attackmap.analyzer_catalog import get_analyzer_catalog
from attackmap.analyzer_profiles import resolve_analyzer_profile
from attackmap.analyzers import analyze_repository, resolve_analyzer_run
from attackmap.index import clear_pinned_index

def main():
    cases = json.loads((OUT / "python-binding-independent-review-final.json").read_text(encoding="utf-8"))["probes"]
    catalog = get_analyzer_catalog()
    selection = resolve_analyzer_profile("python@1.0", catalog.metadata)
    chosen = [analyzer for analyzer in catalog.analyzers if analyzer.name in selection.module_names]
    result = {"scope": "Actual installed offline python@1.0 profile; inert source parsed, no framework/provider execution",
              "python": sys.executable, "profile": selection.profile.qualified_name,
              "selected_candidates": [{"name": analyzer.name, "class_file": inspect.getfile(type(analyzer))} for analyzer in chosen], "cases": {}}
    assert any(row["name"] == "python" and ".tools" in row["class_file"] for row in result["selected_candidates"])
    for name in ("shadowed-known-route-decorator", "foreign-custom-decorator-collision"):
        root = ROOT / ".tmp/wp039-python-20261023/independent-decorator-profile" / name
        root.mkdir(parents=True, exist_ok=False)
        files = {"pyproject.toml": '[project]\nname="independent-oracle"\ndependencies=["flask"]\n', **cases[name]["files"]}
        for relative, text in files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
        clear_pinned_index()
        plan = resolve_analyzer_run(root, chosen, profile_id=selection.profile.qualified_name)
        scan = analyze_repository(root, run_plan=plan, incremental=False)
        result["cases"][name] = {"source_sha256": {relative: hashlib.sha256((root / relative).read_bytes()).hexdigest() for relative in files},
            "scan": scan.model_dump(mode="json"), "route_projection": [{"path": row.path, "auth": row.auth, "guards": row.guards, "source_analyzer": row.source_analyzer} for row in scan.routes]}
        clear_pinned_index()
    (OUT / "python-decorator-profile-probe.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({name: row["route_projection"] for name, row in result["cases"].items()}, indent=2))

if __name__ == "__main__":
    main()
