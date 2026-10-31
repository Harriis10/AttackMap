"""Persist the bounded WP032 proof; application observations are normalized fixtures."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent


def main() -> None:
    test_path = ROOT / "tests/test_wp032_protocol_fleet.py"
    spec = importlib.util.spec_from_file_location("wp032_protocol_fleet", test_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    proof = module.qualification_proof(module.FIXTURE)
    owning_sources = [ROOT / name for name in (
        "src/attackmap/contracts.py", "src/attackmap/crossrepo.py", "src/attackmap/config_scanner.py",
        "src/attackmap/fleet_architecture.py", "src/attackmap/models.py", "src/attackmap/finding_presentation.py",
        "src/attackmap/exploitability.py", "src/attackmap/threat_model.py")]
    proof["sha256"] = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [test_path, Path(__file__).resolve(), *owning_sources, *sorted(module.FIXTURE.rglob("*"))]
        if path.is_file() and "__pycache__" not in path.parts}
    proof["summary"] = {"repositories": 3, "contract_links": len(proof["links"]),
        "resolutions": dict(Counter(link["resolution"] for link in proof["links"])),
        "http_graph_edges": sum(edge["kind"] == "cross_repo_http_call" for edge in proof["architecture"]["edges"]),
        "cross_boundary_flows": len(proof["cross_boundary_flows"]), "trust_gaps": len(proof["trust_gaps"]),
        "finding_score_references": len(proof["finding_score_references"]),
        "evidence_records": len(proof["architecture"]["evidence"])}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "qualification.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(proof["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
