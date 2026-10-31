"""Persist physical config/static app evidence; no provider or runtime calls."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import platform
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent


def main() -> None:
    test_path = ROOT / "tests/test_wp032_multibackend_proxy.py"
    spec = importlib.util.spec_from_file_location("wp032_multibackend_fixture", test_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    physical_root = (Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else
                     ROOT / ".tmp/wp032-multibackend-qualification-20261031")
    if physical_root.exists():
        raise FileExistsError("Preserve prior materialization; use a fresh task-specific path.")
    proof = module.qualification_proof(physical_root)
    proof["platform"] = {"platform": platform.platform(), "python": sys.version}
    proof["base_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    proof["checkout"] = "pre-existing dirty worktree; no commit, reset, clean, package or release"
    sources = [ROOT / name for name in (
        "src/attackmap/config_scanner.py", "src/attackmap/contracts.py", "src/attackmap/scan_service.py",
        "src/attackmap/crossrepo.py",
        "src/attackmap/fleet_architecture.py", "src/attackmap/models.py",
        "tests/test_wp032_protocol_fleet.py", "tests/test_wp032_reference_binding.py",
        "tests/test_wp032_score_references.py")]
    proof["sha256"] = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [test_path, Path(__file__).resolve(), *sources, *sorted(module.FIXTURE.rglob("*"))]
        if path.is_file() and "__pycache__" not in path.parts}
    diff = subprocess.check_output(["git", "diff", "--", "src/attackmap/config_scanner.py"], cwd=ROOT)
    proof["owning_source_dirty_diff_sha256"] = hashlib.sha256(diff).hexdigest()
    proof["dirty_diff_scope"] = "Full config_scanner.py diff includes preserved earlier datastore/messaging/Rails work. This slice changes proxy helpers/Ingress/nginx, negative DeploymentAliases facts/resolution, and effective-alias carry-forward only; scan_service.py also has separately owned WP034 changes."
    proof["summary"] = {"repositories": 3, "contract_links": len(proof["links"]),
        "resolutions": dict(Counter(link["resolution"] for link in proof["links"])),
        "http_graph_edges": sum(edge["kind"] == "cross_repo_http_call" for edge in proof["architecture"]["edges"]),
        "evidence_records": len(proof["architecture"]["evidence"]), "provider_calls": 0}
    (OUT / "qualification.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(proof["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
