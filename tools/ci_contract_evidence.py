"""CI evidence for actual consumers and applicable analyzers; never a maturity gate."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    "node": ("tests/fixtures/atproto-service", ("javascript-web", "node-atproto")),
    "php": ("tests/fixtures/php-omeka-app", ("php-web", "php-laminas", "omeka-s")),
    "python": ("tests/fixtures/python-service-app", ("python-web", "python-service")),
}
SIGNAL_FIELDS = ("routes", "auth_hints", "service_hints", "framework_hints", "protocol_hints",
                 "entrypoint_hints", "data_access", "edge_hints")


def hashed_inventory(root: Path, paths: list[str]) -> dict:
    files = {}
    for name in paths:
        target = root / name
        if not target.exists():
            raise ValueError(f"Required CI input missing: {name}")
        candidates = target.rglob("*") if target.is_dir() else (target,)
        for path in candidates:
            if not path.is_file() or any(part in {"__pycache__", "bin", "obj", ".pytest_cache"} for part in path.parts):
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError(f"CI input escaped checkout: {path}")
            files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    files = dict(sorted(files.items()))
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(canonical).hexdigest(), "files": files}


def input_paths(root: Path = ROOT) -> list[str]:
    corpus = json.loads((root / "fixtures/evaluation/corpus.json").read_text(encoding="utf-8"))
    paths = ["src/attackmap", "schemas", "fixtures/run-contract", "fixtures/desktop-workflows",
             "desktop/windows/AttackMap.NativeSpike", "desktop/windows/EngineProtocol.Tests",
             "desktop/windows/ReportAdapter.Tests", "fixtures/evaluation/corpus.json", "pyproject.toml",
             ".github/workflows/client-contract-fixtures.yml", "tools/ci_contract_evidence.py",
             "scripts/verify_setup.py", "tests/test_run_contract.py", "tests/test_ui_contract_adapter.py",
             "tests/test_desktop_workflow_fixtures.py", "tests/test_desktop_reference.py",
             "tests/test_ecosystem_node_atproto.py", "tests/test_ecosystem_php.py",
             "tests/test_ecosystem_python.py", "docs/verification/windows-parity/WP029/test_ci_contract_evidence.py"]
    paths += sorted({case["path"] for case in corpus["cases"]})
    paths += [path for path, _names in GROUPS.values()]
    return paths


def require_fresh_core_import() -> None:
    if any(name == "attackmap" or name.startswith("attackmap.") for name in sys.modules):
        raise ValueError("Actual execution requires a fresh process; preloaded core may be stale")


def assert_core_origin(root: Path = ROOT) -> None:
    import attackmap
    expected = (root / "src/attackmap").resolve()
    if Path(attackmap.__file__).resolve() != expected / "__init__.py":
        raise ValueError("Imported AttackMap core is not the checkout being hashed")
    for name, module in tuple(sys.modules.items()):
        if name.startswith("attackmap.") and getattr(module, "__file__", None):
            if not Path(module.__file__).resolve().is_relative_to(expected):
                raise ValueError(f"Foreign core submodule imported: {name}")


def assert_output_scope(output: Path, root: Path = ROOT) -> None:
    destination = output.resolve()
    if any(destination.is_relative_to((root / name).resolve()) for name in input_paths(root)):
        raise ValueError("Evidence output must be outside the hashed input scope")


def evidence_identity(root: Path = ROOT) -> dict:
    paths = input_paths(root)
    identity = hashed_inventory(root, paths)
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                              capture_output=True, text=True).stdout.strip()
    return {"core_checkout_revision": revision, "github_sha": os.environ.get("GITHUB_SHA"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"), "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "platform": platform.platform(), "python": platform.python_version(),
            "input_identity": identity,
            "installed_packages": sorted(({"name": d.metadata["Name"], "version": d.version,
                                            "direct_url": d.read_text("direct_url.json")}
                                           for d in importlib.metadata.distributions() if d.metadata.get("Name")),
                                         key=lambda row: row["name"].casefold()),
            "scope": "Exact checkout bytes and installed package versions; no Swift/frozen/manual acceptance implied"}


def require_exercised(name: str, applicable: bool, counts: dict[str, int], errors: list) -> None:
    if not applicable:
        raise ValueError(f"Required analyzer {name} was inapplicable; this is not a passing exercise")
    if errors or not any(counts.values()):
        raise ValueError(f"Required analyzer {name} failed or emitted no structured signals")


def exercise(group: str) -> dict:
    from attackmap.analyzers import get_builtin_repository_analyzers
    from attackmap.index import RepoIndex, clear_pinned_index
    assert_core_origin()
    relative, names = GROUPS[group]
    root = (ROOT / relative).resolve()
    available = {analyzer.name: analyzer for analyzer in get_builtin_repository_analyzers()}
    index = RepoIndex.build(root)
    rows = []
    try:
        for name in names:
            analyzer = available[name]  # missing registration fails, never becomes a skip
            applicable = analyzer.detect(root)
            if not applicable:
                require_exercised(name, False, {}, [])
            result = analyzer.analyze(root, index=index)
            counts = {field: len(getattr(result, field, [])) for field in SIGNAL_FIELDS}
            errors = [error.model_dump(mode="json") for error in getattr(result, "analyzer_errors", [])]
            require_exercised(name, applicable, counts, errors)
            rows.append({"name": name, "version": analyzer.metadata.version, "applicable": applicable,
                         "counts": counts, "result": result.model_dump(mode="json")})
        return {"fixture": relative, "group": group, "analyzers": rows,
                "scope": "Actual local fixture extraction only; no corpus maturity or platform UI acceptance"}
    finally:
        clear_pinned_index()


def evaluate() -> dict:
    from attackmap.evaluation import load_corpus, run_evaluation, report_json
    assert_core_origin()
    corpus = load_corpus(ROOT / "fixtures/evaluation/corpus.json")
    report = run_evaluation(corpus, ROOT)
    errors = [row.case.case_id for row in report.results if row.error]
    if errors:
        raise ValueError(f"Corpus scans failed: {errors}")
    # Metrics remain visible even below maturity thresholds. Do not relabel cases
    # or accept scan errors as clean negatives merely to make a CI gate green.
    return report_json(report)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("identity", "analyzers", "corpus"), required=True)
    parser.add_argument("--group", choices=tuple(GROUPS))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert_output_scope(args.output)
    if args.mode != "identity":
        require_fresh_core_import()
    payload = {"schema_version": 1, "identity": evidence_identity(), "mode": args.mode}
    if args.mode == "analyzers":
        if args.group is None:
            parser.error("analyzers mode requires --group")
        payload["exercise"] = exercise(args.group)
    elif args.mode == "corpus":
        payload["evaluation"] = evaluate()
    if args.mode != "identity":
        assert_core_origin()
    after = hashed_inventory(ROOT, input_paths())
    if after != payload["identity"]["input_identity"]:
        raise ValueError("CI input bytes changed during execution; result cannot be bound to this identity")
    payload["input_identity_verified_after_execution"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"mode": args.mode, "output": str(args.output),
                      "input_identity": payload["identity"]["input_identity"]["sha256"]}))


if __name__ == "__main__":
    main()
