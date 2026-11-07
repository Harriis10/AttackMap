"""Test-only frozen entry point; run cold and warm in separate processes.

Freeze this helper with the same AttackMap inputs as the candidate engine,
including all incremental._ENGINE_MODULES as hidden imports. No production
command or extractor behavior is changed. Pass an existing small repository
and an external, initially unused cache directory to both invocations.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import sys
from types import CodeType

import attackmap
from attackmap.incremental import _ENGINE_MODULES, engine_identity
import attackmap.scanner as scanner


def digest(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def cache_state(path: Path) -> dict | None:
    if not path.exists():
        return None
    data = path.read_bytes()
    document = json.loads(data)
    return dict(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                generation=document["generation"], entries=len(document["entries"]),
                entry_generations=sorted({entry["gen"] for entry in document["entries"].values()}))


def code_identities() -> dict:
    identities = {}
    for name in _ENGINE_MODULES:
        module = "attackmap." + name.replace("/", ".")
        code = importlib.util.find_spec(module).loader.get_code(module)
        if not isinstance(code, CodeType):
            raise RuntimeError(f"No real loader code for {module}")
        identities[name] = dict(sha256=hashlib.sha256(marshal.dumps(code)).hexdigest(),
                                filename=code.co_filename)
    return identities


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("cold", "warm", "upgrade", "full"))
    parser.add_argument("--reference-mode", choices=("cold", "upgrade"), default="cold")
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    args = parser.parse_args()
    if not getattr(sys, "frozen", False):
        raise RuntimeError("This probe must run as a real frozen executable")
    package = Path(attackmap.__file__).parent
    physical_sources = [name for name in _ENGINE_MODULES if (package / f"{name}.py").exists()]
    if physical_sources:
        raise RuntimeError(f"Expected source-less frozen modules: {physical_sources}")
    repo, cache = args.repo.resolve(), args.cache.resolve()
    if cache == repo or repo in cache.parents:
        raise RuntimeError("Probe cache must be outside the analyzed repository")
    reference = cache / f"probe-{args.reference_mode}-reference.json"
    cache_file = cache / "per-file-cache.json"
    before = cache_state(cache_file)
    if args.mode == "cold" and (reference.exists() or cache_file.exists()):
        raise RuntimeError("Cold proof requires a previously unused cache")
    calls = []
    original = scanner._analyze_indexed_file
    extractor_code = hashlib.sha256(marshal.dumps(original.__code__)).hexdigest()

    def counted(item):
        calls.append(item.rel)
        return original(item)

    scanner._analyze_indexed_file = counted
    try:
        result = scanner.scan_files(repo, incremental=args.mode != "full", cache_dir=cache)
    finally:
        scanner._analyze_indexed_file = original
    proof = dict(mode=args.mode, frozen=True, engine=engine_identity(),
                 result_sha256=digest(result.model_dump()),
                 fresh_extractor_calls=len(calls), scanned_files=result.files_scanned,
                 coverage_sha256=digest(result.scanned_files),
                 fresh_extractor_paths_sha256=digest(sorted(calls)),
                 physical_extractor_sources=physical_sources,
                 extractor_code_sha256=extractor_code, module_code=code_identities(),
                 cache_before=before, cache_after=cache_state(cache_file),
                 per_file_family_counts={family: len(getattr(result, family)) for family in (
                     "routes", "external_calls", "databases", "auth_hints", "secret_hints",
                     "crypto_weaknesses", "web_hardening_issues", "code_weaknesses")})
    if not cache_file.is_file():
        raise RuntimeError("Frozen scan did not persist the incremental cache")
    if args.mode == "cold":
        if not calls or not result.scanned_files:
            raise RuntimeError("Cold probe must exercise actual per-file extraction")
        reference.write_text(json.dumps(proof, sort_keys=True), encoding="utf-8")
    else:
        cold = json.loads(reference.read_text(encoding="utf-8"))
        if args.mode == "warm" and calls:
            raise RuntimeError(f"Warm scan recomputed files: {calls}")
        if any(proof[key] != cold[key] for key in (
                "result_sha256", "scanned_files", "coverage_sha256", "per_file_family_counts")):
            raise RuntimeError("Result or coverage differs from reference")
        if args.mode == "upgrade":
            if before != cold["cache_after"] or not before["entries"]:
                raise RuntimeError("Upgrade must consume the populated, unchanged previous-build cache")
            if proof["engine"] == cold["engine"] or proof["extractor_code_sha256"] == cold["extractor_code_sha256"]:
                raise RuntimeError("Upgrade needs a real engine and extractor code change")
            if proof["fresh_extractor_paths_sha256"] != cold["fresh_extractor_paths_sha256"] or not calls:
                raise RuntimeError("Upgrade did not re-extract exactly the cold paths")
            if proof["cache_after"]["generation"] == before["generation"]:
                raise RuntimeError("Upgrade did not replace the cache generation")
            (cache / "probe-upgrade-reference.json").write_text(json.dumps(proof, sort_keys=True), encoding="utf-8")
        else:
            if proof["engine"] != cold["engine"]:
                raise RuntimeError("Engine identity differs from reference")
            if before != proof["cache_after"]:
                raise RuntimeError("Warm or non-incremental scan changed the cache")
            if args.mode == "full" and proof["fresh_extractor_paths_sha256"] != cold["fresh_extractor_paths_sha256"]:
                raise RuntimeError("Non-incremental reference did not extract exactly the cold paths")
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
