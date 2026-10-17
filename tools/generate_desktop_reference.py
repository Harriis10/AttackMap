"""Deterministic synthetic canonical report for roadmap C20/C26 measurements.

No analyzer is run and no generated item is security evidence. The full profile
contains exactly 10,000 findings, 50,000 observations and 20 MiB of report bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

FIXTURE_VERSION = "desktop-reference/v1"
DEFAULT_FINDINGS = 10_000
DEFAULT_OBSERVATIONS = 50_000
DEFAULT_BYTES = 20 * 1024 * 1024
SYNTHETIC_NOTE = "SYNTHETIC PERFORMANCE FIXTURE: no repository was scanned; evidence and runtime reachability are unknown."
WORKSPACE = Path(__file__).resolve().parents[1]


def encode(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")


def build_report(*, findings: int = DEFAULT_FINDINGS, observations: int = DEFAULT_OBSERVATIONS,
                 report_bytes: int = DEFAULT_BYTES) -> bytes:
    """Return exact-size canonical JSON; padding is labelled transport load only."""
    if findings < 1 or observations < 1 or report_bytes < 1:
        raise ValueError("Counts and report_bytes must be positive")
    rows = []
    for index in range(findings):
        entity = f"synthetic-entity-{index:05}"
        rows.append({
            "id": hashlib.sha256(f"{FIXTURE_VERSION}:{entity}".encode("ascii")).hexdigest()[:16],
            "rule_id": "synthetic-performance-only", "entity_id": entity,
            "title": f"SYNTHETIC reference finding {index:05}",
            "severity": ("high", "medium", "low")[index % 3],
            "confidence": "low", "evidence_basis": "unknown",
            "evidence": [f"SYNTHETIC placeholder observation {index % observations:05}; no source was analyzed."],
            "locations": [{"file": f"synthetic/service-{index % 100:03}/file-{index:05}.txt", "line": index % 500 + 1}],
            "mitigation": "SYNTHETIC recommendation: use this row only to measure navigation and rendering.",
            "tags": ["synthetic-fixture", "performance-only"],
        })
    signals = [{
        "observation_id": f"synthetic-observation-{index:05}",
        "kind": "service", "label": f"SYNTHETIC observation {index:05}",
        "file": f"synthetic/service-{index % 100:03}/observation-{index:05}.txt",
        "confidence": 0.0,
        "properties": {"synthetic": "true", "evidence_basis": "unknown"},
    } for index in range(observations)]
    report = {
        "scan": {"root": "synthetic-desktop-reference", "files_scanned": 0,
                 "languages": [], "signals": signals, "limitations": [SYNTHETIC_NOTE],
                 "routes": [], "dependencies": [], "analyzer_errors": []},
        "findings": rows, "suppressed_findings": [], "attack_paths": [],
        "attack_surfaces": [], "exploitability": [],
        "defensive_review": SYNTHETIC_NOTE,
        "fixture": {"version": FIXTURE_VERSION, "synthetic": True,
                    "security_evidence": False, "findings": findings,
                    "observations": observations, "report_bytes": report_bytes,
                    "padding_purpose": "ASCII transport/parser load only; not observations or evidence.",
                    "padding": ""},
    }
    unpadded = encode(report)
    if len(unpadded) > report_bytes:
        raise ValueError(f"Requested report_bytes {report_bytes} is smaller than unpadded report {len(unpadded)}")
    report["fixture"]["padding"] = "x" * (report_bytes - len(unpadded))
    result = encode(report)
    assert len(result) == report_bytes
    return result


def _output_directory(output: Path) -> Path:
    target = output.resolve()
    if target.is_relative_to(WORKSPACE) and not target.is_relative_to(WORKSPACE / ".pytest_cache"):
        raise ValueError("Inside the workspace, generated fixtures must stay under .pytest_cache")
    return target


def generate(output: Path, *, findings: int = DEFAULT_FINDINGS,
             observations: int = DEFAULT_OBSERVATIONS, report_bytes: int = DEFAULT_BYTES) -> dict:
    target = _output_directory(output)
    raw = build_report(findings=findings, observations=observations, report_bytes=report_bytes)
    digest = hashlib.sha256(raw).hexdigest()
    severities = {name: sum(1 for index in range(findings) if index % 3 == remainder)
                  for remainder, name in enumerate(("high", "medium", "low"))}
    manifest = {"fixture_version": FIXTURE_VERSION, "synthetic": True,
                "report": "attackmap-report.json", "sha256": digest,
                "report_bytes": len(raw), "finding_count": findings,
                "observation_count": observations, "severity_counts": severities,
                "unknown_evidence_findings": findings, "unique_finding_ids": findings,
                "unique_observation_ids": observations, "files_scanned": 0,
                "performance_acceptance": "unmeasured"}
    files = {"attackmap-report.json": raw, "desktop-reference-manifest.json": encode(manifest),
             "attackmap-report.sha256": f"{digest}  attackmap-report.json\n".encode("ascii")}
    # No overwrite of a different fixture or user file. Identical reruns are safe.
    for name, content in files.items():
        path = target / name
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError(f"Refusing redirected output file: {name}")
        if path.exists() and (not path.is_file() or path.read_bytes() != content):
            raise ValueError(f"Refusing to overwrite different output: {name}")
    target.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (target / name).write_bytes(content)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=WORKSPACE / ".pytest_cache" / "m3-desktop-reference")
    parser.add_argument("--findings", type=int, default=DEFAULT_FINDINGS)
    parser.add_argument("--observations", type=int, default=DEFAULT_OBSERVATIONS)
    parser.add_argument("--report-bytes", type=int, default=DEFAULT_BYTES)
    args = parser.parse_args()
    try:
        manifest = generate(args.output, findings=args.findings, observations=args.observations,
                            report_bytes=args.report_bytes)
    except (OSError, ValueError) as error:
        parser.exit(2, f"{error}\n")
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
