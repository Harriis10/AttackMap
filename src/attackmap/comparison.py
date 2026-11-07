"""Core-owned saved-report comparison for CLI and native desktop consumers."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .diff import ComparisonCoverage, FindingSnapshot, diff_findings
from .finding_identity import legacy_id_aliases

COMPARISON_VERSION = "1.0"
MAX_REPORT_BYTES = 64 * 1024 * 1024


def _validate(report: dict[str, Any]) -> None:
    if not isinstance(report, dict) or not isinstance(report.get("scan"), dict):
        raise ValueError("Expected a canonical saved report with scan and findings.")
    if "schema_version" in report:
        raise ValueError("Versioned run envelopes are not saved reports; select the canonical report artifact.")
    if not isinstance(report["scan"].get("root"), str) or not report["scan"]["root"]:
        raise ValueError("Report repository identity is missing; select a report with scan.root.")
    for field in ("findings", "suppressed_findings"):
        rows = report.get(field, [] if field == "suppressed_findings" else None)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"Report {field} must be a list of finding objects.")


def coverage_from_report(report: dict[str, Any]) -> ComparisonCoverage:
    scan = report["scan"]
    files = scan.get("scanned_files")
    enumerated = (frozenset(path.replace("\\", "/") for path in files)
                  if isinstance(files, list) and all(isinstance(path, str) for path in files) else None)
    errors = scan.get("analyzer_errors") or []
    limitations = scan.get("limitations") or []
    return ComparisonCoverage(scanned_files=enumerated,
                              analyzer_errors=tuple(str(value) for value in errors),
                              limitations=tuple(str(value) for value in limitations))


def compare_reports(baseline: dict[str, Any], current: dict[str, Any], *,
                    baseline_path: str = "", current_path: str = "") -> dict[str, Any]:
    """Classify missing findings only where explicit current source coverage permits."""
    _validate(baseline)
    _validate(current)
    roots = [report["scan"]["root"].replace("\\", "/").rstrip("/") for report in (baseline, current)]
    if roots[0] != roots[1]:
        raise ValueError("Reports belong to different repositories; choose a baseline for the displayed repository.")
    before = [FindingSnapshot.from_dump(row) for row in baseline["findings"]]
    now = [FindingSnapshot.from_dump(row) for row in current["findings"]]
    suppressed = [FindingSnapshot.from_dump(row) for row in current.get("suppressed_findings", [])]
    coverage = coverage_from_report(current)
    result = diff_findings(before, now, suppressed, current_coverage=coverage)
    sources = {
        "new": current["findings"], "persisted": current["findings"],
        "resolved": baseline["findings"], "resolution_uncertain": baseline["findings"],
        "newly_suppressed": current.get("suppressed_findings", []),
    }
    changes = {}
    for group, rows in sources.items():
        by_id = {FindingSnapshot.from_dump(row).id: row for row in rows}
        changes[group] = []
        for snapshot in getattr(result, group):
            item = {**by_id[snapshot.id], "id": snapshot.id}
            item.setdefault("evidence_basis", "unknown")
            if group == "resolution_uncertain":
                item["resolution_reason"] = result.resolution_reasons[snapshot.id]
            changes[group].append(item)
    current_by_id = {FindingSnapshot.from_dump(row).id: row for row in current["findings"]}
    changes["new_instances"] = [
        {**current_by_id[snapshot.id], "id": snapshot.id, "new_instance_locations": labels}
        for snapshot, labels in result.new_instances
    ]
    notes = list(result.identity_notices)
    notes.extend("Current coverage limitation: " + note for note in coverage.limitations)
    notes.extend(result.coverage_notes)
    # Baseline records that cannot be mapped to a stable identity (foreign
    # recorded ids, ambiguous legacy titles) still diff, but are flagged for
    # review instead of being silently re-identified (C13).
    notes.extend(legacy_id_aliases(baseline["findings"]).notices)
    return {
        "comparison_version": COMPARISON_VERSION,
        "baseline": {"report_path": baseline_path, "repository_root": baseline["scan"]["root"]},
        "current": {"report_path": current_path, "repository_root": current["scan"]["root"]},
        "counts": result.counts(), "changes": changes, "notes": list(dict.fromkeys(notes)),
    }


def compare_report_files(baseline: str | Path, current: str | Path) -> dict[str, Any]:
    paths = [Path(value).resolve() for value in (baseline, current)]
    reports, hashes = [], []
    for path in paths:
        with path.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("Report exceeds the 64 MiB comparison limit.")
        reports.append(json.loads(raw))
        hashes.append(hashlib.sha256(raw).hexdigest())
    result = compare_reports(*reports, baseline_path=str(paths[0]), current_path=str(paths[1]))
    for field, digest in zip(("baseline", "current"), hashes):
        result[field]["report_sha256"] = digest
    return result
