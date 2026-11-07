"""Hash-bound replay of a selected report into the existing canonical graph.

This adapter reads captured report data only. It performs no scan, source-file
discovery, endpoint connection, provider invocation, or report mutation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .artifact_publisher import _safe
from .fleet import FleetRepoResult, FleetScan
from .fleet_architecture import _root, build_fleet_architecture
from .models import ScanResult

MAX_REPORT_BYTES = 64 * 1024 * 1024


def _local_path(value: str) -> Path:
    if (not value or len(value) > 32767 or any(ord(c) < 32 for c in value)
            or value.startswith(("\\\\", "//"))):
        raise ValueError("An absolute local report path is required")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("An absolute local report path is required")
    # Reject Windows devices, alternate streams, wildcard and aliased components.
    for component in path.parts[1:]:
        if (any(c in component for c in ':*?"<>|') or component.endswith((".", " "))
                or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", component)):
            raise ValueError("Unsupported local report path")
    if os.name == "nt":
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) != 3:
            raise ValueError("Report path must use a fixed local drive")
    return Path(os.path.abspath(path))


class ReportGraphRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)
    report_path: str = Field(min_length=1, max_length=32767)
    report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    repository_root: str = Field(min_length=1, max_length=32767)

    @field_validator("report_path", "repository_root")
    @classmethod
    def local_path(cls, value: str) -> str:
        _local_path(value)
        return value


def _fingerprint(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
            getattr(info, "st_file_attributes", 0), getattr(info, "st_reparse_tag", 0))


def _read_report(path: Path, expected_hash: str) -> bytes:
    _safe(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_REPORT_BYTES:
        raise ValueError("Report is not a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if _fingerprint(opened) != _fingerprint(before):
            raise ValueError("Report changed before reading")
        raw = stream.read(MAX_REPORT_BYTES + 1)
        after = os.fstat(stream.fileno())
    _safe(path)
    current = path.lstat()
    if (len(raw) != before.st_size or len(raw) > MAX_REPORT_BYTES
            or _fingerprint(before) != _fingerprint(after)
            or _fingerprint(after) != _fingerprint(current)
            or before.st_ctime_ns != current.st_ctime_ns
            or opened.st_ctime_ns != after.st_ctime_ns
            or hashlib.sha256(raw).hexdigest() != expected_hash):
        raise ValueError("Report changed or its hash does not match")
    return raw


def _object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate report JSON field")
        result[key] = value
    return result


def _invalid_constant(value: str):
    raise ValueError("Nonfinite report JSON value")


def project_report_graph(payload: dict) -> dict:
    request = ReportGraphRequest.model_validate(payload)
    path = _local_path(request.report_path)
    raw = _read_report(path, request.report_sha256)
    report = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_object,
                        parse_constant=_invalid_constant)
    if not isinstance(report, dict) or not isinstance(report.get("scan"), dict):
        raise ValueError("A captured analysis report with scan data is required")
    scan = ScanResult.model_validate(report["scan"], strict=True)
    if _root(scan.root) != _root(request.repository_root):
        raise ValueError("Report repository identity differs from the selection")
    # ScanResult defaults retain legacy reports that predate ledger/snapshots.
    # No inferred transport identity or cross-repository relationship is added.
    fleet = FleetScan(results=[FleetRepoResult("selected-report", scan.root, str(path.parent), scan, [])])
    graph = build_fleet_architecture(fleet, [{
        "root": scan.root, "requested_id": "single-report", "repo_id": "selected-report",
        "run_id": request.run_id, "generation": request.run_id,
        "report_hash": request.report_sha256}])
    graph["limitations"] = sorted(set(graph["limitations"]) | {
        "Single selected report replay; this is not a multi-repository Fleet generation."})
    # Recheck after parsing/projection as well, including byte identity even if
    # a writer tried restoring timestamps. Do not publish a stale selection.
    if _read_report(path, request.report_sha256) != raw:
        raise ValueError("Report changed during projection")
    return {"report_path": str(path), "report_sha256": request.report_sha256,
            "run_id": request.run_id, "repository_root": scan.root,
            "snapshot_id": scan.scan_snapshot.snapshot_id if scan.scan_snapshot else None,
            "graph": graph}
