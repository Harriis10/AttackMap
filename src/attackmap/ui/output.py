"""Scan report directories outside the scanned repo, matching macOS ScanOutputLocation."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path


def _base_dir() -> Path:
    root = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".attackmap")
    path = Path(root) / "AttackMap" / "scans"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return cleaned or "repo"


def _key(name: str, paths: list[Path]) -> str:
    joined = "\n".join(os.path.normcase(str(path.resolve())) for path in paths)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12]
    return f"{_safe_name(name)}-{digest}"


def reports_dir(repo: Path, base: Path | None = None) -> Path:
    root = base or _base_dir()
    folder = root / _key(repo.name, [repo]) / "reports"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def previous_report_path(repo: Path, base: Path | None = None) -> Path:
    return reports_dir(repo, base).parent / "previous-report.json"


def fleet_dir(repos: list[Path], base: Path | None = None) -> Path:
    root = base or _base_dir()
    name = f"fleet-{repos[0].name}" if repos else "fleet"
    folder = root / _key(name, repos) / "fleet"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def rotate_previous(repo: Path, output: Path) -> Path | None:
    """Set aside the last report so a rescan can use it as --baseline."""
    current = output / "attackmap-report.json"
    if not current.is_file():
        return None
    dest = previous_report_path(repo)
    dest.write_bytes(current.read_bytes())
    return dest
