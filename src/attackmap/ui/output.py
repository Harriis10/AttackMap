"""Scan report directories outside the scanned repo, matching macOS ScanOutputLocation."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

_CURRENT_POINTER = "current-generation.json"


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


def generation_dir(base: Path, run_id: str) -> Path:
    """Per-run artifact directory inside the report base."""
    folder = base / run_id
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def promote_generation(base: Path, run_id: str) -> None:
    """Atomically update the pointer to the current generation.

    Writes a sibling file and renames it into place so readers never see a
    partially written pointer.
    """
    pointer = base / _CURRENT_POINTER
    tmp = base / f".{_CURRENT_POINTER}.tmp"
    tmp.write_text(json.dumps({"generation": run_id}), encoding="utf-8")
    tmp.replace(pointer)


def current_generation(base: Path) -> Path | None:
    """Return the currently promoted generation directory, if any."""
    pointer = base / _CURRENT_POINTER
    if not pointer.is_file():
        return None
    try:
        data = json.loads(pointer.read_text(encoding="utf-8"))
        run_id = data.get("generation")
        if not isinstance(run_id, str):
            return None
        gen = base / run_id
        return gen if gen.is_dir() else None
    except (OSError, json.JSONDecodeError):
        return None


def rotate_previous(repo: Path, output: Path) -> Path | None:
    """Set aside the last promoted report so a rescan can use it as --baseline."""
    current_gen = current_generation(output)
    if current_gen is None:
        return None
    current = current_gen / "attackmap-report.json"
    if not current.is_file():
        return None
    dest = output.parent / "previous-report.json"
    dest.write_bytes(current.read_bytes())
    return dest
