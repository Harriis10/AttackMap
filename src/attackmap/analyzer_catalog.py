"""Effective analyzer discovery, including candidates the registry cannot use.

This is an inventory of this process, not a repository applicability or execution
record. Installed distribution metadata is evidence about an installation; it is
not an attestation of the installed source or of a locked upstream commit.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
import hashlib
import inspect
import json
from pathlib import Path
import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from .analyzer_contracts import AnalyzerMetadata
from .plugins_lock import OFFICIAL_PLUGINS

if TYPE_CHECKING:
    from .analyzer_contracts import AnalyzerProtocol


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _error(stage: str, exc: Exception | None = None) -> dict[str, str | None]:
    # Exception messages can contain credentials and source text. Match the
    # existing discovery logger's exception-type-only policy.
    name = type(exc).__name__ if exc is not None else None
    if name is not None and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", name) is None:
        name = "Exception"
    return {"stage": stage, "error_type": name}


def _safe_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parts = urlsplit(value)
        # direct_url.json URLs are metadata supplied by a package. Do not expose
        # embedded credentials, signed query strings, or fragments in a catalog.
        host = parts.netloc.rsplit("@", 1)[-1]
        return urlunsplit((parts.scheme, host, parts.path, "", ""))
    except ValueError:
        return None


def _installed_source(dist: object | None) -> tuple[dict[str, object], list[dict[str, str | None]]]:
    source: dict[str, object] = {"kind": "distribution_metadata_only"}
    errors: list[dict[str, str | None]] = []
    read_text = getattr(dist, "read_text", None)
    if not callable(read_text):
        return source, errors
    try:
        raw = read_text("direct_url.json")
        if raw is None:
            return source, errors
        if not isinstance(raw, str) or len(raw) > 65536:
            raise ValueError("Invalid direct URL metadata")
        direct = json.loads(raw)
        if not isinstance(direct, dict):
            raise ValueError("Invalid direct URL metadata")
        source["evidence"] = "distribution_direct_url"
        source["url"] = _safe_url(direct.get("url"))
        vcs = direct.get("vcs_info")
        if isinstance(vcs, dict):
            source.update({
                "kind": "vcs",
                "vcs": _text(vcs.get("vcs")),
                "commit_id": _text(vcs.get("commit_id")),
                "requested_revision": _text(vcs.get("requested_revision")),
            })
        elif isinstance(direct.get("dir_info"), dict):
            source.update({"kind": "directory", "editable": direct["dir_info"].get("editable") is True})
        elif isinstance(direct.get("archive_info"), dict):
            url = source.get("url")
            source["kind"] = "wheel" if isinstance(url, str) and url.lower().endswith(".whl") else "archive"
            archive = direct["archive_info"]
            hashes = archive.get("hashes")
            if isinstance(hashes, dict):
                source["archive_hashes"] = {key: value for key, value in hashes.items() if isinstance(key, str) and isinstance(value, str)}
            elif isinstance(archive.get("hash"), str):
                source["archive_hash"] = archive["hash"]
    except Exception as exc:
        errors.append(_error("provenance_metadata", exc))
    return source, errors


def _provenance(dist: object | None, package_name: str | None) -> dict[str, object]:
    declared = next((dict(item) for item in OFFICIAL_PLUGINS if item["package"] == package_name), None)
    source, errors = _installed_source(dist)
    pin_status = "unverified" if declared is not None else "not_applicable"
    if declared is not None and source.get("kind") == "vcs" and source.get("vcs") == "git":
        commit = source.get("commit_id")
        url = source.get("url")
        if isinstance(commit, str) and isinstance(url, str):
            expected = f"https://github.com/mlaify/{declared['repo']}"
            same_repo = url.removesuffix(".git").rstrip("/") == expected
            pin_status = "matches_installed_vcs_metadata" if same_repo and commit == declared["git_sha"] else "differs_from_installed_vcs_metadata"
    return {
        "declared_pin": declared,
        "installed_source": source,
        "pin_status": pin_status,
        "content_verified": False,
        "errors": errors,
    }


def _implementation(analyzer: object) -> dict[str, str | None]:
    implementation_type = type(analyzer)
    try:
        source_file = inspect.getsourcefile(implementation_type)
    except (TypeError, OSError):
        source_file = None
    source_sha256 = None
    source_status = "unavailable"
    if source_file is not None:
        try:
            source_path = Path(source_file)
            if source_path.suffix == ".py" and not source_path.is_symlink() and source_path.is_file():
                if source_path.stat().st_size > 4 * 1024 * 1024:
                    source_status = "oversized"
                else:
                    source_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
                    source_status = "observed_file"
        except OSError:
            source_status = "unreadable"
    return {
        "module": _text(getattr(implementation_type, "__module__", None)),
        "qualname": _text(getattr(implementation_type, "__qualname__", None)),
        "source_file": source_file,
        "source_sha256": source_sha256,
        "source_status": source_status,
    }


@dataclass
class AnalyzerDiscoveryCollector:
    """Optional observer used by the existing discovery and registry functions."""

    trusted_only: bool
    candidates: list[dict[str, object]] = field(default_factory=list)
    loaded: list[tuple[AnalyzerProtocol, dict[str, object]]] = field(default_factory=list)
    errors: list[dict[str, str | None]] = field(default_factory=list)

    def builtin(self, analyzer: AnalyzerProtocol, metadata: AnalyzerMetadata) -> None:
        try:
            package_version = version("attackmap")
        except PackageNotFoundError:
            package_version = None
        row: dict[str, object] = {
            "candidate_id": f"builtin:{analyzer.name}",
            "name": analyzer.name,
            "origin": "builtin",
            "status": "loaded",
            "package": {"name": "attackmap", "version": package_version},
            "official_package": None,
            "entry_point": None,
            "implementation": _implementation(analyzer),
            "metadata": metadata.model_dump(mode="json"),
            "provenance": {"declared_pin": None, "installed_source": {"kind": "builtin"}, "pin_status": "not_applicable", "content_verified": False, "errors": []},
            "shadowed_by": None,
            "error": None,
        }
        self.candidates.append(row)
        self.loaded.append((analyzer, row))

    def entry_point(self, entry_point: object, distribution: str | None, group: str) -> dict[str, object]:
        dist = getattr(entry_point, "dist", None)
        name = _text(getattr(entry_point, "name", None))
        row: dict[str, object] = {
            "candidate_id": f"entry-point:{len(self.candidates)}:{distribution or 'unknown'}:{name or 'unknown'}",
            "name": name,
            "origin": "plugin",
            "status": "discovered",
            "package": {"name": distribution, "version": _text(getattr(dist, "version", None))},
            "official_package": any(item["package"] == distribution for item in OFFICIAL_PLUGINS),
            "entry_point": {"name": name, "group": group, "value": _text(getattr(entry_point, "value", None))},
            "implementation": None,
            "metadata": None,
            "provenance": _provenance(dist, distribution),
            "shadowed_by": None,
            "error": None,
        }
        self.candidates.append(row)
        return row

    def accepted(self, row: dict[str, object], analyzer: AnalyzerProtocol, metadata: AnalyzerMetadata) -> None:
        row.update(name=analyzer.name, status="loaded", metadata=metadata.model_dump(mode="json"), implementation=_implementation(analyzer))
        self.loaded.append((analyzer, row))

    def failed(self, row: dict[str, object], stage: str, exc: Exception | None = None) -> None:
        row.update(status=f"{stage}_error", error=_error(stage, exc))


@dataclass(frozen=True)
class AnalyzerCatalogSnapshot:
    """One discovery pass shared by metadata and provenance consumers."""

    analyzers: tuple[AnalyzerProtocol, ...]
    metadata: tuple[AnalyzerMetadata, ...]
    _collector: AnalyzerDiscoveryCollector = field(repr=False)

    def to_dict(self) -> dict[str, object]:
        discovered_packages = {
            row["package"]["name"] for row in self._collector.candidates
            if row["origin"] == "plugin" and isinstance(row["package"], dict)
        }
        return deepcopy({
            "schema": 1,
            "scope": "installed_discovery",
            "policy": {
                "registry_precedence": "builtin_first_seen_name",
                "run_order": ["priority", "name"],
                "trusted_only": self._collector.trusted_only,
            },
            "effective_order": [analyzer.name for analyzer in self.analyzers],
            "candidates": self._collector.candidates,
            "discovery_errors": self._collector.errors,
            # Absence of an entry point does not prove a package is uninstalled.
            "undiscovered_official_packages": [item["package"] for item in OFFICIAL_PLUGINS if item["package"] not in discovered_packages],
        })


def get_analyzer_catalog() -> AnalyzerCatalogSnapshot:
    """Discover once, preserving registry precedence and the effective run order."""
    from .analyzers import _run_order_key, get_analyzer_metadata, get_registered_analyzers, trusted_analyzers_only

    collector = AnalyzerDiscoveryCollector(trusted_only=trusted_analyzers_only())
    analyzers = tuple(sorted(get_registered_analyzers(catalog=collector), key=_run_order_key))
    metadata = tuple(get_analyzer_metadata(analyzer) for analyzer in analyzers)
    return AnalyzerCatalogSnapshot(analyzers, metadata, collector)
