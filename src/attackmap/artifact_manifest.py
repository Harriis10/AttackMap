"""Versioned artifact manifest and section files for AttackMap scan output."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .safe_fs import UnsafePathError, ensure_output_dir, max_file_bytes, safe_write_text


SCHEMA_VERSION = "1.0.0"
ARTIFACT_TYPE = "attackmap_artifact_manifest"
MANIFEST_FILENAME = "artifact-manifest.json"
PINS_FILENAME = "pinned-generations.json"

_LEGACY_JSON_FILES = frozenset({
    "attackmap-report.json", "run-manifest.json", "defensive-review.json",
    "review-context-pack.json", "fleet-summary.json",
    "defensive-review-llm.meta.json", "benchmark-results.json",
    "attackmap-diagnostics.json",
})

_MARKDOWN_EXPORTS = (
    "architecture.md", "attack-surface.md", "defensive-review.md",
    "attackmap-exploitability.md", "attackmap-paths.md", "attackmap-topology.md",
    "attackmap-paths.dot", "attackmap-topology.dot",
)

_OPTIONAL_EXPORTS = (
    "attackmap-diff.md", "defensive-review-llm.md", "defensive-review-llm.meta.json",
    "vulnerability-hypotheses.md", "vulnerability-hypotheses.meta.json",
    "remediation.md", "remediation.meta.json", "triage.md", "triage.meta.json",
    "pr-review.md", "pr-review.json",
)

# Sections extracted from the legacy monolithic report JSON.
SECTION_ORDER: list[tuple[str, str, str]] = [
    ("scan", "scan.json", "structured-scan-result"),
    ("findings", "findings.json", "findings-array"),
    ("attack_paths", "attack_paths.json", "attack-paths-array"),
    ("attack_surfaces", "attack_surfaces.json", "attack-surfaces-array"),
    ("exploitability", "exploitability.json", "exploitability-array"),
    ("suppressed_findings", "suppressed_findings.json", "suppressed-findings-array"),
]

_MANIFEST_OUTPUT_NAMES = frozenset(
    filename for _, filename, _ in SECTION_ORDER
) | frozenset(_MARKDOWN_EXPORTS) | frozenset(_OPTIONAL_EXPORTS) | {
    "defensive-review.json", "review-context-pack.json", "run-manifest.json",
    "attackmap-report.json", "attackmap-report.sarif",
}


@dataclass(frozen=True)
class ArtifactSection:
    name: str
    path: str
    format: str
    role: str
    checksum: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "path": self.path,
            "format": self.format,
            "role": self.role,
        }
        if self.checksum is not None:
            data["checksum"] = self.checksum
        return data


@dataclass(frozen=True)
class ArtifactManifest:
    schema_version: str
    artifact_type: str
    generation_id: str
    engine_version: str
    created_at: str
    exit_state: dict[str, Any]
    run_identity: dict[str, Any]
    sections: list[ArtifactSection]
    compatibility_exports: list[ArtifactSection]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_type": self.artifact_type,
            "generation_id": self.generation_id,
            "engine_version": self.engine_version,
            "created_at": self.created_at,
            "exit_state": self.exit_state,
            "run_identity": self.run_identity,
            "sections": [s.to_dict() for s in self.sections],
            "compatibility_exports": [s.to_dict() for s in self.compatibility_exports],
        }


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _analyzer_identity(analyzer_metadata: list[dict[str, Any]]) -> str:
    """Content identity of the analyzer set + versions one run used (C33/AM047).

    Name/version only: cosmetic metadata changes must not fork run identity.
    """
    entries = sorted(
        ({"name": str(item.get("name", "")), "version": str(item.get("version", ""))}
         for item in analyzer_metadata),
        key=lambda entry: (entry["name"], entry["version"]),
    )
    payload = json.dumps(entries, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _captured_sources(
    out: Path, snapshot_id: str, raw_files: dict[str, str]
) -> list[dict[str, str]]:
    """Bind excerpt sources only when their raw hashes match the snapshot.

    Spans are content-addressed and immutable (they never re-read the live
    file). A normalized text hash cannot establish original-byte identity;
    missing raw hashes and mismatches remain explicitly unbound (C33/AM047).
    """
    sources: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for filename in ("vulnerability-hypotheses.meta.json", "defensive-review-llm.meta.json"):
        data = _artifact_json(out / filename, min(max_file_bytes(), 2_000_000))
        context = data.get("citation_context") if isinstance(data, dict) else None
        entries = context.get("sources") if isinstance(context, dict) else None
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            path, sha = entry.get("path"), entry.get("source_sha256")
            if not isinstance(path, str) or not isinstance(sha, str) or (path, sha) in seen:
                continue
            seen.add((path, sha))
            source = {"path": path, "source_sha256": sha}
            if raw_files.get(path) == sha:
                source["captured_under_snapshot_id"] = snapshot_id
            sources.append(source)
    return sources


def _snapshot_publication_block(
    report_data: dict[str, Any], repo_root: str, out: Path
) -> dict[str, Any] | None:
    """Verify the analyzed snapshot against the working tree at publication.

    The scan section carries the index-time snapshot identity (C33/AM047);
    this is the publication gate. Any file that changed, disappeared or
    appeared since the index marks the run incomplete — with an explicit
    limitation listing the paths — instead of silently publishing evidence
    from two revisions. Files under the output directory are excluded: the
    run writes its own reports there. Bounded policy: no retry loop; the
    operator re-runs for a consistent report.
    """
    scan_section = report_data.get("scan")
    raw = scan_section.get("scan_snapshot") if isinstance(scan_section, dict) else None
    if not isinstance(raw, dict) or not isinstance(raw.get("files"), dict):
        return None
    from .index import ScanSnapshot

    snapshot = ScanSnapshot.from_identity(raw)
    verification = snapshot.verify(repo_root, exclude=(out,))
    block: dict[str, Any] = {
        "snapshot_id": snapshot.snapshot_id,
        "file_count": len(snapshot.files),
        "total_size": snapshot.total_size,
        "config_identity": snapshot.config_identity,
        "index_config": dict(snapshot.index_config),
        "verification": {
            **verification.to_dict(),
            "basis": "sha256 of utf-8 text under index acceptance rules",
            "excluded_paths": [str(out)],
        },
    }
    limitation = verification.limitation()
    if limitation is not None:
        block["incomplete"] = True
        block["limitation"] = limitation
    captured = _captured_sources(out, snapshot.snapshot_id, dict(snapshot.raw_files))
    if captured:
        block["sources_captured"] = captured
        unbound = sorted({source["path"] for source in captured
                          if "captured_under_snapshot_id" not in source})
        block["source_capture_verification"] = {
            "state": "unverified" if unbound else "verified",
            "unbound_paths": unbound,
            "basis": "sha256 of original captured bytes",
        }
        if unbound:
            note = "AI excerpt sources do not match captured raw snapshot: " + ", ".join(unbound)
            # Tree verification alone cannot validate an excerpt captured from
            # a transient revision that was restored before publication.
            if block["verification"]["state"] == "verified":
                block["verification"]["state"] = "unverified"
            block["verification"]["note"] = note
            block["incomplete"] = True
            block["limitation"] = ((limitation + " ") if limitation else "") + (
                "incomplete snapshot: " + note + ". Re-run for a consistent report."
            )
    return block


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_run_id() -> str:
    """Return an opaque unique id, independent of wall-clock resolution."""
    now = datetime.now(timezone.utc)
    return f"{now.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex}"


def _section_from_file(
    out: Path, name: str, filename: str, role: str, artifact_format: str = "json"
) -> ArtifactSection | None:
    path = out / filename
    if not path.is_file():
        return None
    return ArtifactSection(
        name=name,
        path=filename,
        format=artifact_format,
        role=role,
        checksum=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def write_artifact_manifest(
    output_dir: str | Path,
    run_id: str,
    engine_version: str,
    repo_root: str,
    repo_name: str,
    analyzer_metadata: list[dict[str, Any]],
    exit_code: int,
    status: str,
    report_data: dict[str, Any],
    output_format: str = "json",
) -> Path:
    """Write section files and ``artifact-manifest.json`` into *output_dir*.

    The legacy ``attackmap-report.json`` must already have been written;
    this function only adds the manifest and extracted section files.
    """
    out = ensure_output_dir(output_dir, mark=True)

    sections: list[ArtifactSection] = []
    for name, filename, role in SECTION_ORDER:
        data = report_data.get(name)
        if data is None:
            data = []
        path = out / filename
        text = json.dumps(data, indent=2) + "\n"
        safe_write_text(out, path, text)
        sections.append(
            ArtifactSection(
                name=name,
                path=filename,
                format="json",
                role=role,
                checksum=_sha256(text),
            )
        )

    # Reference standalone files that are already produced elsewhere.
    for name, filename, role in (
        ("defensive_review", "defensive-review.json", "defensive-review-structured"),
        ("review_context_pack", "review-context-pack.json", "review-context-pack"),
    ):
        section = _section_from_file(out, name, filename, role)
        if section is not None:
            sections.append(section)

    compatibility_exports = [
        ArtifactSection(
            name="legacy_report",
            path="attackmap-report.json",
            format="json",
            role="monolithic-legacy-report",
            checksum=None,
        ),
    ]
    legacy_report = out / "attackmap-report.json"
    if legacy_report.is_file():
        compatibility_exports[0] = ArtifactSection(
            name="legacy_report",
            path="attackmap-report.json",
            format="json",
            role="monolithic-legacy-report",
            checksum=hashlib.sha256(legacy_report.read_bytes()).hexdigest(),
        )

    # Record only files emitted by this presentation format, never every file
    # found in an output directory that may also contain user-owned sources.
    exports = ["run-manifest.json", "attackmap-report.sarif"]
    exports.extend(_OPTIONAL_EXPORTS)
    if output_format == "all":
        exports.extend(_MARKDOWN_EXPORTS)
    for filename in exports:
        section = _section_from_file(
            out, filename, filename, "compatibility-export", Path(filename).suffix.lstrip("."),
        )
        if section is not None:
            compatibility_exports.append(section)

    snapshot_block = _snapshot_publication_block(report_data, repo_root, out)
    exit_state: dict[str, Any] = {"exit_code": exit_code, "status": status}
    run_identity: dict[str, Any] = {
        "repo_root": repo_root,
        "repo_name": repo_name,
        "analyzers": list(analyzer_metadata),
        "analyzer_identity": _analyzer_identity(analyzer_metadata),
    }
    if snapshot_block is not None:
        run_identity["snapshot"] = snapshot_block
        if snapshot_block.get("incomplete"):
            # Additive marker (the status string stays engine-owned): a
            # drifted snapshot never publishes as a complete run (C33/AM047).
            exit_state["snapshot_state"] = "incomplete"

    manifest = ArtifactManifest(
        schema_version=SCHEMA_VERSION,
        artifact_type=ARTIFACT_TYPE,
        generation_id=run_id,
        engine_version=engine_version,
        created_at=_iso_now(),
        exit_state=exit_state,
        run_identity=run_identity,
        sections=sections,
        compatibility_exports=compatibility_exports,
    )

    manifest_path = out / MANIFEST_FILENAME
    safe_write_text(out, manifest_path, json.dumps(manifest.to_dict(), indent=2) + "\n")
    return manifest_path


def _artifact_json(path: Path, limit: int) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or path.stat().st_size > limit:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, UnicodeError, ValueError, RecursionError):
        return None


def _is_legacy_artifact(name: str, data: dict[str, Any]) -> bool:
    """Recognize old report structures without reserving their basenames."""
    shapes = {
        "attackmap-report.json": {"scan": dict, "findings": list, "attack_paths": list, "attack_surfaces": list},
        "run-manifest.json": {"engine_version": str, "analyzers": list, "stages": list, "files_scanned": int, "findings_by_severity": dict},
        "defensive-review.json": {"schema_version": str, "target_metadata": dict, "raw_structured_signals": dict, "limitations_meta": dict},
        "fleet-summary.json": {"repo_count": int, "repos": list, "cross_repo_links": list, "total_findings": int},
        "defensive-review-llm.meta.json": {"backend": str, "model": str, "usage": dict},
        "attackmap-diagnostics.json": {"schema_version": str, "export_type": str, "generated_at": str, "generations": list},
    }
    if name == "review-context-pack.json":
        return data.get("artifact_type") == "attackmap_review_context_pack"
    if name == "benchmark-results.json":
        overall = data.get("overall")
        return isinstance(data.get("cases"), list) and isinstance(overall, dict) and bool(overall) and all(
            isinstance(value, dict) and {"tp", "fp", "precision", "recall", "missed_expected"} <= value.keys()
            for value in overall.values()
        )
    required = shapes.get(name)
    return bool(required) and all(isinstance(data.get(key), kind) for key, kind in required.items())


def _is_pins_payload(data: dict[str, Any]) -> bool:
    """Recognize our pin store structurally; a user file with this name stays input."""
    pinned = data.get("pinned")
    return (data.get("schema_version") == "1.0" and isinstance(pinned, list)
            and len(pinned) <= 10_000 and len(set(pinned)) == len(pinned)
            and all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name)
                    and not name.endswith(".") for name in pinned))


def generated_artifact_names(directory: Path, filenames: list[str]) -> set[str]:
    """Identify local generated files using manifest checksums or legacy shapes.

    Invalid metadata and replaced files remain scan inputs. Only flat paths are
    accepted: current publishers write flat manifests, and a repository-supplied
    manifest must not hide arbitrary files in other directories.
    """
    names = set(filenames)
    generated: set[str] = set()
    claimed: set[str] = set()
    if "current-generation.json" in names:
        from .artifact_publisher import current_generation
        if current_generation(directory) is not None:
            generated.add("current-generation.json")
    if PINS_FILENAME in names:
        payload = _artifact_json(directory / PINS_FILENAME, min(max_file_bytes(), 100_000))
        if payload is not None and _is_pins_payload(payload):
            generated.add(PINS_FILENAME)
    manifest = (
        _artifact_json(directory / MANIFEST_FILENAME, min(max_file_bytes(), 1_000_000))
        if MANIFEST_FILENAME in names else None
    )
    if (manifest and manifest.get("artifact_type") == ARTIFACT_TYPE
            and isinstance(manifest.get("generation_id"), str)
            and isinstance(manifest.get("sections"), list)
            and isinstance(manifest.get("compatibility_exports"), list)):
        generated.add(MANIFEST_FILENAME)
        for section in manifest["sections"] + manifest["compatibility_exports"]:
            if not isinstance(section, dict):
                continue
            name = section.get("path")
            if (not isinstance(name, str) or name not in names
                    or name not in _MANIFEST_OUTPUT_NAMES or Path(name).name != name):
                continue
            claimed.add(name)
            path = directory / name
            try:
                if not path.is_symlink() and path.stat().st_size <= max_file_bytes():
                    if section.get("checksum") == hashlib.sha256(path.read_bytes()).hexdigest():
                        generated.add(name)
            except (OSError, UnicodeError):
                continue
    for name in sorted((names & _LEGACY_JSON_FILES) - claimed, key=lambda value: (value.endswith(".meta.json"), value)):
        data = _artifact_json(directory / name, max_file_bytes())
        if name == "defensive-review-llm.meta.json" and not generated & {"attackmap-report.json", "run-manifest.json"}:
            continue
        if data is not None and _is_legacy_artifact(name, data):
            generated.add(name)
    return generated


def _load_section(data: dict[str, Any]) -> ArtifactSection:
    return ArtifactSection(
        name=data["name"],
        path=data["path"],
        format=data["format"],
        role=data["role"],
        checksum=data.get("checksum"),
    )


def load_artifact_manifest(path: str | Path) -> ArtifactManifest:
    """Load ``artifact-manifest.json`` from disk.

    Extra keys are ignored so minor schema additions stay forward-compatible.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ArtifactManifest(
        schema_version=data["schema_version"],
        artifact_type=data["artifact_type"],
        generation_id=data["generation_id"],
        engine_version=data["engine_version"],
        created_at=data["created_at"],
        exit_state=dict(data["exit_state"]),
        run_identity=dict(data["run_identity"]),
        sections=[_load_section(s) for s in data["sections"]],
        compatibility_exports=[_load_section(e) for e in data["compatibility_exports"]],
    )
