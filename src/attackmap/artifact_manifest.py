"""Versioned artifact manifest and section files for AttackMap scan output."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .safe_fs import UnsafePathError, ensure_output_dir, safe_write_text


SCHEMA_VERSION = "1.0.0"
ARTIFACT_TYPE = "attackmap_artifact_manifest"

# Sections extracted from the legacy monolithic report JSON.
SECTION_ORDER: list[tuple[str, str, str]] = [
    ("scan", "scan.json", "structured-scan-result"),
    ("findings", "findings.json", "findings-array"),
    ("attack_paths", "attack_paths.json", "attack-paths-array"),
    ("attack_surfaces", "attack_surfaces.json", "attack-surfaces-array"),
    ("exploitability", "exploitability.json", "exploitability-array"),
    ("suppressed_findings", "suppressed_findings.json", "suppressed-findings-array"),
]


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


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_run_id() -> str:
    """Return a deterministic id for CLI runs without an explicit run_id."""
    now = datetime.now(timezone.utc)
    short = hashlib.sha256(now.isoformat().encode()).hexdigest()[:8]
    return f"{now.strftime('%Y%m%dT%H%M%S')}-{short}"


def _section_from_file(
    out: Path, name: str, filename: str, role: str
) -> ArtifactSection | None:
    path = out / filename
    if not path.is_file():
        return None
    return ArtifactSection(
        name=name,
        path=filename,
        format="json",
        role=role,
        checksum=_sha256(path.read_text(encoding="utf-8")),
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
            checksum=_sha256(legacy_report.read_text(encoding="utf-8")),
        )

    manifest = ArtifactManifest(
        schema_version=SCHEMA_VERSION,
        artifact_type=ARTIFACT_TYPE,
        generation_id=run_id,
        engine_version=engine_version,
        created_at=_iso_now(),
        exit_state={"exit_code": exit_code, "status": status},
        run_identity={
            "repo_root": repo_root,
            "repo_name": repo_name,
            "analyzers": list(analyzer_metadata),
        },
        sections=sections,
        compatibility_exports=compatibility_exports,
    )

    manifest_path = out / "artifact-manifest.json"
    safe_write_text(out, manifest_path, json.dumps(manifest.to_dict(), indent=2) + "\n")
    return manifest_path


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
