"""Validate immutable report generations and commit one current pointer.

Callers render into ``generation_dir`` and never modify a published directory.
The pointer is the only commit boundary; old generations are retained.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path
from typing import Callable

from .artifact_manifest import ARTIFACT_TYPE, MANIFEST_FILENAME, SCHEMA_VERSION, SECTION_ORDER
from .safe_fs import UnsafePathError, ensure_output_dir, safe_write_text

CURRENT_POINTER = "current-generation.json"
DEFAULT_REQUIRED = ("attackmap-report.json", MANIFEST_FILENAME, "run-manifest.json")
FLEET_REQUIRED = ("fleet-summary.json", MANIFEST_FILENAME, "run-manifest.json")


def _component(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) or value.endswith("."):
        raise UnsafePathError("Invalid generation or artifact name")
    if value.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        raise UnsafePathError("Reserved Windows path component")
    return value


def _safe(path: Path) -> Path:
    # lstat flags are available on Python 3.11, unlike Path.is_junction().
    # Check ancestors first so a redirected parent is rejected before traversal.
    for part in reversed((path.absolute(), *path.absolute().parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue  # A not-yet-created destination is allowed.
        except OSError as exc:
            raise UnsafePathError("Cannot verify artifact path") from exc
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or getattr(info, "st_reparse_tag", 0)):
            raise UnsafePathError(f"Refusing redirected artifact path: {part}")
    return path


def prepare_output_root(base: Path) -> Path:
    """Validate before creating/marking an atomic output root; allocate no run."""
    base = _safe(Path(base))
    return ensure_output_dir(base, mark=True)


def generation_dir(base: Path, run_id: str) -> Path:
    base = _safe(Path(base))
    ensure_output_dir(base)
    folder = _safe(base / _component(run_id))
    if (folder / MANIFEST_FILENAME).exists():
        raise ValueError("Generation already finalized; choose a unique run ID")
    folder.mkdir(exist_ok=True)
    return folder


def _json(path: Path) -> dict:
    _safe(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path.name}")
    return data


def validate_generation(folder: Path, *, required_files: tuple[str, ...] = DEFAULT_REQUIRED) -> dict:
    """Verify manifest version, required section shapes, and every recorded byte hash."""
    folder = _safe(Path(folder))
    manifest = _json(folder / MANIFEST_FILENAME)
    fleet = manifest.get("generation_profile") == "fleet"
    if fleet and required_files == DEFAULT_REQUIRED:
        required_files = FLEET_REQUIRED
    for name in required_files:
        path = _safe(folder / _component(name))
        if not path.is_file():
            raise ValueError(f"Missing required artifact: {name}")
    if (manifest.get("schema_version") != SCHEMA_VERSION
            or manifest.get("artifact_type") != ARTIFACT_TYPE
            or manifest.get("generation_id") != folder.name):
        raise ValueError("Unsupported or foreign artifact manifest")
    identity = manifest.get("run_identity")
    if (not isinstance(manifest.get("engine_version"), str)
            or not isinstance(manifest.get("created_at"), str)
            or not isinstance(identity, dict)
            or not isinstance(identity.get("repo_root"), str)
            or not isinstance(identity.get("repo_name"), str)
            or not isinstance(identity.get("analyzers"), list)):
        raise ValueError("Invalid artifact manifest identity")
    state = manifest.get("exit_state", {})
    if (not isinstance(state, dict) or type(state.get("exit_code")) is not int
            or state.get("status") not in {"completed", "success", "succeeded", "ok", "policy_failed"}):
        raise ValueError("Unsuccessful generation cannot become current")
    sections = manifest.get("sections")
    exports = manifest.get("compatibility_exports")
    if not isinstance(sections, list) or not isinstance(exports, list):
        raise ValueError("Invalid artifact entries")
    paths = set()
    for entry in sections + exports:
        if not isinstance(entry, dict):
            raise ValueError("Invalid artifact entry")
        if not all(isinstance(entry.get(key), str) for key in ("name", "format", "role", "path")):
            raise ValueError("Invalid artifact entry schema")
        name = _component(entry.get("path", ""))
        if name in paths:
            raise ValueError("Duplicate artifact path")
        paths.add(name)
        path = _safe(folder / name)
        raw = path.read_bytes()
        if "size_bytes" in entry and entry["size_bytes"] != len(raw):
            raise ValueError(f"Artifact size mismatch: {name}")
        if hashlib.sha256(raw).hexdigest() != entry.get("checksum"):
            raise ValueError(f"Artifact checksum mismatch: {name}")
        if entry.get("format") == "json":
            json.loads(raw)
    for key, filename, _ in ([] if fleet else SECTION_ORDER):
        if filename not in paths:
            raise ValueError(f"Missing required section: {filename}")
        value = json.loads((folder / filename).read_text(encoding="utf-8"))
        if not isinstance(value, dict if key == "scan" else list):
            raise ValueError(f"Invalid section schema: {filename}")
    if not set(required_files).difference({MANIFEST_FILENAME}) <= paths:
        raise ValueError("Required artifacts must have manifest checksums")
    if fleet:
        summary = _json(folder / "fleet-summary.json")
        if (type(summary.get("repo_count")) is not int or not isinstance(summary.get("repos"), list)
                or not isinstance(summary.get("cross_repo_links"), list)
                or type(summary.get("total_findings")) is not int):
            raise ValueError("Invalid fleet summary schema")
        children = manifest.get("children")
        if not isinstance(children, list) or len(children) != summary["repo_count"]:
            raise ValueError("Missing fleet child generations")
        seen = set()
        for child in children:
            parts = child["path"].split("/")
            if len(parts) != 2 or child["path"] in seen:
                raise ValueError("Invalid fleet child path")
            seen.add(child["path"])
            target = _safe(folder.joinpath(*(_component(part) for part in parts)))
            if hashlib.sha256((target / MANIFEST_FILENAME).read_bytes()).hexdigest() != child["manifest_sha256"]:
                raise ValueError("Fleet child manifest checksum mismatch")
            validate_generation(target)
    else:
        report = _json(folder / "attackmap-report.json")
        if not isinstance(report.get("scan"), dict) or not isinstance(report["scan"].get("root"), str):
            raise ValueError("Invalid report schema")
    timing = _json(folder / "run-manifest.json")
    if not isinstance(timing.get("stages"), list):
        raise ValueError("Invalid run timing schema")
    return manifest


def current_generation(base: Path) -> Path | None:
    """Resolve only a fully validated current generation; corruption fails closed."""
    try:
        base = _safe(Path(base))
        pointer = _json(base / CURRENT_POINTER)
        folder = _safe(base / _component(pointer["generation"]))
        manifest_bytes = (folder / MANIFEST_FILENAME).read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != pointer["manifest_sha256"]:
            return None
        validate_generation(folder)
        return folder
    except (OSError, ValueError, KeyError, TypeError):
        return None


def publish_generation(base: Path, run_id: str, *,
                       required_files: tuple[str, ...] = DEFAULT_REQUIRED,
                       cancelled: Callable[[], bool] | None = None,
                       boundary: Callable[[str], None] | None = None) -> Path:
    """Finalize and validate staged output, then atomically commit its pointer.

    ``boundary`` is a test fault-injection hook. Cancellation before commit leaves
    current untouched. A cancellation racing after commit observes a completed
    publication. No fallible operation is performed after the commit.
    """
    started = time.perf_counter()
    base = _safe(Path(base))
    folder = _safe(base / _component(run_id))
    pointer_path = _safe(base / CURRENT_POINTER)
    if pointer_path.exists() and _json(pointer_path).get("generation") == run_id:
        raise ValueError("Cannot modify the current generation")

    def checkpoint(name: str) -> None:
        if boundary:
            boundary(name)
        if cancelled and cancelled():
            raise InterruptedError("Artifact publication cancelled")

    checkpoint("before_validation")
    manifest = validate_generation(folder, required_files=required_files)
    if manifest.get("publication", {}).get("immutable"):
        raise ValueError("Generation already prepared; choose a unique run ID")
    checkpoint("after_validation")
    timing_path = folder / "run-manifest.json"
    timing = _json(timing_path)
    timing["stages"] = [s for s in timing["stages"] if s.get("name") != "publication"]
    # Duration covers validation and preparation; the atomic replace itself is
    # intentionally excluded because committed files must never be rewritten.
    timing["stages"].append({"name": "publication", "milliseconds": round((time.perf_counter() - started) * 1000, 3)})
    if "diagnostic_context" in timing:
        from .diagnostics import DiagnosticStage, context_from_run_manifest
        context = context_from_run_manifest(timing, outcome="completed")
        stages = [stage for stage in context.stages if stage.stage_id != "publication"]
        stages.append(DiagnosticStage(stage_id="publication", outcome="completed",
                                      duration_milliseconds=timing["stages"][-1]["milliseconds"]))
        timing["diagnostic_context"] = context.model_copy(update={"stages": stages[:128]}).model_dump(mode="json")
    safe_write_text(folder, timing_path, json.dumps(timing, indent=2) + "\n")
    checkpoint("after_timing")
    for entry in manifest["sections"] + manifest["compatibility_exports"]:
        if entry["path"] == "run-manifest.json":
            entry["checksum"] = hashlib.sha256(timing_path.read_bytes()).hexdigest()
        entry["size_bytes"] = (folder / entry["path"]).stat().st_size
    manifest["publication"] = {"immutable": True}
    safe_write_text(folder, folder / MANIFEST_FILENAME, json.dumps(manifest, indent=2) + "\n")
    checkpoint("after_manifest")
    validate_generation(folder, required_files=required_files)
    pointer = {"generation": run_id, "manifest_sha256": hashlib.sha256((folder / MANIFEST_FILENAME).read_bytes()).hexdigest()}
    tmp = _safe(base / f".current-{uuid.uuid4().hex}.tmp")
    committed = False
    try:
        safe_write_text(base, tmp, json.dumps(pointer) + "\n")
        with tmp.open("r+b") as handle:
            os.fsync(handle.fileno())
        checkpoint("before_commit")
        _safe(pointer_path)
        os.replace(tmp, pointer_path)
        committed = True
    finally:
        if not committed and tmp.exists():
            tmp.unlink()
    return folder


def _bounded_diagnostic_json(path: Path) -> dict:
    _safe(path)
    with path.open("rb") as handle:
        raw = handle.read(1_000_001)
    _safe(path)
    if len(raw) > 1_000_000:
        raise ValueError("Diagnostic metadata exceeds size limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Diagnostic metadata must be an object")
    return value


def _safe_scan_timing(value):
    from datetime import datetime
    if not isinstance(value, dict) or value.get("schema_version") != "1.0" or value.get("clock") != "engine_utc" or value.get("scope") != "analysis_pipeline_before_publication":
        return None
    if value.get("outcome") not in {None, "completed", "failed", "cancelled"}:
        return None
    stamps = {}
    for key in ("started_at", "finished_at"):
        text = value.get(key)
        if text is not None:
            try:
                stamp = datetime.fromisoformat(text)
                if stamp.utcoffset() is None or stamp.utcoffset().total_seconds() != 0:
                    return None
                stamps[key] = stamp
            except (TypeError, ValueError):
                return None
    if "finished_at" in stamps and ("started_at" not in stamps or stamps["finished_at"] < stamps["started_at"]):
        return None
    return {key: value.get(key) for key in ("schema_version", "clock", "scope", "started_at", "finished_at", "outcome")}


def context_from_staged_run(folder: Path, *, outcome: str):
    """Read bounded stage metadata, not a claim of final artifact/hash integrity."""
    from .diagnostics import DiagnosticContext, context_from_run_manifest, merge_diagnostic_context
    from pydantic import ValidationError
    folder = _safe(Path(folder))
    manifest_path = folder / MANIFEST_FILENAME
    if manifest_path.exists():
        try:
            manifest = _bounded_diagnostic_json(manifest_path)
            if manifest.get("generation_id") != folder.name or manifest.get("schema_version") != SCHEMA_VERSION:
                return None
        except (OSError, ValueError):
            return None
    context = None
    candidates = (folder / "run-manifest.json",
                  folder / "diagnostics" / _component(folder.name) / "terminal-diagnostic.json")
    for path in candidates:
        try:
            _safe(path)
            value = _bounded_diagnostic_json(path)
            if path.name == "run-manifest.json":
                incoming = context_from_run_manifest(value, outcome=outcome)
            else:
                if not _diagnostic_identity(value, folder.name):
                    continue
                incoming = DiagnosticContext.model_validate(value["diagnostic_context"])
                incoming = incoming.model_copy(update={"outcome": outcome})
            context = merge_diagnostic_context(context, incoming)
        except (OSError, ValueError, KeyError, ValidationError):
            continue
    return context


def _diagnostic_identity(payload: dict, run_id: str) -> bool:
    return (payload.get("schema_version") in {"1.0", "1.1"} and payload.get("run_id") == run_id
            and payload.get("state") in {"failed", "cancelled"}
            and payload.get("artifact_readiness") == "unavailable")


def diagnostic_context_from_generation(base: Path, run_id: str, *, outcome: str):
    return context_from_staged_run(_safe(Path(base)) / _component(run_id), outcome=outcome)


def write_diagnostic(base: Path, run_id: str, *, state: str, error: str | None = None,
                     scan_timing: dict[str, str | None] | None = None,
                     context=None, preserve_context: bool = True) -> Path:
    """Record a failed/cancelled run separately without changing current."""
    if state not in {"failed", "cancelled"}:
        raise ValueError("Diagnostic state must be failed or cancelled")
    folder = _safe(Path(base) / "diagnostics" / _component(run_id))
    ensure_output_dir(folder, mark=True)
    target = _safe(folder / "terminal-diagnostic.json")
    from .diagnostics import DiagnosticContext, merge_diagnostic_context, unknown_diagnostic
    incoming = (DiagnosticContext.model_validate(context) if isinstance(context, dict)
                else context if isinstance(context, DiagnosticContext) else unknown_diagnostic(outcome=state))
    incoming = incoming.model_copy(update={"outcome": state})
    previous = None
    previous_payload = {}
    if preserve_context:
        try:
            previous_payload = _bounded_diagnostic_json(target)
            if _diagnostic_identity(previous_payload, run_id):
                previous = DiagnosticContext.model_validate(previous_payload.get("diagnostic_context"))
            else:
                previous_payload = {}
        except (OSError, ValueError):
            pass
    payload = {"schema_version": "1.1", "run_id": run_id,
               "state": state, "artifact_readiness": "unavailable", "error": error,
               "diagnostic_context": merge_diagnostic_context(previous, incoming).model_dump(mode="json")}
    timing = _safe_scan_timing(scan_timing if scan_timing is not None else previous_payload.get("scan_timing"))
    if timing is not None:
        payload["scan_timing"] = timing
    safe_write_text(folder, target, json.dumps(payload, indent=2) + "\n")
    return target


def export_compatibility(base: Path, generation: Path, *, output_format: str = "all") -> list[Path]:
    """Export known reports as a nonauthoritative flat compatibility view.

    Existing user files are never overwritten. A failed export does not undo
    the committed generation; consumers requiring consistency use the pointer.
    """
    from .artifact_manifest import _MANIFEST_OUTPUT_NAMES, generated_artifact_names
    if output_format not in {"all", "json", "markdown"}:
        raise ValueError("Unknown compatibility output format")
    base, generation = _safe(Path(base)), _safe(Path(generation))
    if current_generation(base) != generation:
        raise ValueError("Only the current generation can be exported")
    manifest = validate_generation(generation)
    allowed = _MANIFEST_OUTPUT_NAMES | {MANIFEST_FILENAME, "fleet-summary.json", "fleet-summary.md", "fleet-graph.md"}
    sources = [(base, generation, manifest)]
    if manifest.get("generation_profile") == "fleet":
        destinations = set()
        for child in manifest["children"]:
            repo_id, child_id = child["path"].split("/")
            destination = _safe(base / _component(repo_id))
            if destination in destinations or destination == generation:
                raise ValueError("Fleet compatibility destinations must be unique")
            destinations.add(destination)
            source = _safe(generation / repo_id / child_id)
            sources.append((destination, source, validate_generation(source)))
    plans = []
    for destination, source, source_manifest in sources:
        names = {entry["path"] for entry in source_manifest["sections"] + source_manifest["compatibility_exports"]} & allowed
        names.add(MANIFEST_FILENAME)
        if output_format == "json":
            names = {name for name in names if Path(name).suffix in {".json", ".sarif"}}
        elif output_format == "markdown":
            names = {name for name in names if Path(name).suffix in {".md", ".dot"}
                     or name in {"run-manifest.json", MANIFEST_FILENAME}}
        existing = [path.name for path in destination.iterdir() if path.is_file()] if destination.is_dir() else []
        generated = generated_artifact_names(destination, existing)
        # Fleet Markdown files also carry positive byte identities, even though
        # the scanner's older output allowlist only recognizes scan filenames.
        if MANIFEST_FILENAME in existing:
            previous = _json(destination / MANIFEST_FILENAME)
            if destination != base and previous.get("generation_id") == destination.name:
                raise ValueError("Compatibility export cannot overwrite an immutable generation")
            if previous.get("artifact_type") == ARTIFACT_TYPE and previous.get("schema_version") == SCHEMA_VERSION:
                for entry in previous.get("sections", []) + previous.get("compatibility_exports", []):
                    if isinstance(entry, dict) and entry.get("path") in allowed:
                        path = _safe(destination / entry["path"])
                        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == entry.get("checksum"):
                            generated.add(entry["path"])
        # Preflight every child and parent before replacing any files.
        if destination.exists() and not destination.is_dir():
            raise ValueError(f"Compatibility export would overwrite a user file: {destination.name}")
        for name in names:
            target = _safe(destination / name)
            if target.exists() and name not in generated:
                raise ValueError(f"Compatibility export would overwrite a user file: {target}")
        plans.append((destination, source, names))
    exported = []
    for destination, source, names in sorted(plans, key=lambda plan: plan[0] == base):
        ensure_output_dir(destination)
        for name in sorted(names, key=lambda name: name == MANIFEST_FILENAME):
            target = destination / name
            with (source / name).open(encoding="utf-8", newline="") as handle:
                safe_write_text(destination, target, handle.read())
            exported.append(target)
    return exported


def write_fleet_manifest(folder: Path, run_id: str, *, engine_version: str,
                         repo_roots: list[str], status: str = "succeeded", exit_code: int = 0) -> Path:
    """Index fleet artifacts and bind each already published child generation."""
    from datetime import datetime, timezone
    folder = _safe(Path(folder))
    if folder.name != _component(run_id):
        raise ValueError("Fleet generation identity mismatch")
    children = []
    for candidate in sorted(folder.iterdir()):
        if candidate.is_dir():
            child = current_generation(candidate)
            if child is not None:
                children.append({"path": child.relative_to(folder).as_posix(),
                    "manifest_sha256": hashlib.sha256((child / MANIFEST_FILENAME).read_bytes()).hexdigest()})
    if not (folder / "run-manifest.json").exists():
        safe_write_text(folder, folder / "run-manifest.json", json.dumps({"stages": []}) + "\n")
    entries = []
    for name in ("fleet-summary.json", "run-manifest.json", "fleet-summary.md", "fleet-graph.md"):
        path = _safe(folder / name)
        if path.is_file():
            entries.append({"name": name, "path": name, "format": path.suffix[1:],
                "role": "fleet-artifact", "checksum": hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest = {"schema_version": SCHEMA_VERSION, "artifact_type": ARTIFACT_TYPE,
        "generation_id": run_id, "generation_profile": "fleet", "engine_version": engine_version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "exit_state": {"status": status, "exit_code": exit_code},
        "run_identity": {"repo_root": "fleet", "repo_name": "fleet", "analyzers": [], "repo_roots": repo_roots},
        "sections": entries, "compatibility_exports": [], "children": children}
    target = folder / MANIFEST_FILENAME
    safe_write_text(folder, target, json.dumps(manifest, indent=2) + "\n")
    validate_generation(folder)
    return target
