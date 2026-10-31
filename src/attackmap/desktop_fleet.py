"""Explicit schema 1.4 desktop fleet admission and supervised transport.

The CLI fleet engine remains authoritative for links, ordering and scores.
Partial indexes are diagnostic results, never current analysis generations.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import sys
import threading
from typing import Literal, TextIO

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .run_contract import RunEnvelope, RunProgress, RunTerminal, ScanOptionsV15


def normalized_root(value: str) -> str:
    if PureWindowsPath(value).drive:
        return ntpath.normcase(ntpath.normpath(value))
    return os.path.normcase(os.path.normpath(value))


class FleetRepository(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)
    repository_id: str = Field(min_length=1, max_length=256)
    repository_path: str = Field(min_length=1, max_length=32767)

    @field_validator("repository_path")
    @classmethod
    def local_absolute(cls, value: str) -> str:
        if (any(ord(c) < 32 for c in value) or value.startswith(("\\\\", "//"))
                or not (PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute())):
            raise ValueError("Fleet roots must be absolute local paths")
        return value


def repository_set_id(repositories: list[FleetRepository]) -> str:
    entries = sorted((item.repository_id, normalized_root(item.repository_path)) for item in repositories)
    raw = json.dumps(entries, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return "fleet:" + hashlib.sha256(raw).hexdigest()


class FleetScanOptions(ScanOptionsV15):
    """Fleet-supported scan options; unknown options must never disappear."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)


class FleetRunRequest(RunEnvelope):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)
    schema_version: Literal["1.4"] = "1.4"
    kind: Literal["fleet_request"] = "fleet_request"
    repositories: list[FleetRepository] = Field(min_length=2, max_length=16)
    output_path: str = Field(min_length=1)
    modules: list[str] = Field(default_factory=list)
    max_workers: int = Field(default=1, ge=1, le=4)
    options: FleetScanOptions = Field(default_factory=FleetScanOptions)

    @model_validator(mode="after")
    def admitted(self) -> FleetRunRequest:
        roots = [normalized_root(item.repository_path) for item in self.repositories]
        ids = [item.repository_id for item in self.repositories]
        if len(set(roots)) != len(roots) or len(set(ids)) != len(ids):
            raise ValueError("Fleet repository identities and roots must be unique")
        if self.repository_id != repository_set_id(self.repositories):
            raise ValueError("Repository-set identity mismatch")
        o = self.options
        if o.analyzer_profile is not None:
            from .analyzer_profiles import get_analyzer_profiles
            if self.modules or not any(p.qualified_name == o.analyzer_profile for p in get_analyzer_profiles()):
                raise ValueError("Fleet analyzer profile is unsupported or conflicts with explicit modules")
        if (o.provider.effective_mode != "none" or o.baseline is not None
                or o.fail_on_new_high or o.fail_on_new_suppression or o.secrets_history
                or o.suppress_file is not None):
            raise ValueError("Fleet AI, baseline policies, custom suppression and history are unsupported")
        return self


class FleetChildEvent(RunEnvelope):
    schema_version: Literal["1.4"] = "1.4"
    kind: Literal["fleet_child"] = "fleet_child"
    child_repository_id: str
    child_repository_path: str
    child_run_id: str
    child_output_id: str
    state: Literal["queued", "running", "completed", "failed", "cancelled", "skipped"]
    completed_units: int | None = Field(default=None, ge=0)
    total_units: int | None = Field(default=None, ge=0)
    manifest_path: str | None = None
    manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def consistent(self) -> FleetChildEvent:
        if self.total_units is not None and (self.completed_units is None or self.completed_units > self.total_units):
            raise ValueError("Invalid child progress")
        if (self.manifest_path is None) != (self.manifest_sha256 is None):
            raise ValueError("Manifest path and hash must be supplied together")
        if self.manifest_path is not None and self.state != "completed":
            raise ValueError("Only verified complete children have manifest references")
        if self.state == "completed" and self.manifest_path is None:
            raise ValueError("Complete child requires a verified manifest reference")
        return self


class FleetTerminal(RunTerminal):
    schema_version: Literal["1.4"] = "1.4"
    kind: Literal["fleet_terminal"] = "fleet_terminal"
    fleet_outcome: Literal["succeeded", "partial", "failed", "cancelled"]
    children: list[FleetChildEvent] = Field(min_length=2, max_length=16)
    index_path: str | None = None
    index_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def consistent_fleet(self) -> FleetTerminal:
        if self.fleet_outcome == "succeeded" and (self.state != "completed" or any(c.state != "completed" for c in self.children)):
            raise ValueError("A complete fleet requires every child")
        if self.fleet_outcome != "succeeded" and self.state == "completed":
            raise ValueError("Incomplete fleet cannot be completed")
        if (self.fleet_outcome == "cancelled") != (self.state == "cancelled"):
            raise ValueError("Cancellation must remain explicit")
        if self.fleet_outcome == "partial" and not (any(c.state == "completed" for c in self.children)
                and any(c.state != "completed" for c in self.children)):
            raise ValueError("Partial fleet requires successful and incomplete children")
        if len({c.child_repository_id for c in self.children}) != len(self.children):
            raise ValueError("Child identities must be unique")
        if any(any(getattr(c, key) != getattr(self, key) for key in
                   ("schema_version", "run_id", "repository_id", "generation")) for c in self.children):
            raise ValueError("Child envelopes must belong to this parent generation")
        if (self.index_path is None) != (self.index_sha256 is None):
            raise ValueError("Index path and hash must be supplied together")
        return self


def child_run_id(request: FleetRunRequest, repository: FleetRepository) -> str:
    raw = json.dumps([request.run_id, request.generation, repository.repository_id], separators=(",", ":"))
    return "child-" + hashlib.sha256(raw.encode()).hexdigest()[:32]


def validate_roots(request: FleetRunRequest) -> None:
    resolved = []
    for repository in request.repositories:
        root = Path(repository.repository_path)
        if not root.is_dir():
            raise ValueError("Fleet repository is unavailable")
        resolved.append(os.path.normcase(str(root.resolve(strict=True))))
    if len(set(resolved)) != len(resolved):
        raise ValueError("Fleet roots resolve to the same repository")


def broker_argv(prepared: Path) -> list[str]:
    prefix = ([sys.executable, "desktop-worker"] if getattr(sys, "frozen", False)
              else [sys.executable, "-m", "attackmap.desktop_worker"])
    return [*prefix, "--engine", "--request", str(prepared)]


def _identity(request: FleetRunRequest) -> dict:
    return {name: getattr(request, name) for name in ("schema_version", "run_id", "repository_id", "generation")}


def collect_children(request: FleetRunRequest, folder: Path, *, failed: set[str] | None = None,
                     cancelled: bool = False, started: set[str] | None = None) -> list[FleetChildEvent]:
    """Only a validated exact child generation can establish successful completion."""
    from .artifact_publisher import validate_generation
    from .fleet import fleet_repo_ids
    rows = []
    for slug, repository in zip(fleet_repo_ids([Path(r.repository_path) for r in request.repositories]), request.repositories):
        run_id = child_run_id(request, repository)
        # Collection is read-only: generation_dir allocates a new generation
        # and deliberately rejects an already finalized one. Validation below
        # checks this existing path, including redirected ancestors and hashes.
        child = folder / slug / run_id
        state = ("cancelled" if cancelled and repository.repository_id in (started or set()) else
                 "failed" if slug in (failed or set()) or repository.repository_id in (started or set()) else "skipped")
        path = checksum = None
        try:
            manifest = validate_generation(child)
            if (manifest["generation_id"] != run_id or normalized_root(manifest["run_identity"]["repo_root"])
                    != normalized_root(str(Path(repository.repository_path).resolve()))):
                raise ValueError("Child identity mismatch")
            report = json.loads((child / "attackmap-report.json").read_text(encoding="utf-8"))
            if normalized_root(report["scan"]["root"]) != normalized_root(str(Path(repository.repository_path).resolve())):
                raise ValueError("Child report identity mismatch")
            path = str(child / "artifact-manifest.json")
            checksum = hashlib.sha256(Path(path).read_bytes()).hexdigest()
            state = "completed"
        except (OSError, ValueError, KeyError, TypeError):
            if child.exists() and state == "skipped":
                state = "failed"
        rows.append(FleetChildEvent(**_identity(request), revision=0,
            child_repository_id=repository.repository_id, child_repository_path=repository.repository_path,
            child_run_id=run_id, child_output_id=slug, state=state, manifest_path=path, manifest_sha256=checksum))
    return rows


_MAX_FLEET_SUMMARY_BYTES = 64 * 1024 * 1024


def _fleet_summary_reference(folder: Path) -> dict[str, str] | None:
    """Bind available diagnostic bytes, never establish successful publication."""
    from .artifact_publisher import _safe
    target = _safe(folder / "fleet-summary.json")
    try:
        before = target.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_FLEET_SUMMARY_BYTES:
        raise ValueError("Fleet summary is not a bounded regular file")

    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
                getattr(info, "st_file_attributes", 0), getattr(info, "st_reparse_tag", 0))

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(target, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if fingerprint(opened) != fingerprint(before):
            raise ValueError("Fleet summary changed before reading")
        raw = handle.read(_MAX_FLEET_SUMMARY_BYTES + 1)
        after = os.fstat(handle.fileno())
    _safe(target)
    current = target.lstat()
    if (len(raw) > _MAX_FLEET_SUMMARY_BYTES or len(raw) != before.st_size
            or fingerprint(before) != fingerprint(after)
            or fingerprint(after) != fingerprint(current)
            # Windows lstat/fstat may expose different ctime semantics; compare like APIs.
            or before.st_ctime_ns != current.st_ctime_ns
            or opened.st_ctime_ns != after.st_ctime_ns):
        raise ValueError("Fleet summary changed while reading")
    return {"path": "fleet-summary.json", "sha256": hashlib.sha256(raw).hexdigest()}


def _index_payload(request: FleetRunRequest, folder: Path, children: list[FleetChildEvent]) -> dict:
    payload = {**_identity(request), "kind": "fleet_index", "children": [row.model_dump(mode="json") for row in children]}
    summary = _fleet_summary_reference(folder)
    if summary is not None:
        payload["fleet_summary"] = summary
    return payload


def write_index(request: FleetRunRequest, folder: Path, children: list[FleetChildEvent]) -> Path:
    from .safe_fs import safe_write_text
    target = folder / "desktop-fleet.json"
    payload = _index_payload(request, folder, children)
    safe_write_text(folder, target, json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
    return target


def run_engine(request: FleetRunRequest) -> int:
    from .analyzers import select_requested_analyzers
    from .fleet import fleet_repo_ids
    from .run_contract import RunRequest
    from .scan_service import ScanRequestError, execute_scan_request, scan_request_from_run
    validate_roots(request)
    selected = select_requested_analyzers(request.modules, auto_install=False) if request.modules else None
    # Reuse the neutral option mapping; the synthetic request is never dispatched.
    single = RunRequest(schema_version="1.5" if request.options.analyzer_profile else "1.3", run_id=request.run_id, repository_id=request.repositories[0].repository_id,
        generation=request.generation, revision=0, repository_path=request.repositories[0].repository_path,
        output_path=request.output_path, modules=request.modules,
        options=request.options.model_dump(exclude={"analyzer_profile"}) if request.options.analyzer_profile is None else request.options.model_dump())
    service = scan_request_from_run(single, echo=lambda *args, **kwargs: None)
    service.repo_paths = [Path(item.repository_path) for item in request.repositories]
    service.max_workers = request.max_workers
    service.analyzers = selected
    service.fleet_supervised = True
    service.fleet_timeout_seconds = request.options.timeout_seconds
    service.fleet_child_run_ids = dict(zip(fleet_repo_ids(service.repo_paths),
        [child_run_id(request, item) for item in request.repositories]))
    started: set[str] = set()
    rows_by_slug = dict(zip(fleet_repo_ids(service.repo_paths), request.repositories))
    lock = threading.Lock()

    def progress(event: dict) -> None:
        repository = rows_by_slug[event["repo_id"]]
        if event.get("state") in {"completed", "failed"}:
            row = next(item for item in collect_children(request, Path(request.output_path),
                failed={event["repo_id"]} if event["state"] == "failed" else set(), started=started)
                if item.child_repository_id == repository.repository_id)
            with lock:
                print(json.dumps({"event": "fleet_child", "child": row.model_dump(mode="json")}), file=sys.stderr, flush=True)
            return
        supplied = event.get("progress", {})
        done, total = supplied.get("done"), supplied.get("total")
        bounded = type(done) is int and type(total) is int and 0 <= done <= total
        row = FleetChildEvent(**_identity(request), revision=0,
            child_repository_id=repository.repository_id, child_repository_path=repository.repository_path,
            child_run_id=child_run_id(request, repository), child_output_id=event["repo_id"], state="running",
            completed_units=done if bounded else None, total_units=total if bounded else None)
        with lock:
            started.add(repository.repository_id)
            print(json.dumps({"event": "fleet_child", "child": row.model_dump(mode="json")}), file=sys.stderr, flush=True)

    cancellation = threading.Event()
    service.cancel_check = cancellation.is_set
    service.fleet_event = progress
    service.fleet_finished = lambda folder, fleet: write_index(request, folder,
        collect_children(request, folder, failed={item["repo_id"] for item in fleet.failed},
                         cancelled=cancellation.is_set(), started=started))
    import signal
    handlers = {}
    if threading.current_thread() is threading.main_thread():
        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            if hasattr(signal, name):
                number = getattr(signal, name)
                handlers[number] = signal.getsignal(number)
                signal.signal(number, lambda *_: cancellation.set())
    try:
        try:
            result = execute_scan_request(service)
        except ScanRequestError:
            raise ValueError("Desktop fleet application request failed validation") from None
        return 130 if cancellation.is_set() else result.exit_code
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)


def serve(request: FleetRunRequest, *, control: TextIO, events: TextIO) -> int:
    from .artifact_publisher import generation_dir, publish_generation, validate_generation
    from .execution import ProcessSupervisor
    from .safe_fs import ensure_output_dir, safe_write_text
    validate_roots(request)
    folder = generation_dir(Path(request.output_path).absolute(), request.run_id)
    ensure_output_dir(folder, mark=True)
    prepared = folder / "desktop-request.json"
    safe_write_text(folder, prepared, request.model_copy(update={"output_path": str(folder)}).model_dump_json())
    supervisor = ProcessSupervisor()
    lock, finished, cancelled = threading.RLock(), threading.Event(), threading.Event()
    revision = request.revision
    completing = False
    started: set[str] = set()
    expected = {item.repository_id: item for item in request.repositories}
    from .fleet import fleet_repo_ids
    output_ids = dict(zip(expected, fleet_repo_ids([Path(r.repository_path) for r in request.repositories])))

    def emit(model) -> None:
        nonlocal revision
        with lock:
            revision += 1
            payload = model.model_copy(update={"revision": revision}).model_dump(mode="json")
            try:
                events.write(json.dumps(payload, ensure_ascii=True) + "\n")
                events.flush()
            except (OSError, BrokenPipeError):
                cancelled.set()
                supervisor.request_cancel()

    def progress(event: dict) -> None:
        with lock:
            if completing or event.get("event") != "fleet_child":
                return
            try:
                row = FleetChildEvent.model_validate(event["child"])
                repository = expected[row.child_repository_id]
                if (any(getattr(row, key) != value for key, value in _identity(request).items())
                        or row.child_run_id != child_run_id(request, repository)
                        or row.child_output_id != output_ids[repository.repository_id]
                        or row.child_repository_path != repository.repository_path
                        or row.state not in {"running", "completed", "failed"}):
                    return
                if row.state == "completed":
                    actual = next(item for item in collect_children(request, folder)
                                  if item.child_repository_id == row.child_repository_id)
                    if actual.state != "completed" or actual.manifest_sha256 != row.manifest_sha256 or actual.manifest_path != row.manifest_path:
                        return
                started.add(repository.repository_id)
                emit(row)
            except (KeyError, ValueError, TypeError):
                return

    def complete(code: int, _tail: str = "") -> None:
        nonlocal completing
        with lock:
            if completing:
                return
            completing = True
        error = None
        children = collect_children(request, folder, cancelled=cancelled.is_set(), started=started)
        ready = False
        try:
            all_complete = all(row.state == "completed" for row in children)
            if code == 0 and all_complete and not cancelled.is_set():
                index_payload = json.loads((folder / "desktop-fleet.json").read_text(encoding="utf-8"))
                expected_index = _index_payload(request, folder, children)
                if index_payload != expected_index:
                    raise ValueError("Fleet index identity mismatch")
                validate_generation(folder)
                publish_generation(Path(request.output_path).absolute(), request.run_id, cancelled=cancelled.is_set)
                ready = True
            else:
                # The broker verifies and rewrites this diagnostic index itself.
                write_index(request, folder, children)
        except (OSError, ValueError):
            error = "Fleet publication failed; previous results were preserved."
        index = folder / "desktop-fleet.json"
        outcome = ("cancelled" if cancelled.is_set() else "succeeded" if ready else
                   "partial" if any(row.state == "completed" for row in children)
                   and any(row.state != "completed" for row in children) else "failed")
        state = "cancelled" if cancelled.is_set() else "completed" if ready else "failed"
        for row in children:
            emit(row)
        emit(FleetTerminal(**_identity(request), revision=0, state=state,
            execution_outcome="succeeded" if ready else "cancelled" if cancelled.is_set() else "failed",
            artifact_readiness="ready" if ready else "unavailable", fleet_outcome=outcome, children=children,
            index_path=str(index) if index.is_file() else None,
            index_sha256=hashlib.sha256(index.read_bytes()).hexdigest() if index.is_file() else None, error=error))
        finished.set()

    env = dict(os.environ)
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "OPENAI_BASE_URL",
                 "ANTHROPIC_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID"):
        env.pop(name, None)
    emit(RunProgress(**_identity(request), revision=0, state="queued"))
    for repository in request.repositories:
        emit(FleetChildEvent(**_identity(request), revision=0, child_repository_id=repository.repository_id,
            child_repository_path=repository.repository_path, child_run_id=child_run_id(request, repository),
            child_output_id=output_ids[repository.repository_id], state="queued"))
    if not supervisor.start(broker_argv(prepared), env=env, on_progress=progress, on_done=complete,
                            timeout=request.options.timeout_seconds):
        complete(1)
        return 1

    def controls() -> None:
        try:
            descriptor = control.fileno()
        except (AttributeError, OSError, ValueError):
            descriptor = None
        while not finished.is_set():
            # Read at most one byte from the real pipe to avoid buffered-stdin
            # shutdown locks. EOF and any cancel line own the entire branch.
            line = os.read(descriptor, 1) if descriptor is not None else control.readline(65)
            if not line or line.strip() in ("cancel", b"c"):
                with lock:
                    if completing:
                        return
                    cancelled.set()
                    emit(RunProgress(**_identity(request), revision=0, state="cancelling"))
                    supervisor.request_cancel()
                return
    threading.Thread(target=controls, daemon=True).start()
    finished.wait()
    return 0
