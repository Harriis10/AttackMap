"""One walk, one read: a per-run file index for built-in scanners and taint."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path

from .safe_fs import contained_file, is_oversized, max_file_bytes, walk_repo
from .models import ResourceLimitEvent, ScanSnapshotIdentity
from .srcpaths import is_skipped_dir, line_number

_NOISY_SYMLINK_PARTS = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"}

# Default accepted-file-count ceiling (C35 engineering target). Same
# acceptance semantics as the byte budget: overflowing files are skipped,
# the scope becomes partial — never a silent drop. ``ATTACKMAP_INDEX_FILE_LIMIT``
# overrides the default; 0 disables the count cap.
DEFAULT_INDEX_FILE_LIMIT = 100_000
_INDEX_FILE_LIMIT_ENV = "ATTACKMAP_INDEX_FILE_LIMIT"

# Content basis for snapshot identity: the indexed text, i.e. the utf-8-decoded
# file as the passes saw it (C33/AM047). Verification re-reads with the same
# basis, so a drift verdict never depends on newline or encoding normalization.
_SNAPSHOT_SCHEMA = "attackmap-snapshot/1.0"

# C33/AM047: the index this thread's whole-repo passes resolve content through.
# ``RepoIndex.build`` pins itself so passes invoked later for the same root
# (SBOM, supply-chain, workflows, authz, anomalies, fingerprints) read the
# captured revision even where their call sites thread no index explicitly.
# Lookups are root-gated and per-thread; a newer build for the same root wins.
_PINNED: "ContextVar[RepoIndex | None]" = ContextVar("attackmap_pinned_index", default=None)


def pinned_repo_index() -> "RepoIndex | None":
    """The index pinned for this thread by the latest :meth:`RepoIndex.build`."""
    return _PINNED.get()


def active_index_for(root: str | Path) -> "RepoIndex | None":
    """The pinned index for exactly ``root`` (another repo's pin never applies)."""
    index = _PINNED.get()
    if index is None:
        return None
    try:
        return index if index.root == Path(root).resolve() else None
    except OSError:
        return None


def clear_pinned_index() -> None:
    """Drop this thread's pin (the pipeline resets it once a run completes)."""
    _PINNED.set(None)


def content_sha256(text: str) -> str:
    """sha256 of a file's content on the index basis (decoded utf-8 text)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IndexedFile:
    rel: str
    suffix: str
    text: str
    line_starts: tuple[int, ...]
    path: Path
    mtime_ns: int = 0
    size: int = 0
    sha256: str = ""

    def line_of(self, offset: int) -> int:
        return line_number(self.text, offset)


@dataclass(frozen=True)
class SnapshotVerification:
    """Publication-time re-check of the working tree against one snapshot.

    ``state`` is ``"verified"`` (no drift), ``"drifted"`` (the run analyzed a
    mixture of revisions) or ``"unverified"`` (the check itself could not run).
    """

    state: str
    checked_files: int = 0
    changed: tuple[str, ...] = ()
    deleted: tuple[str, ...] = ()
    added: tuple[str, ...] = ()
    note: str | None = None

    @property
    def drifted(self) -> bool:
        return self.state == "drifted"

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "checked_files": self.checked_files,
            "changed": list(self.changed),
            "deleted": list(self.deleted),
            "added": list(self.added),
            **({"note": self.note} if self.note else {}),
        }

    def limitation(self) -> str | None:
        """Limitations-mechanism string for a drifted snapshot, else None."""
        if not self.drifted:
            return None
        parts = []
        if self.changed:
            parts.append("changed since index: " + ", ".join(self.changed))
        if self.deleted:
            parts.append("deleted since index: " + ", ".join(self.deleted))
        if self.added:
            parts.append("new since index: " + ", ".join(self.added))
        return (
            "incomplete snapshot: repository mutated during scan ("
            + "; ".join(parts)
            + "). Evidence may mix file revisions; re-run for a consistent report."
        )


@dataclass(frozen=True)
class ScanSnapshot:
    """Content identity of every accepted file at index time (C33/AM047).

    One run's deterministic passes read the indexed text, so its evidence is
    tied to this snapshot. ``snapshot_id`` hashes the sorted ``(rel, sha256)``
    set: any accepted-file content change, addition or deletion changes it.
    """

    snapshot_id: str
    files: tuple[tuple[str, str], ...]
    total_size: int
    index_config: tuple[tuple[str, int], ...]

    @staticmethod
    def _id_for(files: tuple[tuple[str, str], ...]) -> str:
        payload = json.dumps([_SNAPSHOT_SCHEMA, list(files)],
                             ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def from_indexed(cls, files: list[IndexedFile], index_config: dict[str, int]) -> "ScanSnapshot":
        entries = tuple(sorted((f.rel, f.sha256) for f in files))
        return cls(cls._id_for(entries), entries, sum(f.size for f in files),
                   tuple(sorted(index_config.items())))

    @classmethod
    def from_identity(cls, data: dict) -> "ScanSnapshot":
        """Rehydrate from a serialized :class:`models.ScanSnapshotIdentity`."""
        raw_files = data.get("files")
        entries = tuple(sorted((str(rel), str(sha))
                               for rel, sha in (raw_files or {}).items()))
        raw_config = data.get("index_config")
        config = tuple(sorted((str(name), int(value))
                              for name, value in (raw_config or {}).items()))
        return cls(cls._id_for(entries), entries, int(data.get("total_size") or 0), config)

    @property
    def config_identity(self) -> str:
        payload = json.dumps([_SNAPSHOT_SCHEMA, "config", list(self.index_config)],
                             ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def identity(self) -> ScanSnapshotIdentity:
        """The additive model form carried on ``ScanResult.scan_snapshot``."""
        return ScanSnapshotIdentity(
            snapshot_id=self.snapshot_id,
            files=dict(self.files),
            total_size=self.total_size,
            index_config=dict(self.index_config),
            config_identity=self.config_identity,
        )

    def verify(self, root: str | Path, *, exclude: tuple[str | Path, ...] = ()) -> SnapshotVerification:
        """Re-read the working tree and compare it against this snapshot.

        Every snapshot file is re-hashed on the index basis (full content, no
        mtime shortcut — stat timestamps only gate the cheaper mid-scan
        ``RepoIndex.mutation_warnings``), and the tree is re-walked to find
        files that appeared after the index was built. New-file detection
        replays the acceptance limits recorded in ``index_config`` (per-file
        cap, aggregate byte budget, file-count cap) in the build's walk order,
        so a new file the policy would have skipped is not drift: the analyzed
        snapshot is complete without it. Paths under *exclude* (the run's own
        output directory) are not drift.
        """
        root_path = Path(root)
        excluded: list[Path] = []
        for item in exclude:
            try:
                excluded.append(Path(item).resolve())
            except OSError:
                continue
        known = dict(self.files)
        changed: list[str] = []
        deleted: list[str] = []
        added: list[str] = []
        checked = 0
        for rel, expected in self.files:
            path = root_path / rel
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                changed.append(rel)
                continue
            except OSError:
                # A snapshot file that vanished is deleted; one that stat-fails
                # or denies reading is drift of the changed kind either way.
                (deleted if not path.exists() else changed).append(rel)
                continue
            checked += 1
            if content_sha256(text) != expected:
                changed.append(rel)
        # Charge each snapshot file its (live) size — the build's charge is not
        # recoverable from the hashes; a file whose size also changed is
        # already reported under ``changed``.
        known_sizes: dict[str, int] = {}
        for rel in known:
            try:
                known_sizes[rel] = (root_path / rel).stat().st_size
            except OSError:
                continue  # gone: reported above, occupies no budget now
        added = list(
            _replay_added_files(root_path, known_sizes, dict(self.index_config), exclude=excluded)
        )
        state = "drifted" if (changed or deleted or added) else "verified"
        return SnapshotVerification(state, checked, tuple(sorted(changed)),
                                    tuple(sorted(deleted)), tuple(sorted(added)))


def _is_under(path: Path, base: Path) -> bool:
    try:
        return path.resolve().is_relative_to(base)
    except (OSError, RuntimeError):
        return False


def _replay_added_files(
    root: Path,
    known_sizes: dict[str, int],
    config: dict[str, int],
    *,
    exclude: tuple[Path, ...] = (),
) -> tuple[str, ...]:
    """New files the index acceptance policy would have captured (C33/AM047).

    Replays :meth:`RepoIndex.build`'s gates — per-file byte cap, aggregate byte
    budget, accepted-file count cap, utf-8 decode — in the build's walk order.
    Snapshot files (``known_sizes``) are charged their size and count first,
    exactly as the build accepted them, so a candidate the budget or count cap
    would have skipped is not reported: that file was never part of any
    analyzable snapshot under these limits.
    """
    file_limit = int(config.get("max_file_bytes") or 0) or max_file_bytes()
    budget = int(config.get("index_byte_budget") or 0)
    count_limit = int(config.get("index_file_limit") or 0)
    used = 0
    accepted = 0
    added: list[str] = []
    for path in walk_repo(root, prune=is_skipped_dir):
        try:
            rel = path.relative_to(root).as_posix()
            size = path.stat().st_size
        except (ValueError, OSError):
            continue
        if any(_is_under(path, base) for base in exclude):
            continue
        if rel in known_sizes:
            used += known_sizes[rel]
            accepted += 1
            continue
        # The build's gate order: per-file cap, budget charge, count cap, decode.
        if size > file_limit:
            continue
        if budget > 0:
            if used + size > budget:
                continue
            used += size
        if count_limit > 0 and accepted >= count_limit:
            continue
        try:
            path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        added.append(rel)
        accepted += 1
    return tuple(sorted(added))


@dataclass(frozen=True)
class RepoIndex:
    root: Path
    files: tuple[IndexedFile, ...]
    limitations: tuple[str, ...]
    resource_limit_events: tuple[ResourceLimitEvent, ...] = ()
    resource_limit_scopes: tuple[str, ...] = ()
    resource_limit_reporting: str = "unknown"
    snapshot: ScanSnapshot | None = None
    _by_rel: dict[str, IndexedFile] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_by_rel", {f.rel: f for f in self.files})

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    def with_suffixes(self, suffixes: set[str] | None) -> Iterator[IndexedFile]:
        if suffixes is None:
            yield from self.files
            return
        wanted = {s.lower() for s in suffixes}
        for item in self.files:
            if item.suffix.lower() in wanted:
                yield item

    def get(self, rel: str) -> IndexedFile | None:
        return self._by_rel.get(rel.replace("\\", "/"))

    def as_path_map(self, suffixes: set[str] | None = None) -> dict[str, Path]:
        return {item.rel: item.path for item in self.with_suffixes(suffixes)}

    def text_of(self, rel: str) -> str | None:
        item = self.get(rel)
        return None if item is None else item.text

    def mutation_warnings(self) -> tuple[str, ...]:
        """Return diagnostics for files that changed since the index was built.

        Cheap stat gate first (this runs mid-scan); any stat drift is confirmed
        against the snapshot's content hash, so a touch or in-place rewrite of
        identical text is not reported. New accepted files are detected too —
        they were never part of the analyzed snapshot (C33/AM047) — replaying
        the build's acceptance limits, so a file the byte budget or count cap
        would have skipped is not a mutation warning.
        """
        warnings: list[str] = []
        for item in self.files:
            try:
                stat = item.path.stat()
            except OSError as exc:
                warnings.append(
                    f"repository mutated during scan ({type(exc).__name__}): {item.rel}"
                )
                continue
            if stat.st_size == item.size and stat.st_mtime_ns == item.mtime_ns:
                continue
            try:
                current = content_sha256(item.path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError):
                current = None
            if current != item.sha256:
                warnings.append(f"repository mutated during scan: {item.rel}")
        warnings.extend(
            f"repository mutated during scan: new file: {rel}" for rel in self._new_files()
        )
        return tuple(warnings)

    def _new_files(self) -> tuple[str, ...]:
        """Accepted files present now that the index never captured, judged
        under the acceptance limits recorded at build time (budget-faithful:
        a file the byte budget or count cap would have skipped is not new
        drift — no snapshot under those limits could have contained it)."""
        config = dict(self.snapshot.index_config) if self.snapshot is not None else {}
        return _replay_added_files(self.root, {f.rel: f.size for f in self.files}, config)

    @classmethod
    def build(
        cls,
        root: str | Path,
        *,
        max_bytes: int | None = None,
        max_files: int | None = None,
    ) -> RepoIndex:
        root_path = Path(root).resolve()
        limitations: list[str] = []
        files: list[IndexedFile] = []
        resource_events: list[ResourceLimitEvent] = []
        env_budget = int(os.environ.get("ATTACKMAP_INDEX_BYTE_BUDGET", "0") or "0")
        budget = max_bytes if max_bytes is not None and max_bytes > 0 else env_budget
        # Captured once so the snapshot's config identity describes the limits
        # that actually decided which files were accepted.
        file_limit = max_file_bytes()
        try:
            env_file_limit = int(os.environ.get(_INDEX_FILE_LIMIT_ENV, "") or DEFAULT_INDEX_FILE_LIMIT)
        except ValueError:
            env_file_limit = DEFAULT_INDEX_FILE_LIMIT
        if max_files is not None:
            file_count_limit = max_files  # 0 explicitly disables the cap
        else:
            file_count_limit = env_file_limit if env_file_limit > 0 else 0
        used_bytes = 0
        budget_exceeded = False
        count_exceeded = False
        skipped_over_count = 0

        def _record_symlink(path: Path) -> None:
            rel = path.relative_to(root_path)
            if not any(part in _NOISY_SYMLINK_PARTS for part in rel.parts):
                limitations.append(f"symlink not followed: {rel.as_posix()}")

        for path in walk_repo(root_path, prune=is_skipped_dir, on_symlink=_record_symlink):
            try:
                stat = path.stat()
            except OSError as exc:
                limitations.append(
                    f"unreadable file skipped ({type(exc).__name__}): "
                    f"{path.relative_to(root_path).as_posix()}"
                )
                continue

            size = stat.st_size
            if size > file_limit:
                resource_events.append(ResourceLimitEvent.skipped_file(
                    producer="repo_index", category="file_bytes", relative=path.relative_to(root_path).as_posix(),
                    limit=file_limit, observed_bytes=size))
                limitations.append(
                    f"oversized file skipped (> {file_limit} bytes): "
                    f"{path.relative_to(root_path).as_posix()}"
                )
                continue

            if budget > 0:
                if used_bytes + size > budget:
                    resource_events.append(ResourceLimitEvent.skipped_file(
                        producer="repo_index", category="index_bytes", relative=path.relative_to(root_path).as_posix(),
                        limit=budget, observed_bytes=used_bytes + size))
                    if not budget_exceeded:
                        limitations.append(
                            f"aggregate byte budget exceeded ({budget} bytes); "
                            "files exceeding the remaining budget skipped"
                        )
                        budget_exceeded = True
                    continue
                used_bytes += size

            # Accepted-count cap (C35): same semantics as the byte budget —
            # files beyond the cap are skipped with one aggregate limitation
            # line (never itemized) and one structured event emitted after
            # the walk knows the skipped total.
            if file_count_limit > 0 and len(files) >= file_count_limit:
                if not count_exceeded:
                    limitations.append(
                        f"file count limit exceeded ({file_count_limit} files); "
                        "remaining files skipped"
                    )
                    count_exceeded = True
                skipped_over_count += 1
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            except OSError as exc:
                limitations.append(
                    f"unreadable file skipped ({type(exc).__name__}): "
                    f"{path.relative_to(root_path).as_posix()}"
                )
                continue
            rel = path.relative_to(root_path).as_posix()
            files.append(
                IndexedFile(
                    rel=rel,
                    suffix=path.suffix,
                    text=text,
                    line_starts=(),
                    path=path,
                    mtime_ns=stat.st_mtime_ns,
                    size=size,
                    sha256=content_sha256(text),
                )
            )
        snapshot = ScanSnapshot.from_indexed(
            files,
            {
                "max_file_bytes": file_limit,
                "index_byte_budget": budget,
                "index_file_limit": file_count_limit,
            },
        )
        scopes = ["repo_index.file_bytes", "repo_index.index_bytes"]
        if count_exceeded:
            identity = ["resource-limit/1.0", "repo_index", "index_files",
                        "aggregate", file_count_limit, None]
            event_id = hashlib.sha256(
                json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()
            ).hexdigest()
            resource_events.append(ResourceLimitEvent(
                event_id=event_id,
                category="index_files",
                producer="repo_index",
                limit=file_count_limit,
                unit="files",
                action="skipped_remaining_files",
                observed_files=skipped_over_count or None,
            ))
            scopes.append("repo_index.index_files")
        repo_index = cls(root=root_path, files=tuple(files), limitations=tuple(limitations),
                         resource_limit_events=tuple(resource_events),
                         resource_limit_scopes=tuple(scopes),
                         resource_limit_reporting="complete",
                         snapshot=snapshot)
        # C33/AM047: this thread's whole-repo passes resolve content for this
        # root through the freshest captured snapshot (lookups are root-gated).
        _PINNED.set(repo_index)
        return repo_index


@dataclass(frozen=True)
class PassSources:
    """Snapshot-pinned content view for one whole-repo pass (C33/AM047).

    A pass keeps its own file enumeration — its depth caps and skip sets are
    part of its output contract — but resolves *content* through the captured
    index, so a mid-run edit cannot change the pass's input. A file the index
    never captured reads as missing (``None``): it is outside the analyzed
    snapshot (added mid-run, or rejected by the index acceptance policy), so
    the pass skips it exactly as it skips an unreadable file today. With no
    index pinned every call falls back to the live read it always did.
    """

    root: Path
    index: "RepoIndex | None"

    @classmethod
    def for_root(cls, root: str | Path, index: "RepoIndex | None" = None) -> "PassSources":
        """Explicit index when it matches ``root``, else the ambient pin for it."""
        root_path = Path(root).resolve()
        resolved = index if index is not None and Path(index.root) == root_path else None
        if resolved is None:
            resolved = active_index_for(root_path)
        return cls(root=root_path, index=resolved)

    @property
    def pinned(self) -> bool:
        return self.index is not None

    def text(self, path: Path, *, errors: str = "strict") -> str | None:
        """Text for an enumerated absolute path: captured when the file is in
        the snapshot, else the live read (``None`` on OSError / not captured)."""
        if self.index is None:
            try:
                return path.read_text(encoding="utf-8", errors=errors)
            except OSError:
                return None
        try:
            rel = path.relative_to(self.root).as_posix()
        except ValueError:
            return None
        item = self.index.get(rel)
        return None if item is None else item.text

    def gated_text(self, rel: str, *, max_bytes: int, errors: str = "ignore") -> str | None:
        """Size-gated text for a repo-relative path. The size gate uses the
        *captured* size when pinned (IndexedFile.size) and the live stat
        otherwise — metadata stays faithful to whichever basis supplies the
        content."""
        if self.index is not None:
            item = self.index.get(rel)
            if item is None or item.size > max_bytes:
                return None
            return item.text
        path = contained_file(self.root, rel)
        if path is None:
            return None
        try:
            if path.stat().st_size > max_bytes:
                return None
            return path.read_text(encoding="utf-8", errors=errors)
        except OSError:
            return None

    def exists(self, rel: str) -> bool:
        """Existence on the pass's input basis. A captured file exists; for a
        file outside the snapshot this stays a *live* existence check —
        lockfile-presence questions are structural metadata, not content."""
        if self.index is not None and self.index.get(rel) is not None:
            return True
        try:
            return (self.root / rel).is_file()
        except OSError:
            return False

    def oversized(self, path: Path) -> bool:
        """Per-file byte-cap gate: the captured size when the file is part of
        the snapshot, the live size otherwise."""
        if self.index is not None:
            try:
                item = self.index.get(path.relative_to(self.root).as_posix())
            except ValueError:
                return True
            if item is not None:
                return item.size > max_file_bytes()
        return is_oversized(path)
