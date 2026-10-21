"""Sealed captured inputs for cooperating isolated SDK clients, not an OS sandbox."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from threading import Lock
import zipfile

from .index import CapturedSource, IndexedFile, RepoIndex, ScanSnapshot, content_sha256
from .models import ResourceLimitEvent, ScanSnapshotIdentity

PROTOCOL = "attackmap-host-input/1.0"


class SnapshotInputError(ValueError):
    pass


def _json(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotInputError("Duplicate manifest field")
        result[key] = value
    return result


def _relative(rel: str, max_chars: int):
    if not isinstance(rel, str) or not rel or len(rel) > max_chars or "\0" in rel:
        raise SnapshotInputError("Invalid captured path")
    path = Path(rel)
    if path.is_absolute() or path.drive or ".." in path.parts or path.as_posix() != rel:
        raise SnapshotInputError("Captured path escapes or is not canonical")


@dataclass(frozen=True)
class SealedSnapshot:
    path: str
    root: str
    snapshot_id: str
    config_identity: str
    archive_sha256: str
    archive_bytes: int
    manifest_bytes: int
    file_count: int
    total_bytes: int
    file_bytes: int
    path_chars: int
    protocol: str = PROTOCOL

    def dumps(self) -> str:
        return _json(asdict(self)).decode("utf-8")

    @classmethod
    def loads(cls, value: str):
        try:
            descriptor = cls(**json.loads(value, object_pairs_hook=_unique))
            for field in ("archive_bytes", "manifest_bytes", "file_count", "total_bytes", "file_bytes", "path_chars"):
                if type(getattr(descriptor, field)) is not int or getattr(descriptor, field) < 0:
                    raise SnapshotInputError("Invalid descriptor budget")
            if descriptor.protocol != PROTOCOL:
                raise SnapshotInputError("Unsupported snapshot input protocol")
            if not Path(descriptor.path).is_absolute() or not Path(descriptor.root).is_absolute():
                raise SnapshotInputError("Snapshot descriptor paths must be absolute")
            for value in (descriptor.archive_sha256, descriptor.snapshot_id, descriptor.config_identity):
                if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                    raise SnapshotInputError("Invalid descriptor identity")
            return descriptor
        except (ValueError, TypeError, KeyError) as exc:
            raise SnapshotInputError(str(exc)) from exc


def write_snapshot(index: RepoIndex, path: Path) -> SealedSnapshot:
    if index.snapshot is None:
        raise SnapshotInputError("Captured index has no snapshot identity")
    rows, seen, total, largest = [], set(), 0, 0
    # Metadata references original capture; raw payloads are never copied into a
    # parent-side aggregate or base64 string. Core-only UTF8 encoding is per-file.
    with path.open("xb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            def record(rel, raw, basis, mtime):
                nonlocal total, largest
                _relative(rel, max(1, len(rel)))
                if rel in seen:
                    raise SnapshotInputError("Duplicate captured source")
                seen.add(rel)
                ordinal = len(rows)
                rows.append([rel, basis, len(raw), hashlib.sha256(raw).hexdigest(), mtime])
                total += len(raw)
                largest = max(largest, len(raw))
                with archive.open(f"payloads/{ordinal:08d}.bin", "w", force_zip64=True) as payload:
                    payload.write(raw)
            for source in index.sources:
                record(source.rel, source.raw, "raw", source.mtime_ns)
            for item in index.files:
                if item.rel not in seen:
                    record(item.rel, item.text.encode("utf-8"), "core-text", item.mtime_ns)
            manifest = _json({"protocol": PROTOCOL, "root": str(index.root),
                "snapshot": index.snapshot.identity().model_dump(mode="json"), "records": rows,
                "sdk_count": len(index.sources),
                "core": [[f.rel, f.suffix, f.size, f.mtime_ns, f.sha256, bool(f.line_starts)] for f in index.files],
                "limitations": list(index.limitations),
                "resource_limit_events": [event.model_dump(mode="json") for event in index.resource_limit_events],
                "resource_limit_scopes": list(index.resource_limit_scopes),
                "resource_limit_reporting": index.resource_limit_reporting})
            archive.writestr("manifest.json", manifest)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        size = stream.tell()
    return SealedSnapshot(str(path.resolve()), str(index.root), index.snapshot.snapshot_id,
        index.snapshot.config_identity, digest, size, len(manifest), len(rows), total, largest,
        max((len(row[0]) for row in rows), default=0))


def _read_member(archive, info, limit):
    if info.file_size > limit:
        raise SnapshotInputError("Snapshot member exceeds declared budget")
    with archive.open(info) as stream:
        raw = stream.read(limit + 1)
        if len(raw) != info.file_size or len(raw) > limit or stream.read(1):
            raise SnapshotInputError("Snapshot member size mismatch")
        return raw


def read_snapshot(descriptor: SealedSnapshot) -> RepoIndex:
    try:
        # Check descriptors built directly by callers as well as decoded argv.
        descriptor = SealedSnapshot.loads(descriptor.dumps())
        with Path(descriptor.path).open("rb") as stream:
            stream.seek(0, 2)
            if stream.tell() != descriptor.archive_bytes:
                raise SnapshotInputError("Snapshot archive size mismatch")
            stream.seek(0)
            if hashlib.file_digest(stream, "sha256").hexdigest() != descriptor.archive_sha256:
                raise SnapshotInputError("Snapshot archive seal mismatch")
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive:
                entries = archive.infolist()
                names = [entry.filename for entry in entries]
                if len(entries) != descriptor.file_count + 1 or len(set(names)) != len(names):
                    raise SnapshotInputError("Snapshot member count or duplicate mismatch")
                if any(info.compress_type != zipfile.ZIP_STORED or info.flag_bits & 1 for info in entries):
                    raise SnapshotInputError("Compressed/encrypted snapshots unsupported")
                expected_names = {"manifest.json"} | {f"payloads/{i:08d}.bin" for i in range(descriptor.file_count)}
                if set(names) != expected_names:
                    raise SnapshotInputError("Unknown/missing snapshot member")
                info = archive.getinfo("manifest.json")
                if info.file_size != descriptor.manifest_bytes:
                    raise SnapshotInputError("Snapshot manifest budget mismatch")
                manifest = json.loads(_read_member(archive, info, descriptor.manifest_bytes), object_pairs_hook=_unique)
                if set(manifest) != {"protocol", "root", "snapshot", "records", "sdk_count", "core", "limitations",
                                     "resource_limit_events", "resource_limit_scopes", "resource_limit_reporting"}:
                    raise SnapshotInputError("Unknown/missing snapshot manifest fields")
                if manifest["protocol"] != PROTOCOL or manifest["root"] != descriptor.root:
                    raise SnapshotInputError("Snapshot protocol/root mismatch")
                if (not isinstance(manifest["core"], list) or len(manifest["core"]) > descriptor.file_count
                        or manifest["resource_limit_reporting"] not in {"unknown", "partial", "complete"}
                        or any(not isinstance(manifest[key], list) or any(not isinstance(value, str) for value in manifest[key])
                               for key in ("limitations", "resource_limit_scopes"))):
                    raise SnapshotInputError("Invalid snapshot view/resource metadata")
                expected = ScanSnapshotIdentity.model_validate(manifest["snapshot"])
                if expected.snapshot_id != descriptor.snapshot_id or expected.config_identity != descriptor.config_identity:
                    raise SnapshotInputError("Snapshot/config identity mismatch")
                rows = manifest["records"]
                sdk_count = manifest["sdk_count"]
                if not isinstance(rows, list) or len(rows) != descriptor.file_count or type(sdk_count) is not int or not 0 <= sdk_count <= len(rows):
                    raise SnapshotInputError("Invalid snapshot record counts")
                captured, sources, total = {}, [], 0
                for ordinal, row in enumerate(rows):
                    rel, basis, size, sha, mtime = row
                    _relative(rel, descriptor.path_chars)
                    if rel in captured or type(size) is not int or not 0 <= size <= descriptor.file_bytes or type(mtime) is not int:
                        raise SnapshotInputError("Invalid snapshot source metadata")
                    total += size
                    if total > descriptor.total_bytes:
                        raise SnapshotInputError("Snapshot aggregate budget exceeded")
                    if basis not in {"raw", "core-text"} or (ordinal < sdk_count) != (basis == "raw"):
                        raise SnapshotInputError("Snapshot SDK acceptance mismatch")
                    raw = _read_member(archive, archive.getinfo(f"payloads/{ordinal:08d}.bin"), size)
                    if hashlib.sha256(raw).hexdigest() != sha:
                        raise SnapshotInputError("Captured source hash mismatch")
                    captured[rel] = (raw, basis)
                    if basis == "raw":
                        sources.append(CapturedSource(rel, raw, mtime))
                if total != descriptor.total_bytes:
                    raise SnapshotInputError("Snapshot aggregate byte mismatch")
                files, seen = [], set()
                root = Path(descriptor.root)
                for rel, suffix, size, mtime, sha, has_lines in manifest["core"]:
                    if rel in seen or rel not in captured or not isinstance(suffix, str) or type(size) is not int or size < 0 or type(mtime) is not int or type(has_lines) is not bool:
                        raise SnapshotInputError("Invalid core view metadata")
                    seen.add(rel)
                    raw, basis = captured[rel]
                    text = raw.decode("utf-8")
                    if basis == "raw":
                        text = text.replace("\r\n", "\n").replace("\r", "\n")
                    if content_sha256(text) != sha:
                        raise SnapshotInputError("Core text identity mismatch")
                    lines = (0, *(i + 1 for i, ch in enumerate(text) if ch == "\n")) if has_lines else ()
                    files.append(IndexedFile(rel, suffix, text, lines, root / rel, mtime, size, sha))
                if any(basis == "core-text" and rel not in seen for rel, (_raw, basis) in captured.items()):
                    raise SnapshotInputError("Unreferenced core-only capture")
                snapshot = ScanSnapshot.from_indexed(files, dict(expected.index_config), sources)
                if snapshot.identity() != expected:
                    raise SnapshotInputError("Reconstructed snapshot differs from sealed identity")
                return RepoIndex(root, tuple(files), tuple(manifest["limitations"]),
                    tuple(ResourceLimitEvent.model_validate(row) for row in manifest["resource_limit_events"]),
                    tuple(manifest["resource_limit_scopes"]), manifest["resource_limit_reporting"], snapshot, tuple(sources))
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile) as exc:
        if isinstance(exc, SnapshotInputError):
            raise
        raise SnapshotInputError(f"Invalid snapshot input: {exc}") from exc


class SnapshotBundle:
    """One archive shared by siblings; close is deferred until verified readers exit."""
    def __init__(self, index: RepoIndex):
        self._directory = Path(tempfile.mkdtemp(prefix="attackmap-snapshot-"))
        self._lock, self._readers, self._closing = Lock(), 0, False
        try:
            self.descriptor = write_snapshot(index, self._directory / "snapshot.zip")
            self.identity = index.snapshot.identity()
        except BaseException:
            shutil.rmtree(self._directory, ignore_errors=True)
            raise

    def acquire(self):
        with self._lock:
            if self._closing:
                raise SnapshotInputError("Snapshot bundle already closing")
            self._readers += 1
        return SnapshotLease(self)

    def close(self):
        with self._lock:
            self._closing = True
            if not self._readers:
                shutil.rmtree(self._directory, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class SnapshotLease:
    def __init__(self, bundle):
        self.bundle, self._released = bundle, False

    def release(self):
        with self.bundle._lock:
            if self._released:
                return
            self._released = True
            self.bundle._readers -= 1
            if self.bundle._closing and not self.bundle._readers:
                shutil.rmtree(self.bundle._directory, ignore_errors=True)
