"""One walk, one read: a per-run file index for built-in scanners and taint."""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .safe_fs import max_file_bytes, walk_repo
from .models import ResourceLimitEvent
from .srcpaths import is_skipped_dir, line_number

_NOISY_SYMLINK_PARTS = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"}


@dataclass(frozen=True)
class IndexedFile:
    rel: str
    suffix: str
    text: str
    line_starts: tuple[int, ...]
    path: Path
    mtime_ns: int = 0
    size: int = 0

    def line_of(self, offset: int) -> int:
        return line_number(self.text, offset)


@dataclass(frozen=True)
class RepoIndex:
    root: Path
    files: tuple[IndexedFile, ...]
    limitations: tuple[str, ...]
    resource_limit_events: tuple[ResourceLimitEvent, ...] = ()
    resource_limit_scopes: tuple[str, ...] = ()
    resource_limit_reporting: str = "unknown"
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
        """Return diagnostics for files that changed since the index was built."""
        warnings: list[str] = []
        for item in self.files:
            try:
                stat = item.path.stat()
            except OSError as exc:
                warnings.append(
                    f"repository mutated during scan ({type(exc).__name__}): {item.rel}"
                )
                continue
            if stat.st_size != item.size or stat.st_mtime_ns != item.mtime_ns:
                warnings.append(f"repository mutated during scan: {item.rel}")
        return tuple(warnings)

    @classmethod
    def build(
        cls,
        root: str | Path,
        *,
        max_bytes: int | None = None,
    ) -> RepoIndex:
        root_path = Path(root).resolve()
        limitations: list[str] = []
        files: list[IndexedFile] = []
        resource_events: list[ResourceLimitEvent] = []
        env_budget = int(os.environ.get("ATTACKMAP_INDEX_BYTE_BUDGET", "0") or "0")
        budget = max_bytes if max_bytes is not None and max_bytes > 0 else env_budget
        used_bytes = 0
        budget_exceeded = False

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
            file_limit = max_file_bytes()
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
                )
            )
        return cls(root=root_path, files=tuple(files), limitations=tuple(limitations),
                   resource_limit_events=tuple(resource_events),
                   resource_limit_scopes=("repo_index.file_bytes", "repo_index.index_bytes"),
                   resource_limit_reporting="complete")
