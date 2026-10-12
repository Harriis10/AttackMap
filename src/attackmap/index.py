"""One walk, one read: a per-run file index for built-in scanners and taint."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .safe_fs import is_oversized, max_file_bytes, walk_repo
from .srcpaths import is_skipped_dir, line_number

_NOISY_SYMLINK_PARTS = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"}


@dataclass(frozen=True)
class IndexedFile:
    rel: str
    suffix: str
    text: str
    line_starts: tuple[int, ...]
    path: Path

    def line_of(self, offset: int) -> int:
        return line_number(self.text, offset)


@dataclass(frozen=True)
class RepoIndex:
    root: Path
    files: tuple[IndexedFile, ...]
    limitations: tuple[str, ...]

    def with_suffixes(self, suffixes: set[str] | None) -> Iterator[IndexedFile]:
        if suffixes is None:
            yield from self.files
            return
        wanted = {s.lower() for s in suffixes}
        for item in self.files:
            if item.suffix.lower() in wanted:
                yield item

    def get(self, rel: str) -> IndexedFile | None:
        key = rel.replace("\\", "/")
        for item in self.files:
            if item.rel == key:
                return item
        return None

    def as_path_map(self, suffixes: set[str] | None = None) -> dict[str, Path]:
        return {item.rel: item.path for item in self.with_suffixes(suffixes)}

    def text_of(self, rel: str) -> str | None:
        item = self.get(rel)
        return None if item is None else item.text

    @classmethod
    def build(cls, root: str | Path) -> RepoIndex:
        root_path = Path(root).resolve()
        limitations: list[str] = []
        files: list[IndexedFile] = []

        def _record_symlink(path: Path) -> None:
            rel = path.relative_to(root_path)
            if not any(part in _NOISY_SYMLINK_PARTS for part in rel.parts):
                limitations.append(f"symlink not followed: {rel.as_posix()}")

        for path in walk_repo(root_path, prune=is_skipped_dir, on_symlink=_record_symlink):
            if is_oversized(path):
                limitations.append(
                    f"oversized file skipped (> {max_file_bytes()} bytes): "
                    f"{path.relative_to(root_path).as_posix()}"
                )
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
                )
            )
        return cls(root=root_path, files=tuple(files), limitations=tuple(limitations))
