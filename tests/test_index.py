"""RepoIndex: one walk, one read, shared by built-in scanners."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.index import IndexedFile, RepoIndex
from attackmap.scanner import scan_files


def test_index_walks_and_reads_once(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("const x = 1\n", encoding="utf-8")
    (tmp_path / "cfg.yaml").write_text("db: postgres://h/db\n", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    rels = {f.rel for f in index.files}
    assert "a.py" in rels
    assert "b.js" in rels
    assert "cfg.yaml" in rels
    py = index.get("a.py")
    assert py is not None
    assert py.text == "x = 1\n"
    assert py.suffix == ".py"
    assert list(index.with_suffixes({".py"}))[0].rel == "a.py"


def test_scan_files_uses_index_without_rewalking(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n@app.route('/x')\ndef x():\n    return 1\n",
        encoding="utf-8",
    )
    index = RepoIndex.build(tmp_path)
    walks = {"n": 0}

    def boom(*args, **kwargs):  # noqa: ANN001
        walks["n"] += 1
        raise AssertionError("scan_files should not walk when an index is provided")

    monkeypatch.setattr("attackmap.scanner.walk_repo", boom)
    result = scan_files(tmp_path, suffixes={".py"}, index=index)
    assert walks["n"] == 0
    assert any(r.path == "/x" for r in result.routes)


def test_get_uses_path_map_for_constant_lookup(tmp_path: Path) -> None:
    for i in range(200):
        (tmp_path / f"f{i}.py").write_text(f"x = {i}\n", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    # get() works and is backed by the internal dict
    assert index.get("f50.py") is not None
    assert index.get("f50.py").text == "x = 50\n"  # type: ignore[union-attr]
    assert index.get("missing.py") is None


def test_total_bytes_is_sum_of_file_sizes(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("12345", encoding="utf-8")
    (tmp_path / "b.py").write_text("abc", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    assert index.total_bytes == 5 + 3


def test_byte_budget_skips_remaining_files(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("12345", encoding="utf-8")
    (tmp_path / "b.py").write_text("67890", encoding="utf-8")
    (tmp_path / "c.py").write_text("xxx", encoding="utf-8")
    index = RepoIndex.build(tmp_path, max_bytes=7)
    rels = {f.rel for f in index.files}
    assert len(rels) == 1
    assert "a.py" in rels
    assert any("byte budget exceeded" in note for note in index.limitations)


def test_byte_budget_zero_means_unlimited(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x", encoding="utf-8")
    (tmp_path / "b.py").write_text("y", encoding="utf-8")
    index = RepoIndex.build(tmp_path, max_bytes=0)
    assert len(index.files) == 2


def test_default_byte_budget_can_be_set_by_environment(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "a.py").write_text("12345", encoding="utf-8")
    (tmp_path / "b.py").write_text("67890", encoding="utf-8")
    monkeypatch.setenv("ATTACKMAP_INDEX_BYTE_BUDGET", "5")
    index = RepoIndex.build(tmp_path)
    rels = {f.rel for f in index.files}
    assert len(rels) == 1


def test_mutation_warnings_detect_size_change(tmp_path: Path) -> None:
    path = tmp_path / "a.py"
    path.write_text("x = 1\n", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    assert index.mutation_warnings() == ()
    path.write_text("x = 1\ny = 2\n", encoding="utf-8")
    warnings = index.mutation_warnings()
    assert len(warnings) == 1
    assert "mutated" in warnings[0]


def test_mutation_warnings_detect_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "a.py"
    path.write_text("x = 1\n", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    path.unlink()
    warnings = index.mutation_warnings()
    assert len(warnings) == 1
    assert "mutated" in warnings[0]


def test_indexed_file_stores_mtime_and_size(tmp_path: Path) -> None:
    path = tmp_path / "a.py"
    path.write_text("hello", encoding="utf-8")
    stat = path.stat()
    index = RepoIndex.build(tmp_path)
    item = index.get("a.py")
    assert item is not None
    assert item.size == stat.st_size
    assert item.mtime_ns == stat.st_mtime_ns


def test_indexed_file_defaults_for_optional_fields() -> None:
    f = IndexedFile(rel="a.py", suffix=".py", text="x", line_starts=(), path=Path("a.py"))
    assert f.mtime_ns == 0
    assert f.size == 0
    assert f.sha256 == ""


def test_index_builds_content_identified_snapshot(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("const x = 1\n", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    assert index.snapshot is not None
    import hashlib
    assert index.snapshot.files == (
        ("a.py", hashlib.sha256(b"x = 1\n").hexdigest()),
        ("b.js", hashlib.sha256(b"const x = 1\n").hexdigest()),
    )
    assert index.snapshot.snapshot_id
    # The identity round-trips through the serialized model form.
    identity = index.snapshot.identity()
    assert identity.snapshot_id == index.snapshot.snapshot_id
    assert identity.files == dict(index.snapshot.files)
    assert identity.config_identity == index.snapshot.config_identity


def test_snapshot_identity_changes_on_content_add_delete(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    first = RepoIndex.build(tmp_path).snapshot

    (tmp_path / "a.py").write_text("x = 2\n", encoding="utf-8")  # changed
    changed = RepoIndex.build(tmp_path).snapshot
    assert changed.snapshot_id != first.snapshot_id

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "new.ts").write_text("const y = 2\n", encoding="utf-8")  # added
    grown = RepoIndex.build(tmp_path).snapshot
    assert grown.snapshot_id != first.snapshot_id
    assert grown.snapshot_id != changed.snapshot_id

    (tmp_path / "new.ts").unlink()  # deleted -> back to the original identity
    restored = RepoIndex.build(tmp_path).snapshot
    assert restored.snapshot_id == first.snapshot_id


def test_snapshot_verify_detects_changed_deleted_added(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    snapshot = index.snapshot

    assert snapshot.verify(tmp_path).state == "verified"

    (tmp_path / "a.py").write_text("x = 1\nz = 3\n", encoding="utf-8")
    (tmp_path / "b.py").unlink()
    (tmp_path / "c.js").write_text("const c\n", encoding="utf-8")
    verification = snapshot.verify(tmp_path)
    assert verification.state == "drifted"
    assert verification.changed == ("a.py",)
    assert verification.deleted == ("b.py",)
    assert verification.added == ("c.js",)
    limitation = verification.limitation()
    assert limitation is not None
    assert "a.py" in limitation and "b.py" in limitation and "c.js" in limitation


def test_snapshot_verify_excludes_output_directory(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    snapshot = RepoIndex.build(tmp_path).snapshot
    out = tmp_path / "reports"
    out.mkdir()
    (out / "artifact-manifest.json").write_text("{}\n", encoding="utf-8")
    verification = snapshot.verify(tmp_path, exclude=(out,))
    assert verification.state == "verified"


def test_mutation_warning_requires_content_change_not_stat_drift(tmp_path: Path) -> None:
    path = tmp_path / "a.py"
    path.write_text("x = 1\n", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    # Same content rewritten: stat drifts, the analyzed text does not (C33).
    path.write_text("x = 1\n", encoding="utf-8")
    assert index.mutation_warnings() == ()


def test_mutation_warnings_detect_new_file(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    (tmp_path / "late.js").write_text("const l = 1\n", encoding="utf-8")
    warnings = index.mutation_warnings()
    assert any("new file: late.js" in w for w in warnings)
