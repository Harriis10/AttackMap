"""RepoIndex: one walk, one read, shared by built-in scanners."""

from __future__ import annotations

from pathlib import Path

from attackmap.index import RepoIndex
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

    def boom(*args, **kwargs):
        walks["n"] += 1
        raise AssertionError("scan_files should not walk when an index is provided")

    monkeypatch.setattr("attackmap.scanner.walk_repo", boom)
    result = scan_files(tmp_path, suffixes={".py"}, index=index)
    assert walks["n"] == 0
    assert any(r.path == "/x" for r in result.routes)
