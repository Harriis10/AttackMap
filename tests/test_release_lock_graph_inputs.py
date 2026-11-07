"""Native graph project references must participate in the source-bound package lock."""
import importlib.util
from pathlib import Path
import pytest


def load_module():
    spec = importlib.util.spec_from_file_location("graph_release_lock", Path(__file__).parents[1] / "tools/generate_release_lock.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_graph_project_sources_change_release_identity_but_build_outputs_do_not(tmp_path):
    module = load_module()
    source = tmp_path / "src/attackmap/core.py"
    source.parent.mkdir(parents=True)
    source.write_text("# source\n")
    before = module.release_inputs(tmp_path)
    graph = tmp_path / "desktop/windows/GraphExplorer.Core/GraphModel.cs"
    graph.parent.mkdir(parents=True)
    graph.write_text("// graph model v1\n")
    after = module.release_inputs(tmp_path)
    assert after["source_checksums_sha256"] == before["source_checksums_sha256"]
    assert after["release_inputs_sha256"] != before["release_inputs_sha256"]
    graph.write_text("// graph model v2\n")
    changed = module.release_inputs(tmp_path)
    assert changed["release_inputs_sha256"] != after["release_inputs_sha256"]
    output = graph.parent / "obj/cache.cs"
    output.parent.mkdir()
    output.write_text("// generated build output\n")
    assert module.release_inputs(tmp_path) == changed
    view = tmp_path / "desktop/windows/GraphExplorer.NativeView/GraphExplorerView.cs"
    view.parent.mkdir(parents=True)
    view.write_text("// native graph renderer\n")
    assert module.release_inputs(tmp_path)["release_inputs_sha256"] != changed["release_inputs_sha256"]


def test_linked_desktop_fixture_participates_in_release_identity(tmp_path):
    module = load_module()
    source = tmp_path / "src/core.py"
    source.parent.mkdir()
    source.write_text("# core\n")
    before = module.release_inputs(tmp_path)
    fixture = tmp_path / "desktop/windows/fixtures/findings.json"
    fixture.parent.mkdir(parents=True)
    fixture.write_text('{"findings": []}\n')
    captured = module.release_inputs(tmp_path)
    assert captured["source_checksums_sha256"] == before["source_checksums_sha256"]
    assert captured["release_inputs_sha256"] != before["release_inputs_sha256"]
    fixture.write_text('{"findings": [{"id": "changed"}]}\n')
    assert module.release_inputs(tmp_path)["release_inputs_sha256"] != captured["release_inputs_sha256"]


def test_rejects_two_different_core_inventories(tmp_path, monkeypatch):
    module = load_module()
    values = iter([{"src/a.py": "a" * 64}, {"src/a.py": "b" * 64}])
    monkeypatch.setattr(module, "collect_source_checksums", lambda repo: next(values))
    with pytest.raises(module.ToolError, match="changed while capturing"):
        module.release_inputs(tmp_path)


def test_lock_is_not_written_when_toolchain_probe_changes_native_inputs(tmp_path, monkeypatch):
    module = load_module()
    source = tmp_path / "src/a.py"
    source.parent.mkdir()
    source.write_text("# core\n")
    view = tmp_path / "desktop/windows/GraphExplorer.NativeView/View.cs"
    view.parent.mkdir(parents=True)
    view.write_text("// first\n")
    original = module.release_inputs
    captures = 0
    def changing_capture(repo):
        nonlocal captures
        result = original(repo)
        captures += 1
        if captures == 1:
            view.write_text("// changed before final check\n")
        return result
    monkeypatch.setattr(module, "release_inputs", changing_capture)
    monkeypatch.setattr(module, "probe_toolchain", lambda *args, **kwargs: {})
    with pytest.raises(module.ToolError, match="changed before writing"):
        module.generate_lock(tmp_path, tmp_path / "output")
    assert not (tmp_path / "output/release-lock.json").exists()
