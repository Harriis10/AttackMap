"""The frozen entry admits only the owned isolated analyzer worker."""
import importlib.util
from pathlib import Path
import sys
import types

import pytest


@pytest.fixture
def entry(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "installer/entry.py"
    spec = importlib.util.spec_from_file_location("frozen_entry_dispatch_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    monkeypatch.setattr(module, "configure_redirected_stdio", lambda: calls.append("stdio"))
    monkeypatch.setitem(sys.modules, "attackmap.cli", types.SimpleNamespace(app=lambda: calls.append("cli")))
    def worker(argv):
        calls.append(("worker", argv))
        return 7
    monkeypatch.setitem(sys.modules, "attackmap.analyzer_host", types.SimpleNamespace(_main=worker))
    return module, calls


def test_frozen_owned_worker_dispatch_preserves_worker_arguments(entry, monkeypatch):
    module, calls = entry
    argv = ["engine.exe", "-m", "attackmap.analyzer_host", "--worker", "--repo", "repo"]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 7
    assert calls == ["stdio", ("worker", argv[3:])]


@pytest.mark.parametrize("arguments", [
    [], ["-m"], ["-m", "attackmap.analyzer_host"],
    ["-m", "foreign.module", "--worker"],
    ["-m", "attackmap.analyzer_host", "--help"],
    ["-m", "attackmap.analyzer_host.extra", "--worker"],
    ["desktop-worker", "--request", "request.json"],
    ["desktop-action", "--request", "request.json"],
])
def test_frozen_other_invocations_retain_cli_dispatch(entry, monkeypatch, arguments):
    module, calls = entry
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "argv", ["engine.exe", *arguments])
    module.main()
    assert calls == ["stdio", "cli"]


def test_source_entry_does_not_emulate_interpreter_dispatch(entry, monkeypatch):
    module, calls = entry
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(sys, "argv", ["python", "-m", "attackmap.analyzer_host", "--worker"])
    module.main()
    assert calls == ["stdio", "cli"]
