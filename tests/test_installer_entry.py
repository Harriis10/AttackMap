import importlib.util
import os
from pathlib import Path
import subprocess
import sys

ENTRY = Path(__file__).parents[1] / "installer" / "entry.py"


def load_entry():
    spec = importlib.util.spec_from_file_location("attackmap_installer_entry_test", ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeStream:
    def __init__(self, interactive=False):
        self.interactive = interactive
        self.calls = []

    def isatty(self):
        return self.interactive

    def reconfigure(self, **kwargs):
        self.calls.append(kwargs)


def test_redirected_streams_utf8_and_interactive_stream_unchanged(monkeypatch):
    module = load_entry()
    streams = [FakeStream(), FakeStream(True), FakeStream()]
    for name, stream in zip(("stdin", "stdout", "stderr"), streams):
        monkeypatch.setattr(module.sys, name, stream)
    module.configure_redirected_stdio()
    assert streams[0].calls == streams[2].calls == [{"encoding": "utf-8"}]
    assert streams[1].calls == []


def test_import_is_guarded_and_unavailable_streams_are_tolerated(monkeypatch):
    module = load_entry()
    assert not hasattr(module, "app")
    monkeypatch.setattr(module.sys, "stdin", None)
    # Standard streams expose isatty; hosts may provide a stream without reconfigure.
    monkeypatch.setattr(module.sys, "stdout", type("HostStream", (), {"isatty": lambda self: False})())
    monkeypatch.setattr(module.sys, "stderr", None)
    module.configure_redirected_stdio()


def test_actual_child_entry_roundtrips_utf8_under_forced_legacy_encoding():
    script = r'''
import runpy,sys,types
module=types.ModuleType("attackmap.cli")
def app():
    assert sys.stdin.encoding.lower()==sys.stdout.encoding.lower()==sys.stderr.encoding.lower()=="utf-8"
    text=sys.stdin.read()
    sys.stdout.write(text)
    sys.stderr.write(text)
module.app=app
sys.modules["attackmap.cli"]=module
runpy.run_path(sys.argv[1],run_name="__main__")
'''
    text = '{"synthetic":"žluťoučký → 🔒"}\n'
    env = {**os.environ, "PYTHONIOENCODING": "cp1250", "PYTHONUTF8": "0"}
    result = subprocess.run([sys.executable, "-c", script, str(ENTRY)], input=text.encode("utf-8"), capture_output=True, env=env, timeout=15)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout == result.stderr
    assert result.stdout.decode("utf-8").replace("\r\n", "\n") == text


def test_actual_cli_help_with_forced_legacy_redirected_output():
    result = subprocess.run([sys.executable, str(ENTRY), "analyze", "--help"], capture_output=True,
                            env={**os.environ, "PYTHONIOENCODING": "cp1250", "PYTHONUTF8": "0"}, timeout=30)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert "Usage" in result.stdout.decode("utf-8")
