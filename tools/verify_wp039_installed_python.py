"""Offline installed-plugin qualification in a fresh task-owned target.

Builds the retained exact-pin archive and a collision control with local build
tools. Never changes the active environment or downloads dependencies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PIN = "1bcce0dd5d639cb83ada65cc3f5024bb5a1d9782"
ARCHIVE_SHA256 = "913c102365d5b9e4b902683edc022aa6a281cd4d77990f71abbddf6c0bccf536"


def prepare(archive: Path, output: Path, builder: str) -> Path:
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("Retained pinned archive digest mismatch")
    output.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(command):
        commands.append(command)
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
            env=dict(os.environ, PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1"), timeout=180)
        (output / f"command-{len(commands):02}.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        (output / "commands.json").write_text(json.dumps(commands, indent=2), encoding="utf-8")
        if result.returncode:
            raise RuntimeError(f"Offline command {len(commands)} failed; see its log")

    source = output / "source"
    source.mkdir()
    with zipfile.ZipFile(archive) as bundle:
        prefix = f"attackmap-analyzer-python-{PIN}/"
        for item in bundle.infolist():
            if not item.filename.startswith(prefix) or ".." in Path(item.filename).parts or "\\" in item.filename:
                raise ValueError("Unexpected pinned archive member")
        bundle.extractall(source)
    pinned = source / prefix.rstrip("/")
    wheels, target = output / "wheels", output / "installed"
    run([builder, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation",
        "--wheel-dir", str(wheels), str(pinned)])
    collision = output / "collision-control"
    collision.mkdir()
    (collision / "pyproject.toml").write_text('''[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.build_meta"
[project]
name = "wp039-collision-control"
version = "1.0"
[project.entry-points."attackmap.analyzers"]
python = "wp039_collision:CollisionAnalyzer"
[tool.setuptools]
py-modules = ["wp039_collision"]
''', encoding="utf-8")
    (collision / "wp039_collision.py").write_text('''from attackmap.sdk import AnalyzerMetadata, AnalyzerResult, Route
class CollisionAnalyzer:
    metadata = AnalyzerMetadata(name="python", version="1.0", description="Installed collision control", priority=10)
    name = "python"
    def detect(self, root): return True
    def analyze(self, root):
        return AnalyzerResult(root=str(root), routes=[Route(path="/collision-control", file="project/urls.py", line=1)])
''', encoding="utf-8")
    run([builder, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation",
        "--wheel-dir", str(wheels), str(collision)])
    run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--target", str(target),
        *map(str, sorted(wheels.glob("*.whl")))])
    original = {p.relative_to(pinned / "src").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (pinned / "src").rglob("*.py")}
    installed = {name: hashlib.sha256((target / name).read_bytes()).hexdigest() for name in original}
    if original != installed:
        raise ValueError("Installed source differs from retained exact pin")
    (output / "installation.json").write_text(json.dumps(dict(pin=PIN, archive_sha256=ARCHIVE_SHA256,
        source_hashes=original, installed_source_identical=True, target=str(target),
        wheels={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in wheels.glob("*.whl")}), indent=2), encoding="utf-8")
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--builder-python", required=True)
    parser.add_argument("--archive", type=Path, default=ROOT / "docs/verification/windows-parity/WP039/sol-ultra-20261023-python/upstream-pinned-source.zip")
    args = parser.parse_args()
    output = args.output.resolve()
    target = prepare(args.archive, output, args.builder_python)
    env = dict(os.environ, WP039_PINNED_TARGET=str(target), WP039_EVIDENCE=str(output),
        PYTHONPATH=str(target) + os.pathsep + str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    bound_sources = [ROOT / name for name in ("src/attackmap/analyzer_host.py",
        "src/attackmap/analyzers.py", "src/attackmap/python_django_routes.py",
        "tests/test_wp039_installed_python.py", "tools/verify_wp039_installed_python.py")]
    hashes = lambda: {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in bound_sources}
    before = hashes()
    command = [sys.executable, "-m", "pytest", "tests/test_wp039_installed_python.py", "-q", "-p", "no:cacheprovider",
        "--basetemp", str(output / "pytest-temp"), "--junitxml", str(output / "installed-tests.xml")]
    (output / "test-command.json").write_text(json.dumps(command, indent=2), encoding="utf-8")
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    (output / "installed-tests.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    after = hashes()
    (output / "verification.json").write_text(json.dumps(dict(exit_code=result.returncode,
        source_hashes_before=before, source_hashes_after=after, source_unchanged=before == after,
        scope="Installed pinned extraction and collision identity; no provider, GUI or release acceptance"), indent=2), encoding="utf-8")
    print(result.stdout + result.stderr)
    return result.returncode if before == after else 1


if __name__ == "__main__":
    raise SystemExit(main())
