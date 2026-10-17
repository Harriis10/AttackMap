"""Generate a deterministic release lock manifest for the unsigned Windows development channel.

Captures the exact build inputs: a file-by-file SHA-256 inventory over src/,
installer/, pyproject.toml and README.md (excluding __pycache__ and *.egg-info),
serialized in the same canonical form as the frozen-engine source-checksums.json
(case-insensitively sorted keys, indent=1, CRLF) so digests are directly
comparable with engine-verification.json. Also records the freeze venv's Python
and PyInstaller versions and the local .NET SDK version when present. Unsigned
limitations are recorded honestly; nothing here signs the release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path

SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENGINE_VENV = REPO_ROOT / ".pytest_cache/am043-package/engine-venv"
DEFAULT_DOTNET = REPO_ROOT / ".tools/dotnet/dotnet.exe"
SOURCE_DIRS = ("src", "installer")
SOURCE_FILES = ("pyproject.toml", "README.md")
RUN_TIMEOUT_SECONDS = 180

UNSIGNED_NOTE = (
    "Unsigned development-channel build inputs. No certificate or signing step exists; "
    "this lock pins inputs and tool versions only."
)


class ToolError(Exception):
    """Fatal validation failure; the lock is not written."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _excluded(part: str) -> bool:
    return part == "__pycache__" or part.endswith(".egg-info")


def collect_source_checksums(repo: Path) -> dict:
    """Recompute the source inventory the same way the am043 freeze snapshot did."""
    repo = Path(repo).resolve()
    entries = {}
    for directory in SOURCE_DIRS:
        base = repo / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise ToolError(f"Redirected source entry refused: {path.relative_to(repo).as_posix()}")
            if not path.is_file():
                continue
            parts = (directory,) + path.relative_to(base).parts
            if any(_excluded(part) for part in parts):
                continue
            entries["/".join(parts)] = sha256_file(path)
    for name in SOURCE_FILES:
        candidate = repo / name
        if candidate.is_file():
            entries[name] = sha256_file(candidate)
    if not entries:
        raise ToolError(f"No source inputs found under {repo}")
    return dict(sorted(entries.items(), key=lambda item: item[0].casefold()))


def canonical_source_checksums_bytes(mapping: dict) -> bytes:
    """Byte-exact reproduction of the frozen-engine source-checksums.json format."""
    ordered = dict(sorted(mapping.items(), key=lambda item: item[0].casefold()))
    return json.dumps(ordered, indent=1).replace("\n", "\r\n").encode("utf-8")


def _run_command(cmd, timeout=RUN_TIMEOUT_SECONDS):
    import subprocess

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def probe_toolchain(engine_venv: Path, dotnet_exe: Path, run=_run_command) -> dict:
    """Probe the exact local tool versions used to build the release payload."""
    venv_python = Path(engine_venv) / "Scripts" / "python.exe"
    if venv_python.is_file():
        code, out, _ = run([str(venv_python), "--version"])
        python_info = {
            "version": out.strip().replace("Python ", "") if code == 0 else "unknown",
            "source": f"engine freeze venv ({engine_venv})",
        }
    else:
        python_info = {
            "version": platform.python_version(),
            "source": "generator interpreter; freeze venv not found, so the exact engine build Python is unknown",
        }
    if venv_python.is_file():
        code, out, err = run([str(venv_python), "-m", "PyInstaller", "--version"])
        if code == 0 and out.strip():
            pyinstaller_info = {"version": out.strip().splitlines()[-1].strip(), "source": f"engine freeze venv ({engine_venv})"}
        else:
            pyinstaller_info = {"version": "unknown", "reason": f"PyInstaller probe failed in freeze venv: {(err or out).strip()[:200]}"}
    else:
        pyinstaller_info = {"version": "unknown", "reason": f"freeze venv not found at {engine_venv}; PyInstaller version unavailable"}
    if Path(dotnet_exe).is_file():
        code, out, err = run([str(dotnet_exe), "--version"])
        if code == 0 and out.strip():
            dotnet_info = {"version": out.strip().splitlines()[-1].strip(), "source": str(dotnet_exe)}
        else:
            dotnet_info = {"version": "unknown", "reason": f"dotnet --version failed: {(err or out).strip()[:200]}"}
    else:
        dotnet_info = {"version": "unknown", "reason": f"dotnet SDK not found at {dotnet_exe}"}
    return {"python": python_info, "pyinstaller": pyinstaller_info, "dotnet_sdk": dotnet_info}


def generate_lock(repo: Path, output_dir: Path, engine_venv: Path = DEFAULT_ENGINE_VENV,
                  dotnet_exe: Path = DEFAULT_DOTNET, run=_run_command,
                  reference_source_checksums: Path = None):
    repo = Path(repo).resolve()
    output_dir = Path(output_dir).resolve()
    source_checksums = collect_source_checksums(repo)
    canonical = canonical_source_checksums_bytes(source_checksums)
    lock = {
        "schema_version": SCHEMA_VERSION,
        "lock_kind": "attackmap-windows-development-build-inputs",
        "channel": "unsigned-development",
        "signing": {"status": "unsigned", "note": UNSIGNED_NOTE},
        "source_checksums_scope": [
            "src/** (excluding __pycache__ and *.egg-info)",
            "installer/**",
            "pyproject.toml",
            "README.md",
        ],
        "source_checksums": source_checksums,
        "source_file_count": len(source_checksums),
        "source_checksums_sha256": hashlib.sha256(canonical).hexdigest(),
        "toolchain": probe_toolchain(Path(engine_venv), Path(dotnet_exe), run=run),
        "notes": [
            "Deterministic output: no timestamps; reruns over identical inputs and toolchain produce identical bytes.",
            "source_checksums_sha256 uses the same canonical serialization as the frozen-engine "
            "source-checksums.json, so it can be compared directly with engine source_checksums_sha256 values.",
        ],
    }
    if reference_source_checksums is not None:
        reference = Path(reference_source_checksums)
        if reference.is_file():
            lock["reference_comparison"] = {
                "path": str(reference),
                "reference_source_checksums_sha256": sha256_file(reference),
                "matches_current_sources": sha256_file(reference) == lock["source_checksums_sha256"],
            }
        else:
            lock["reference_comparison"] = {"path": str(reference), "error": "reference source-checksums file not found"}
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "release-lock.json"
    target.write_bytes((json.dumps(lock, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    return lock, target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=str(REPO_ROOT), help="repository root to inventory (default: %(default)s)")
    parser.add_argument("--output", required=True, help="target directory for release-lock.json")
    parser.add_argument("--engine-venv", default=str(DEFAULT_ENGINE_VENV),
                        help="freeze venv providing the exact build Python and PyInstaller versions (default: %(default)s)")
    parser.add_argument("--dotnet", default=str(DEFAULT_DOTNET),
                        help="local dotnet SDK executable to record (default: %(default)s)")
    parser.add_argument("--reference-source-checksums", default=None,
                        help="optional prior source-checksums.json to compare against the current inventory")
    args = parser.parse_args(argv)
    try:
        lock, target = generate_lock(
            Path(args.repo), Path(args.output), Path(args.engine_venv), Path(args.dotnet),
            reference_source_checksums=Path(args.reference_source_checksums) if args.reference_source_checksums else None,
        )
    except ToolError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    toolchain = lock["toolchain"]
    print(f"Lock: {target}")
    print(f"Source files inventoried: {lock['source_file_count']} (digest {lock['source_checksums_sha256']})")
    print(f"Python: {toolchain['python']['version']} ({toolchain['python']['source']})")
    print(f"PyInstaller: {toolchain['pyinstaller']['version']}")
    print(f".NET SDK: {toolchain['dotnet_sdk']['version']}")
    if "reference_comparison" in lock and "matches_current_sources" in lock["reference_comparison"]:
        print(f"Reference match: {lock['reference_comparison']['matches_current_sources']}")
    print("Signing: unsigned; this lock pins build inputs only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
