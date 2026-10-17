"""Generate a deterministic release SBOM for an unsigned Windows development package.

Reads an immutable package directory produced by tools/package_native_windows.ps1
(package-manifest.json + app/ + Install-AttackMap.ps1), re-verifies every file
size and SHA-256 recorded in the manifest, and writes release-sbom.json into a
caller-chosen target directory outside the package. The package itself is never
modified. Python dependencies are derived from the freeze venv's pip freeze when
that venv exists; otherwise the SBOM records "unknown" with the reason. Nothing
here signs or authenticates the package; the unsigned limitation is recorded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA_VERSION = 1
PACKAGE_ID = re.compile(r"^dev-[0-9]{14}-[a-f0-9]{8}$")
SAFE_ENTRY = re.compile(r"^[A-Za-z0-9_./ -]+$")
DEFAULT_ENGINE_VENV = Path(__file__).resolve().parents[1] / ".pytest_cache/am043-package/engine-venv"
RUN_TIMEOUT_SECONDS = 180

UNSIGNED_NOTE = (
    "Unsigned development-channel package. No Authenticode signature, certificate, "
    "publisher identity or timestamp exists; SHA-256 values verify content integrity "
    "only and do not authenticate origin. Notarization is not applicable on Windows."
)


class ToolError(Exception):
    """Fatal, honest validation failure; the SBOM is not written."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_command(cmd, timeout=RUN_TIMEOUT_SECONDS):
    """Run a local command offline; returns (returncode, stdout, stderr). Injectable for tests."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def load_manifest(package_dir: Path) -> dict:
    manifest_path = package_dir / "package-manifest.json"
    if not manifest_path.is_file():
        raise ToolError(f"No package-manifest.json in {package_dir}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise ToolError(f"package-manifest.json is not valid JSON: {error}") from error
    if manifest.get("schema_version") != 1:
        raise ToolError(f"Unsupported manifest schema_version: {manifest.get('schema_version')}")
    if not PACKAGE_ID.match(manifest.get("package_id", "")):
        raise ToolError(f"Invalid package identity: {manifest.get('package_id')}")
    if not isinstance(manifest.get("files"), list) or not manifest["files"]:
        raise ToolError("Manifest records no files")
    return manifest


def safe_app_path(package_dir: Path, relative: str) -> Path:
    parts = relative.split("/")
    if not SAFE_ENTRY.match(relative) or ".." in parts or relative.startswith("/"):
        raise ToolError(f"Unsafe package entry: {relative}")
    candidate = (package_dir / "app").joinpath(*relative.split("/"))
    resolved = candidate.resolve()
    app_root = (package_dir / "app").resolve()
    if app_root != resolved and app_root not in resolved.parents:
        raise ToolError(f"Package entry escapes app root: {relative}")
    return candidate


def verify_package(package_dir: Path, manifest: dict) -> dict:
    """Re-verify every manifest entry and refuse unexpected or tampered content."""
    expected = {"package-manifest.json"}
    installer = package_dir / "Install-AttackMap.ps1"
    if installer.is_file():
        expected.add("Install-AttackMap.ps1")
    seen = set()
    bytes_verified = 0
    for entry in manifest["files"]:
        relative = entry.get("path", "")
        if relative in seen:
            raise ToolError(f"Duplicate manifest entry: {relative}")
        seen.add(relative)
        target = safe_app_path(package_dir, relative)
        if target.is_symlink() or not target.is_file():
            raise ToolError(f"Missing packaged file: {relative}")
        actual_size = target.stat().st_size
        if actual_size != entry.get("size_bytes"):
            raise ToolError(f"Size mismatch for {relative}: manifest {entry.get('size_bytes')} != actual {actual_size}")
        actual_hash = sha256_file(target)
        if actual_hash != entry.get("sha256", "").lower():
            raise ToolError(f"Checksum mismatch for {relative}; package content differs from its manifest")
        expected.add("app/" + relative)
        bytes_verified += actual_size
    for path in sorted(package_dir.rglob("*")):
        relative = path.relative_to(package_dir).as_posix()
        if path.is_symlink():
            raise ToolError(f"Redirected package entry: {relative}")
        if path.is_file() and relative not in expected:
            raise ToolError(f"Unrecognized file in package (not in manifest): {relative}")
    verification = {
        "manifest_schema_version": manifest["schema_version"],
        "package_manifest_sha256": sha256_file(package_dir / "package-manifest.json"),
        "files_verified": len(seen),
        "bytes_verified": bytes_verified,
        "unexpected_files": [],
    }
    if installer.is_file():
        verification["installer_script"] = {
            "path": "Install-AttackMap.ps1",
            "size_bytes": installer.stat().st_size,
            "sha256": sha256_file(installer),
        }
    return verification


def derive_python_dependencies(engine_meta: dict, venv_dir: Path, run=_run_command) -> dict:
    """Derive the packaged engine's Python dependency inventory from the freeze venv."""
    if not engine_meta.get("bundled"):
        return {
            "status": "unknown",
            "reason": "Package does not bundle a frozen engine; no Python runtime ships with this package.",
        }
    venv_python = venv_dir / "Scripts" / "python.exe"
    if not venv_python.is_file():
        return {
            "status": "unknown",
            "reason": f"Freeze venv not found at {venv_dir}; the frozen payload is not introspected, "
            "so the Python dependency inventory cannot be derived for this package.",
        }
    code, out, err = run([str(venv_python), "-m", "pip", "freeze"])
    if code != 0 or not out.strip():
        detail = (err or out).strip().splitlines()[-1] if (err or out).strip() else "no output"
        return {"status": "unknown", "reason": f"pip freeze failed in freeze venv: {detail}"}
    vcode, vout, _ = run([str(venv_python), "--version"])
    packages = sorted((line.strip() for line in out.splitlines() if line.strip()), key=str.casefold)
    return {
        "status": "known",
        "source": "pip freeze of the engine freeze venv",
        "venv": str(venv_dir),
        "python_version": vout.strip() if vcode == 0 else "unknown",
        "packages": packages,
        "package_count": len(packages),
        "note": "Editable and VCS entries reference the local development snapshot used for the freeze.",
    }


def build_sbom(manifest: dict, verification: dict, python_dependencies: dict) -> dict:
    native = manifest.get("native_runtime", {})
    engine_meta = manifest.get("engine", {})
    engine_identity = {"bundled": bool(engine_meta.get("bundled"))}
    if engine_identity["bundled"]:
        for key in ("executable", "runtime_kind", "version", "analyzer_count", "run_schema_range",
                    "verification_sha256", "source_checksums_sha256", "limitations"):
            if key in engine_meta:
                engine_identity[key] = engine_meta[key]
    else:
        for key in ("required_modules", "run_schema_range", "discovery", "note"):
            if key in engine_meta:
                engine_identity[key] = engine_meta[key]
    files = sorted(manifest["files"], key=lambda entry: entry["path"].casefold())
    sbom = {
        "schema_version": SCHEMA_VERSION,
        "sbom_kind": "attackmap-windows-development-release",
        "package_id": manifest["package_id"],
        "channel": manifest.get("channel"),
        "architecture": manifest.get("architecture"),
        "minimum_windows": manifest.get("minimum_windows"),
        "signing": {"status": "unsigned", "note": UNSIGNED_NOTE},
        "native_runtime": {
            "dotnet_self_contained": native.get("dotnet_self_contained"),
            "dotnet_frameworks": native.get("included_frameworks", []),
            "windows_app_sdk_self_contained": native.get("windows_app_sdk_self_contained"),
            "windows_app_sdk": native.get("windows_app_sdk"),
        },
        "engine": engine_identity,
        "python_dependencies": python_dependencies,
        "files": [{"path": f["path"], "size_bytes": f["size_bytes"], "sha256": f["sha256"]} for f in files],
        "file_count": len(files),
        "verification": verification,
    }
    return sbom


def generate(package_dir: Path, output_dir: Path, engine_venv: Path = DEFAULT_ENGINE_VENV, run=_run_command):
    package_dir = Path(package_dir).resolve()
    output_dir = Path(output_dir).resolve()
    if not package_dir.is_dir():
        raise ToolError(f"Package directory not found: {package_dir}")
    if output_dir == package_dir or package_dir in output_dir.parents:
        raise ToolError("Refusing to write the SBOM inside the immutable package; choose a target directory outside it")
    manifest = load_manifest(package_dir)
    verification = verify_package(package_dir, manifest)
    python_dependencies = derive_python_dependencies(manifest.get("engine", {}), Path(engine_venv), run=run)
    sbom = build_sbom(manifest, verification, python_dependencies)
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "release-sbom.json"
    target.write_bytes((json.dumps(sbom, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    return sbom, target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--package", required=True, help="immutable package directory containing package-manifest.json")
    parser.add_argument("--output", required=True, help="target directory for release-sbom.json (must be outside the package)")
    parser.add_argument("--engine-venv", default=str(DEFAULT_ENGINE_VENV),
                        help="freeze venv used for the packaged engine's pip freeze inventory (default: %(default)s)")
    args = parser.parse_args(argv)
    try:
        sbom, target = generate(Path(args.package), Path(args.output), Path(args.engine_venv))
    except ToolError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    engine = sbom["engine"]
    deps = sbom["python_dependencies"]
    print(f"SBOM: {target}")
    print(f"Package: {sbom['package_id']} ({sbom['channel']}, {sbom['architecture']})")
    print(f"Files verified: {sbom['verification']['files_verified']} ({sbom['verification']['bytes_verified']} bytes)")
    if engine["bundled"]:
        print(f"Engine: bundled frozen {engine.get('version')} ({engine.get('analyzer_count')} analyzers)")
    else:
        print("Engine: not bundled")
    if deps["status"] == "known":
        print(f"Python dependencies: known ({deps['package_count']} packages from pip freeze)")
    else:
        print(f"Python dependencies: unknown - {deps['reason']}")
    print("Signing: unsigned; hashes verify content only, they do not authenticate origin.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
