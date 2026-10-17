"""Tests for the AM041 release-readiness tooling (SBOM, lock manifest).

All fixtures are synthetic packages / repositories built inside tmp_path; no
real package or repository content is modified. Everything runs offline.
"""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
# The lock's canonical format was proven byte-identical to the am043 freeze
# snapshot inventory (sha256 87741d2a…) when introduced; that live snapshot is
# mutable, so format stability is now asserted by roundtrip instead.


def load_tool(name):
    spec = importlib.util.spec_from_file_location(f"release_tools_{name}", TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def sbom_tool():
    return load_tool("generate_release_sbom")


@pytest.fixture(scope="module")
def lock_tool():
    return load_tool("generate_release_lock")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_package(root: Path, *, bundled=False, package_id="dev-20260101200000-1a2b3c4d"):
    """Build a small synthetic package directory in the packager's on-disk shape."""
    package = root / "package"
    payload = {
        "AttackMap.NativeSpike.exe": b"synthetic native shell payload",
        "coreclr.dll": b"synthetic clr bytes",
        "AttackMap.NativeSpike.runtimeconfig.json": json.dumps(
            {"runtimeOptions": {"includedFrameworks": [{"name": "Microsoft.NETCore.App", "version": "8.0.32"}]}}
        ).encode("utf-8"),
    }
    if bundled:
        verification = json.dumps({"version": "attackmap 1.5.1", "checks": {"modules_discovered": 19}}).encode("utf-8")
        payload["engine/attackmap.exe"] = b"synthetic frozen engine bytes"
        payload["engine/engine-verification.json"] = verification
    for relative, data in payload.items():
        target = package / "app" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    engine_meta = {
        "bundled": False,
        "required_modules": ["attackmap.desktop_worker", "attackmap.desktop_actions"],
        "run_schema_range": "1.0-1.1",
    }
    if bundled:
        engine_meta = {
            "bundled": True,
            "executable": "app/engine/attackmap.exe",
            "runtime_kind": "Frozen",
            "version": "attackmap 1.5.1",
            "analyzer_count": 19,
            "run_schema_range": "1.0-1.1",
            "verification_sha256": sha256_bytes(payload["engine/engine-verification.json"]),
            "source_checksums_sha256": "0" * 64,
            "limitations": ["synthetic fixture engine"],
        }
    manifest = {
        "schema_version": 1,
        "package_id": package_id,
        "channel": "unsigned-development",
        "architecture": "win-x64",
        "minimum_windows": "10.0.19041.0",
        "native_runtime": {
            "dotnet_self_contained": True,
            "included_frameworks": [{"name": "Microsoft.NETCore.App", "version": "8.0.32"}],
            "windows_app_sdk_self_contained": True,
            "windows_app_sdk": "2.4.0",
        },
        "engine": engine_meta,
        "files": [
            {"path": relative, "size_bytes": len(data), "sha256": sha256_bytes(data)}
            for relative, data in payload.items()
        ],
    }
    (package / "package-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (package / "Install-AttackMap.ps1").write_text("# synthetic installer placeholder", encoding="utf-8")
    return package, manifest


class TestReleaseSbom:
    def test_schema_and_hash_correctness(self, sbom_tool, tmp_path):
        package, manifest = write_package(tmp_path, bundled=True)
        out = tmp_path / "sbom-out"
        sbom, target = sbom_tool.generate(package, out, engine_venv=tmp_path / "missing-venv")
        assert target == out / "release-sbom.json" and target.is_file()
        written = json.loads(target.read_text(encoding="utf-8"))
        assert written == sbom
        assert sbom["schema_version"] == 1
        assert sbom["sbom_kind"] == "attackmap-windows-development-release"
        assert sbom["package_id"] == manifest["package_id"]
        assert sbom["channel"] == "unsigned-development"
        assert sbom["architecture"] == "win-x64"
        assert sbom["minimum_windows"] == "10.0.19041.0"
        # Native runtime components come from the package manifest.
        assert sbom["native_runtime"]["dotnet_frameworks"] == [{"name": "Microsoft.NETCore.App", "version": "8.0.32"}]
        assert sbom["native_runtime"]["windows_app_sdk"] == "2.4.0"
        # Bundled engine identity fields.
        for key in ("version", "analyzer_count", "verification_sha256", "source_checksums_sha256"):
            assert sbom["engine"][key] == manifest["engine"][key]
        # Every packaged file listed, sorted, with correct recomputed hashes.
        listed = [entry["path"] for entry in sbom["files"]]
        assert listed == sorted((f["path"] for f in manifest["files"]), key=str.casefold)
        assert sbom["file_count"] == len(manifest["files"])
        for entry in sbom["files"]:
            data = (package / "app" / entry["path"]).read_bytes()
            assert entry["size_bytes"] == len(data)
            assert entry["sha256"] == sha256_bytes(data)
        assert sbom["verification"]["files_verified"] == len(manifest["files"])
        assert sbom["verification"]["unexpected_files"] == []
        assert sbom["verification"]["installer_script"]["sha256"] == sha256_bytes(
            (package / "Install-AttackMap.ps1").read_bytes()
        )
        # Honest unsigned statement.
        assert sbom["signing"]["status"] == "unsigned"
        signing_text = json.dumps(sbom["signing"]).lower()
        assert "do not authenticate" in signing_text
        # Missing freeze venv in tmp_path forces the honest unknown fallback.
        assert sbom["python_dependencies"]["status"] == "unknown"
        assert "freeze venv not found" in sbom["python_dependencies"]["reason"].lower()

    def test_refuses_tampered_payload(self, sbom_tool, tmp_path):
        package, _ = write_package(tmp_path)
        target_file = package / "app" / "coreclr.dll"
        target_file.write_bytes(b"tampered content")
        out = tmp_path / "sbom-out"
        with pytest.raises(sbom_tool.ToolError, match="(?i)mismatch"):
            sbom_tool.generate(package, out, engine_venv=tmp_path / "missing-venv")
        assert not (out / "release-sbom.json").exists()

    def test_refuses_tampered_manifest_hash(self, sbom_tool, tmp_path):
        package, manifest = write_package(tmp_path)
        manifest["files"][0]["sha256"] = "0" * 64
        (package / "package-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with pytest.raises(sbom_tool.ToolError, match="(?i)checksum mismatch"):
            sbom_tool.generate(package, tmp_path / "sbom-out", engine_venv=tmp_path / "missing-venv")

    def test_refuses_unexpected_file_in_package(self, sbom_tool, tmp_path):
        package, _ = write_package(tmp_path)
        (package / "unexpected-extra.dll").write_bytes(b"extra")
        with pytest.raises(sbom_tool.ToolError, match="(?i)unrecognized file"):
            sbom_tool.generate(package, tmp_path / "sbom-out", engine_venv=tmp_path / "missing-venv")

    def test_refuses_output_inside_immutable_package(self, sbom_tool, tmp_path):
        package, _ = write_package(tmp_path)
        with pytest.raises(sbom_tool.ToolError, match="(?i)immutable package"):
            sbom_tool.generate(package, package / "out", engine_venv=tmp_path / "missing-venv")
        assert not (package / "out").exists()
        assert not (package / "package-manifest.json" / "..").joinpath("release-sbom.json").exists()
        assert sorted(p.name for p in package.iterdir()) == ["Install-AttackMap.ps1", "app", "package-manifest.json"]

    def test_deterministic_output(self, sbom_tool, tmp_path):
        package, _ = write_package(tmp_path)
        first_dir, second_dir = tmp_path / "run-one", tmp_path / "run-two"
        _, first = sbom_tool.generate(package, first_dir, engine_venv=tmp_path / "missing-venv")
        _, second = sbom_tool.generate(package, second_dir, engine_venv=tmp_path / "missing-venv")
        assert first.read_bytes() == second.read_bytes()

    def test_python_dependencies_known_from_freeze_venv(self, sbom_tool, tmp_path):
        package, manifest = write_package(tmp_path, bundled=True)
        venv = tmp_path / "engine-venv"
        (venv / "Scripts").mkdir(parents=True)
        (venv / "Scripts" / "python.exe").write_bytes(b"")

        def fake_run(cmd, timeout=None):
            if "--version" in cmd:
                return 0, "Python 3.13.15\n", ""
            if "freeze" in cmd:
                return 0, "zeta==1.0\nalpha==2.0\nbeta @ git+https://example.invalid/beta.git\n", ""
            raise AssertionError(f"unexpected command {cmd}")

        deps = sbom_tool.derive_python_dependencies(manifest["engine"], venv, run=fake_run)
        assert deps["status"] == "known"
        assert deps["python_version"] == "Python 3.13.15"
        assert deps["packages"] == ["alpha==2.0", "beta @ git+https://example.invalid/beta.git", "zeta==1.0"]
        assert deps["package_count"] == 3
        _, target = sbom_tool.generate(package, tmp_path / "sbom-out", engine_venv=venv, run=fake_run)
        sbom = json.loads(target.read_text(encoding="utf-8"))
        assert sbom["python_dependencies"]["status"] == "known"
        assert sbom["python_dependencies"]["package_count"] == 3

    def test_python_dependencies_unknown_without_bundled_engine(self, sbom_tool, tmp_path):
        venv = tmp_path / "engine-venv"
        (venv / "Scripts").mkdir(parents=True)
        (venv / "Scripts" / "python.exe").write_bytes(b"")
        deps = sbom_tool.derive_python_dependencies({"bundled": False}, venv, run=lambda cmd, timeout=None: (0, "", ""))
        assert deps == {
            "status": "unknown",
            "reason": "Package does not bundle a frozen engine; no Python runtime ships with this package.",
        }

    def test_cli_exit_codes(self, sbom_tool, tmp_path):
        package, _ = write_package(tmp_path, bundled=True)
        out = tmp_path / "cli-out"
        ok = subprocess.run(
            [sys.executable, str(TOOLS / "generate_release_sbom.py"),
             "--package", str(package), "--output", str(out),
             "--engine-venv", str(tmp_path / "missing-venv")],
            capture_output=True, text=True,
        )
        assert ok.returncode == 0, ok.stderr
        assert (out / "release-sbom.json").is_file()
        assert "unsigned" in ok.stdout.lower()
        (package / "app" / "coreclr.dll").write_bytes(b"tampered")
        refused = subprocess.run(
            [sys.executable, str(TOOLS / "generate_release_sbom.py"),
             "--package", str(package), "--output", str(out)],
            capture_output=True, text=True,
        )
        assert refused.returncode == 2
        assert "mismatch" in refused.stderr.lower()


class TestReleaseLock:
    @staticmethod
    def write_fake_repo(root: Path):
        (root / "src" / "attackmap").mkdir(parents=True)
        (root / "src" / "attackmap" / "__init__.py").write_bytes(b"init")
        (root / "src" / "attackmap" / "cli.py").write_bytes(b"cli")
        (root / "src" / "attackmap" / "__pycache__").mkdir()
        (root / "src" / "attackmap" / "__pycache__" / "cli.pyc").write_bytes(b"excluded bytecode")
        (root / "src" / "attackmap.egg-info").mkdir()
        (root / "src" / "attackmap.egg-info" / "PKG-INFO").write_bytes(b"excluded metadata")
        (root / "installer").mkdir()
        (root / "installer" / "entry.py").write_bytes(b"entry")
        (root / "pyproject.toml").write_bytes(b"[project]")
        (root / "README.md").write_bytes(b"readme")
        return root

    def test_checksum_inventory_scope_and_hash_correctness(self, lock_tool, tmp_path):
        repo = self.write_fake_repo(tmp_path / "repo")
        out = tmp_path / "lock-out"
        lock, target = lock_tool.generate_lock(
            repo, out, engine_venv=tmp_path / "missing-venv", dotnet_exe=tmp_path / "missing-dotnet.exe"
        )
        assert target == out / "release-lock.json" and target.is_file()
        expected = {
            "src/attackmap/__init__.py": sha256_bytes(b"init"),
            "src/attackmap/cli.py": sha256_bytes(b"cli"),
            "installer/entry.py": sha256_bytes(b"entry"),
            "pyproject.toml": sha256_bytes(b"[project]"),
            "README.md": sha256_bytes(b"readme"),
        }
        assert lock["source_checksums"] == expected
        assert lock["source_file_count"] == 5
        assert "__pycache__" not in json.dumps(lock["source_checksums"])
        assert "egg-info" not in json.dumps(lock["source_checksums"])
        # The embedded digest is the SHA-256 of the am043-compatible canonical serialization.
        canonical = lock_tool.canonical_source_checksums_bytes(expected)
        assert lock["source_checksums_sha256"] == sha256_bytes(canonical)
        # Missing local toolchain must be reported honestly, never invented.
        assert lock["toolchain"]["pyinstaller"]["version"] == "unknown"
        assert "freeze venv not found" in lock["toolchain"]["pyinstaller"]["reason"]
        assert lock["toolchain"]["dotnet_sdk"]["version"] == "unknown"
        assert "not found" in lock["toolchain"]["dotnet_sdk"]["reason"]
        assert lock["signing"]["status"] == "unsigned"
        assert lock["schema_version"] == 1
        assert lock["lock_kind"] == "attackmap-windows-development-build-inputs"
        written = json.loads(target.read_text(encoding="utf-8"))
        assert written == lock

    def test_deterministic_output(self, lock_tool, tmp_path):
        repo = self.write_fake_repo(tmp_path / "repo")
        _, first = lock_tool.generate_lock(
            repo, tmp_path / "one", engine_venv=tmp_path / "missing-venv", dotnet_exe=tmp_path / "missing-dotnet.exe"
        )
        _, second = lock_tool.generate_lock(
            repo, tmp_path / "two", engine_venv=tmp_path / "missing-venv", dotnet_exe=tmp_path / "missing-dotnet.exe"
        )
        assert first.read_bytes() == second.read_bytes()

    def test_toolchain_probed_from_venv_and_dotnet(self, lock_tool, tmp_path):
        venv = tmp_path / "engine-venv"
        (venv / "Scripts").mkdir(parents=True)
        (venv / "Scripts" / "python.exe").write_bytes(b"")
        dotnet = tmp_path / "dotnet.exe"
        dotnet.write_bytes(b"")

        def fake_run(cmd, timeout=None):
            joined = " ".join(cmd)
            if "PyInstaller" in joined:
                return 0, "6.22.3\n", ""
            if "dotnet" in joined:
                return 0, "8.0.426\n", ""
            return 0, "Python 3.13.15\n", ""

        toolchain = lock_tool.probe_toolchain(venv, dotnet, run=fake_run)
        assert toolchain["python"]["version"] == "3.13.15"
        assert "freeze venv" in toolchain["python"]["source"]
        assert toolchain["pyinstaller"]["version"] == "6.22.3"
        assert toolchain["dotnet_sdk"]["version"] == "8.0.426"

    def test_canonical_format_roundtrip_is_stable(self, lock_tool, tmp_path):
        """Serializing a written inventory twice reproduces the recorded digest —
        format stability without coupling to a mutable live snapshot."""
        repo = self.write_fake_repo(tmp_path / "repo")
        out = tmp_path / "lock-out"
        result = subprocess.run(
            [sys.executable, str(TOOLS / "generate_release_lock.py"),
             "--repo", str(repo), "--output", str(out),
             "--engine-venv", str(tmp_path / "missing-venv"),
             "--dotnet", str(tmp_path / "missing-dotnet.exe")],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        lock = json.loads((out / "release-lock.json").read_text(encoding="utf-8"))
        assert lock["source_checksums_sha256"] == sha256_bytes(
            lock_tool.canonical_source_checksums_bytes(lock["source_checksums"])
        )

    def test_cli_exit_code(self, lock_tool, tmp_path):
        repo = self.write_fake_repo(tmp_path / "repo")
        out = tmp_path / "cli-out"
        result = subprocess.run(
            [sys.executable, str(TOOLS / "generate_release_lock.py"),
             "--repo", str(repo), "--output", str(out),
             "--engine-venv", str(tmp_path / "missing-venv"),
             "--dotnet", str(tmp_path / "missing-dotnet.exe")],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        assert (out / "release-lock.json").is_file()
        assert "unsigned" in result.stdout.lower()
