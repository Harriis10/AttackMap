"""Prepare an additive pinned-Mac patch and producer-shaped owned fixtures.

No scan, provider, Swift execution, checkout mutation, or remote access.
Existing fixtures are verified, never silently regenerated from newer producers.
"""
from pathlib import Path
import difflib
import hashlib
import json
import shutil
import sys
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
PIN = "5f2e8b4d84f9dff06e0f87c69c861a434981bd6a"
FIXTURES = HERE / "AttackMapTests/Fixtures/SelectedGeneration/current"
PROVENANCE = HERE / "fixture-provenance.json"
SOURCES = ["src/attackmap/artifact_manifest.py", "src/attackmap/safe_fs.py",
           "tests/artifact_fixture.py", "fixtures/desktop-parity/report-empty.json"]
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
source_hashes = {name: digest(ROOT / name) for name in SOURCES}

if not FIXTURES.exists():
    FIXTURES.mkdir(parents=True, exist_ok=False)
    report = (ROOT / "fixtures/desktop-parity/report-empty.json").read_bytes()
    (FIXTURES / "attackmap-report.json").write_bytes(report)
    (FIXTURES / "run-manifest.json").write_text('{"stages": []}\n', encoding="utf-8", newline="\n")
    (FIXTURES / "defensive-review.md").write_text(
        "# Synthetic defensive review\n\nFixture only; no scan or provider executed.\n", encoding="utf-8", newline="\n")
    sys.path.insert(0, str(ROOT / "src"))
    from attackmap.artifact_manifest import write_artifact_manifest
    data = json.loads(report)
    # Only the producer's wall-clock field is fixed for reproducible test data.
    with patch("attackmap.artifact_manifest._iso_now", return_value="2026-10-21T00:00:00Z"):
        write_artifact_manifest(FIXTURES, "wp028-owned-generation", "fixture-only",
            data["scan"]["root"], "sample", [], 0, "succeeded", data, output_format="all")
    # Output marker is operational metadata, not an artifact manifest entry.
    manifest = json.loads((FIXTURES / "artifact-manifest.json").read_text())
    listed = {item["path"] for item in manifest["sections"] + manifest["compatibility_exports"]}
    listed.add("artifact-manifest.json")
    for child in FIXTURES.iterdir():
        if child.name not in listed:
            if not child.is_file(): raise SystemExit("Unexpected producer directory")
            child.unlink()
    fixture_hashes = {str(p.relative_to(HERE)).replace("\\", "/"): digest(p) for p in sorted(FIXTURES.iterdir())}
    PROVENANCE.write_text(json.dumps(dict(pinned_mac_commit=PIN,
        producer="attackmap.artifact_manifest.write_artifact_manifest", producer_source_sha256=source_hashes,
        fixed_fixture_clock="2026-10-21T00:00:00Z", shared_report_bytes_copied=True,
        synthetic=True, engine_scan_executed=False, provider_executed=False,
        files_sha256=fixture_hashes), indent=2) + "\n", encoding="utf-8")
else:
    provenance = json.loads(PROVENANCE.read_text())
    for relative, expected in provenance["files_sha256"].items():
        if digest(HERE / relative) != expected: raise SystemExit("Owned immutable fixture changed: " + relative)

for name, expected in source_hashes.items():
    if digest(ROOT / name) != expected: raise SystemExit("Producer input changed during preparation: " + name)
license_source = HERE.parent / "pinned-base/LICENSE"
license_target = HERE / "LICENSE"
if not license_target.exists(): shutil.copyfile(license_source, license_target)
if license_target.read_bytes() != license_source.read_bytes(): raise SystemExit("Retained license mismatch")
targets = sorted((HERE / "AttackMap").rglob("*.swift")) + sorted((HERE / "AttackMapTests").rglob("*.swift")) + sorted(FIXTURES.glob("*"))
chunks = []
for target in targets:
    relative = target.relative_to(HERE).as_posix()
    chunks.extend(difflib.unified_diff([], target.read_text(encoding="utf-8").splitlines(keepends=True),
        fromfile="/dev/null", tofile="b/" + relative))
output = HERE / "selected-generation.patch"
output.write_text("".join(chunks), encoding="utf-8", newline="\n")
manifest = dict(repository="https://github.com/mlaify/AttackMap-mac", pinned_commit=PIN,
    patch_sha256=digest(output), new_files={p.relative_to(HERE).as_posix(): digest(p) for p in targets},
    license_sha256=digest(license_target), swift_compiled=False, xctest_executed=False,
    mac_runtime_executed=False, host_integration=False)
(HERE / "patch-provenance.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(json.dumps(manifest, indent=2))
