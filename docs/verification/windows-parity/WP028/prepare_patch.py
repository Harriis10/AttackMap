"""Offline patch preparation; does not fetch, execute Swift, or alter shared fixtures."""
from pathlib import Path
import difflib
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PATCH = HERE / "mac-adapter-patch"
BASE = HERE / "pinned-base"
PIN = "5f2e8b4d84f9dff06e0f87c69c861a434981bd6a"
relative = Path("AttackMap/Services/CLILocator.swift")
expected_blob = "265bccaa895e71e2dcffbbfa637e45f34383cd74"
original = (BASE / relative).read_bytes()
# apply_patch may have appended one terminal newline to the retained response.
def blob(value):
    return hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()
for candidate in (original, original.rstrip(b"\r\n") + b"\n", original.rstrip(b"\r\n")):
    if blob(candidate) == expected_blob:
        original = candidate
        break
else:
    raise SystemExit("Pinned CLILocator Git blob mismatch; no patch emitted")
(BASE / relative).write_bytes(original)
fixtures = PATCH / "AttackMapTests/Fixtures/DesktopParity"
fixtures.mkdir(parents=True, exist_ok=True)
records = []
for name in ("request-current.json", "request-previous.json", "request-unsupported-major.json"):
    source = ROOT / "fixtures/desktop-parity" / name
    target = fixtures / name
    shutil.copyfile(source, target)
    records.append({"source": str(source.relative_to(ROOT)).replace("\\", "/"),
                    "destination": str(target.relative_to(PATCH)).replace("\\", "/"),
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
chunks = []
for target in sorted(PATCH.rglob("*.swift")):
    name = target.relative_to(PATCH).as_posix()
    before = (BASE / name).read_text(encoding="utf-8").splitlines(keepends=True) if (BASE / name).exists() else []
    after = target.read_text(encoding="utf-8").splitlines(keepends=True)
    chunks.extend(difflib.unified_diff(before, after, fromfile="a/" + name if before else "/dev/null", tofile="b/" + name))
for target in sorted(fixtures.glob("*.json")):
    chunks.extend(difflib.unified_diff([], target.read_text(encoding="utf-8").splitlines(keepends=True),
                                     fromfile="/dev/null", tofile="b/" + target.relative_to(PATCH).as_posix()))
(HERE / "mac-desktop-negotiation.patch").write_text("".join(chunks), encoding="utf-8", newline="\n")
manifest = {"repository": "https://github.com/mlaify/AttackMap-mac", "commit": PIN,
            "pinned_cliloc_git_blob": expected_blob, "verified_git_blob": blob(original),
            "shared_fixture_copies": records, "swift_compiled": False, "mac_runtime_executed": False,
            "patch_sha256": hashlib.sha256((HERE / "mac-desktop-negotiation.patch").read_bytes()).hexdigest()}
(HERE / "patch-provenance.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(json.dumps(manifest, indent=2))
