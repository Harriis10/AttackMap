import hashlib
import json
from pathlib import Path
import shutil

root = Path.cwd()
source = root / "desktop/windows/artifacts/AttackMap-Windows-Portable-20261022-startscan-fix/AttackMap-Windows"
archive = source.parent.with_suffix(".zip")
finished = Path(r"C:\Projects\FINISHED")
staged = finished / "AttackMap-Windows-Portable-20261022-startscan-fix-staged"
staged_zip = finished / "AttackMap-Windows-Portable-20261022-startscan-fix-staged.zip"
proof = root / "docs/verification/windows-parity/WP024/startscan-fix-20261022"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


for parent in (finished, *finished.parents):
    assert not parent.lstat().st_file_attributes & 0x400
assert staged.parent == finished and not staged.exists() and not staged_zip.exists()
manifest = json.loads((source / "portable-manifest.json").read_text())
assert manifest["startup_engine_selection"] == "bundled_on_portable_startup"
runtime = json.loads((proof / "normal-startup/normal-startup.json").read_text())["result"]
assert runtime["passed"] and runtime["scanCompleted"] and runtime["settingsFilePreserved"]
for filename, field in (("AttackMap.NativeSpike.exe", "nativeExeSha256"), ("AttackMap.NativeSpike.dll", "nativeDllSha256"), ("engine/attackmap.exe", "engineSha256")):
    assert sha(source / filename) == runtime[field]
assert sha(archive) == "79a14e259707f89c12a2327798af7365e2da0da85aaaac78ae3dd8e143ef80dd"
shutil.copytree(source, staged)
with archive.open("rb") as incoming, staged_zip.open("xb") as outgoing:
    shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
expected = set(manifest["files"]) | {"portable-manifest.json"}
assert {path.relative_to(staged).as_posix() for path in staged.rglob("*") if path.is_file()} == expected
for name in expected:
    assert sha(staged / name) == sha(source / name), name
assert sha(staged_zip) == sha(archive)
result = {"passed": True, "staged": str(staged), "staged_zip": str(staged_zip), "source": str(source),
    "files_verified": len(expected), "zip_sha256": sha(staged_zip), "native_build": manifest["native_build"],
    "native_exe_sha256": runtime["nativeExeSha256"], "native_dll_sha256": runtime["nativeDllSha256"],
    "engine_sha256": runtime["engineSha256"], "release_candidate": False}
(proof / "staged-copy.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2))
