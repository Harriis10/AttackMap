"""Compare retained immutable sources, installed package and cached wheel bytes."""
from pathlib import Path
import difflib
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
manifest = json.loads((OUT / "upstream-fetch.json").read_text(encoding="utf-8"))
roots = {key: Path(value["source_root"]) for key, value in manifest["archives"].items()}
packages = {key: root / "src/attackmap_analyzer_python" for key, root in roots.items()}
installed = ROOT / ".tools/wp024-freeze-venv/Lib/site-packages/attackmap_analyzer_python"
wheel = ROOT / ".tools/wp024-wheelhouse/attackmap_analyzer_python-0.1.0-py3-none-any.whl"
rows = {}
with zipfile.ZipFile(wheel) as archive:
    for path in sorted(packages["pinned"].rglob("*.py")):
        relative = path.relative_to(packages["pinned"]).as_posix()
        expected, observed, cached = path.read_bytes(), (installed / relative).read_bytes(), archive.read("attackmap_analyzer_python/" + relative)
        rows[relative] = {"pinned_sha256": hashlib.sha256(expected).hexdigest(),
            "installed_sha256": hashlib.sha256(observed).hexdigest(), "wheel_sha256": hashlib.sha256(cached).hexdigest(),
            "exact_match": expected == observed == cached,
            "installed_cached_wheel_exact_match": observed == cached,
            "pinned_installed_equal_after_crlf_to_lf_only": expected.replace(b"\r\n", b"\n") == observed.replace(b"\r\n", b"\n")}
inventories = {label: {path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in sorted(package.rglob("*.py"))} for label, package in packages.items()}
changes = {}
for label in ("candidate", "main_observed"):
    changed = []
    for relative in sorted(set(inventories["pinned"]) | set(inventories[label])):
        before, after = packages["pinned"] / relative, packages[label] / relative
        old = before.read_text(encoding="utf-8") if before.exists() else ""
        new = after.read_text(encoding="utf-8") if after.exists() else ""
        if old != new:
            changed.append(relative)
            (OUT / f"pinned-vs-{label}-{relative.replace('/', '_')}.diff").write_text("".join(difflib.unified_diff(
                old.splitlines(keepends=True), new.splitlines(keepends=True), fromfile="pinned/" + relative, tofile=label + "/" + relative)), encoding="utf-8")
    changes[label] = changed
proof = {"package_files": rows, "all_package_python_files_match_pinned_source_and_cached_wheel": all(row["exact_match"] for row in rows.values()),
         "all_installed_package_python_files_match_cached_wheel_bytes": all(row["installed_cached_wheel_exact_match"] for row in rows.values()),
         "all_installed_package_python_text_matches_pin_after_crlf_to_lf_only": all(row["pinned_installed_equal_after_crlf_to_lf_only"] for row in rows.values()),
         "cached_wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(), "source_roots": {key: str(root) for key, root in roots.items()},
         "source_package_inventories": inventories, "changed_package_files": changes,
         "plugin_entrypoint": "attackmap_analyzer_python:PythonAnalyzer"}
(OUT / "installed-pin-byte-comparison.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
assert proof["all_installed_package_python_files_match_cached_wheel_bytes"]
assert proof["all_installed_package_python_text_matches_pin_after_crlf_to_lf_only"]
print(json.dumps({"installed_matches_pin_after_line_endings_only": True, "changed_files": changes, "observed_main": manifest["api"]["main_observed"].get("commit")}, indent=2))
