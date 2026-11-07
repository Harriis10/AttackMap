"""One bounded offline replay on copied retained pixels; never launch native UI."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
START = time.monotonic()
OUT = Path(__file__).resolve().parent
GUI = OUT.parent
ORIGIN = GUI / "sol-newcandidate-capture-01" / "capture"
GUARD = GUI / "run-gui-checkpoint.py"
PIN = "ca465bd99194112e77a25eaabd9858687ad6a1dbbbe7191facc1c4e32b268afb"
WARNINGS = [
    "Derived offline guard replay of existing pixels; no new native run, renderer, GUI, provider, scan or build.",
    "Original failed native campaign remains failed and unmodified; this is not retroactive native PASS.",
    "Pixel validation is not visual acceptance. Blank controls on large Dark Diagrams/detail captures and stale navigation indicators remain open.",
    "No WP017/WP023, accessibility, candidate or release acceptance is claimed.",
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(name, value):
    with (OUT / name).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def snapshot(folder):
    return {path.relative_to(folder).as_posix(): digest(path)
            for path in sorted(folder.rglob("*")) if path.is_file()}


def main():
    assert digest(GUARD) == PIN, "Guard differs from frozen review pin"
    origin_before = snapshot(ORIGIN)
    save("original-tree-before.json", origin_before)
    target = OUT / "captures"
    target.mkdir()
    manifest_path = ORIGIN / "capture-manifest.json"
    proof = json.loads(manifest_path.read_bytes())
    records = copy.deepcopy(proof["captures"])
    assert len(records) == 56
    mapping = []
    for original_record, derived_record in zip(proof["captures"], records):
        original = Path(original_record["OutputPath"])
        assert original.parent == ORIGIN and original.is_file()
        assert digest(original) == original_record["Sha256"]
        copied = target / original.name
        with copied.open("xb") as stream:
            stream.write(original.read_bytes())
        derived_record["OutputPath"] = str(copied)
        assert {key: value for key, value in derived_record.items() if key != "OutputPath"} == {
            key: value for key, value in original_record.items() if key != "OutputPath"}
        mapping.append(dict(original=str(original), copy=str(copied), kind="png",
                            original_sha256=digest(original), copy_sha256=digest(copied)))
        sidecar = original.with_name(original.name + ".rows.json")
        if sidecar.exists():
            copied_sidecar = target / sidecar.name
            with copied_sidecar.open("xb") as stream:
                stream.write(sidecar.read_bytes())
            mapping.append(dict(original=str(sidecar), copy=str(copied_sidecar), kind="row-diagnostics",
                                original_sha256=digest(sidecar), copy_sha256=digest(copied_sidecar)))
    with (OUT / "original-capture-manifest.json").open("xb") as stream:
        stream.write(manifest_path.read_bytes())
    derived = copy.deepcopy(proof)
    derived["captures"] = records
    save("derived-capture-manifest.json", derived)
    save("copy-provenance.json", dict(original_manifest=str(manifest_path),
         original_manifest_sha256=digest(manifest_path), copied_manifest_sha256=digest(OUT / "original-capture-manifest.json"),
         derivation="Only captures[].OutputPath changed, pointing at byte-identical copies; diagnostic sidecars copied unchanged.",
         mappings=mapping, warnings=WARNINGS))
    copy_before = snapshot(target)
    save("copy-inputs-before.json", copy_before)
    assert all(row["original_sha256"] == row["copy_sha256"] for row in mapping)
    spec = importlib.util.spec_from_file_location("frozen_capture_guard_replay", GUARD)
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    assert digest(GUARD) == PIN
    native_png_pixels = guard.png_pixels

    def bounded_pixels(encoded):
        assert time.monotonic() - START < 540, "Offline replay deadline reached"
        result = native_png_pixels(encoded)
        assert time.monotonic() - START < 540, "Offline replay deadline reached"
        return result

    guard.png_pixels = bounded_pixels
    error, validated = None, None
    try:
        validated = guard.captures_check(records, target,
            {"Architecture", "Inventory", "Reports", "Settings", "FindingDetail"})
    except Exception as failure:
        error = repr(failure)
    origin_after = snapshot(ORIGIN)
    copy_after = {name: digest(target / name) for name in copy_before}
    save("original-tree-after.json", origin_after)
    save("copy-inputs-after.json", copy_after)
    passed = (error is None and validated["passed"] and origin_before == origin_after
              and copy_before == copy_after and digest(GUARD) == PIN)
    result = dict(passed=passed, scope="derived offline guard replay only", error=error,
         guard_sha256=digest(GUARD), original_manifest_sha256=digest(manifest_path),
         original_tree_unchanged=origin_before == origin_after, copied_inputs_unchanged=copy_before == copy_after,
         png_copies=sum(row["kind"] == "png" for row in mapping),
         sidecar_copies=sum(row["kind"] == "row-diagnostics" for row in mapping),
         byte_identical_mappings=all(digest(Path(row["original"])) == digest(Path(row["copy"])) == row["original_sha256"] for row in mapping),
         captures_measured=len(validated["measured"]) if validated else None,
         seconds=time.monotonic() - START, warnings=WARNINGS,
         gui_runs=0, provider_requests=0, engine_runs=0, builds=0, visual_review_performed=False,
         accepted_native_run=False, accepted_wp017=False, accepted_wp023=False,
         accepted_accessibility=False, accepted_release=False)
    save("result.json", result)
    print(json.dumps(result, indent=2), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
