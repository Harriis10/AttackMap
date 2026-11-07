"""Evidence-only schema proposal; standard library only, no model imports."""
import copy
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[5]
SCRATCH = HERE / "schema-budget-proposal-01"
SCRATCH.mkdir(exist_ok=False)
FILES = {
    "schemas/run-request.schema.json": ("ProviderOptions", "ProviderOptionsV13"),
    "schemas/run-fleet-request.schema.json": ("ProviderOptionsV13",),
}
def sha(data):
    return hashlib.sha256(data).hexdigest()

before = {name: sha((ROOT / name).read_bytes()) for name in FILES}
patch = ""
needle = '"timeout_seconds": {\n          "default": 600,\n          "maximum": 3600,'
replacement = needle.replace('"maximum": 3600', '"maximum": 7200')
for name, definitions in FILES.items():
    original = (ROOT / name).read_text(encoding="utf-8")
    parsed = json.loads(original)
    expected = copy.deepcopy(parsed)
    for definition in definitions:
        timeout = expected["$defs"][definition]["properties"]["timeout_seconds"]
        if timeout["maximum"] != 3600 or timeout["default"] != 600:
            raise RuntimeError("Unexpected schema before value")
        timeout["maximum"] = 7200
    if original.count(needle) != len(definitions):
        raise RuntimeError("Ambiguous schema text edits")
    proposed = original.replace(needle, replacement)
    if json.loads(proposed) != expected:
        raise RuntimeError("Unrelated schema metadata changed")
    (SCRATCH / (Path(name).name + ".before")).write_text(original, encoding="utf-8", newline="\n")
    (SCRATCH / (Path(name).name + ".proposed")).write_text(proposed, encoding="utf-8", newline="\n")
    patch += "".join(difflib.unified_diff(original.splitlines(keepends=True), proposed.splitlines(keepends=True),
        fromfile="a/" + name, tofile="b/" + name))
patch_path = HERE / "newlong-budget-schema.patch"
if patch_path.exists():
    raise RuntimeError("Refuse replacing schema patch")
patch_path.write_text(patch, encoding="utf-8", newline="\n")
after = {name: sha((ROOT / name).read_bytes()) for name in FILES}
proof = dict(scope="Evidence-only schema unified diff; no active writes or model imports/tests",
    source_hashes_before=before, source_hashes_after=after, source_unchanged=before == after,
    patch_sha256=sha(patch_path.read_bytes()), changed_fields=3, unrelated_metadata_unchanged=True,
    generated_model_equality_executed=False, tests_executed=False)
(SCRATCH / "source-hash-proof.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
if before != after:
    raise RuntimeError("Active schema files changed")
print(json.dumps(proof, indent=2))
