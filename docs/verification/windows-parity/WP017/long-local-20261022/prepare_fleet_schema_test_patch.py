"""Prepare an unapplied test-file patch; imports standard library only."""
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[5]
TARGET = ROOT / "tests/test_fleet_schema_contract.py"
WATCHED = ("tests/test_run_contract.py", "src/attackmap/desktop_fleet.py", "schemas/run-fleet-request.schema.json")
def snapshot():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in WATCHED}

if TARGET.exists():
    raise RuntimeError("Proposed new test already exists in active tree")
before = snapshot()
source = '''"""Published fleet schema must track the complete deterministic model contract."""
import json
from pathlib import Path

from attackmap.desktop_fleet import FleetRunRequest


def test_published_fleet_request_schema_matches_model():
    root = Path(__file__).resolve().parents[1]
    actual = json.loads((root / "schemas/run-fleet-request.schema.json").read_text(encoding="utf-8"))
    expected = FleetRunRequest.model_json_schema()
    expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    assert actual == expected
'''
scratch = HERE / "fleet-schema-test-proposal-01"
scratch.mkdir(exist_ok=False)
(scratch / "test_fleet_schema_contract.proposed.py").write_text(source, encoding="utf-8", newline="\n")
patch = "".join(difflib.unified_diff([], source.splitlines(keepends=True),
    fromfile="/dev/null", tofile="b/tests/test_fleet_schema_contract.py"))
patch_path = HERE / "newlong-fleet-schema-test.patch"
if patch_path.exists():
    raise RuntimeError("Evidence patch already exists")
patch_path.write_text(patch, encoding="utf-8", newline="\n")
after = snapshot()
proof = dict(scope="Evidence-only new deterministic full fleet schema test; not applied/imported/executed",
    source_hashes_before=before, source_hashes_after=after, source_unchanged=before == after,
    active_new_test_absent=not TARGET.exists(), tests_executed=False,
    patch_sha256=hashlib.sha256(patch_path.read_bytes()).hexdigest())
(scratch / "source-hash-proof.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
if before != after or TARGET.exists():
    raise RuntimeError("Active tree changed")
print(json.dumps(proof, indent=2))
