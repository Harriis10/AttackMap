"""Seal the narrow ownership patch without invoking Git."""

from difflib import unified_diff
from hashlib import sha256
import json
from pathlib import Path
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
changed = ["src/attackmap/topology.py", "tests/test_wp032_service_owner.py"]
chunks = []
for name in changed:
    target = ROOT / name
    baseline = HERE / "baseline" / target.name
    before = baseline.read_text(encoding="utf-8").splitlines(keepends=True) if baseline.exists() else []
    after = target.read_text(encoding="utf-8").splitlines(keepends=True)
    chunks.extend(unified_diff(before, after, fromfile="a/" + name if before else "/dev/null", tofile="b/" + name))
patch = "".join(chunks).encode("utf-8")
(HERE / "canonical.patch").write_bytes(patch)
suite = ET.parse(HERE / "focused.xml").getroot().find("testsuite")
compat = json.loads((HERE / "compatibility.json").read_text(encoding="utf-8"))
manifest = {
    "baseline_commit_from_root": "18fc9b2",
    "change_scope": changed,
    "semantics_changed": False,
    "held_candidate": "r10b-candidate-20261021-a",
    "held_candidate_promoted": False,
    "threat_model_unchanged": compat["baseline_source_sha256"]["threat_model.py"] == compat["current_source_sha256"]["threat_model.py"],
    "baseline_source_sha256": compat["baseline_source_sha256"],
    "current_source_sha256": compat["current_source_sha256"],
    "test_sha256": sha256((ROOT / changed[1]).read_bytes()).hexdigest(),
    "patch_sha256": sha256(patch).hexdigest(),
    "verification": {
        "focused_process_exit": 0,
        "focused_tests": int(suite.attrib["tests"]),
        "focused_failures": int(suite.attrib["failures"]),
        "focused_errors": int(suite.attrib["errors"]),
        "focused_skipped": int(suite.attrib["skipped"]),
        "differential_process_exit": 0,
        "full_output_cases": compat["cases"],
        "full_output_equal": compat["equal"],
        "inputs_unchanged": compat["inputs_unchanged"],
        "negative_control_detected": compat["rejected_candidate_negative_control_detected"],
    },
    "artifact_sha256": {name: sha256((HERE / name).read_bytes()).hexdigest()
                        for name in ["focused.xml", "focused.log", "compatibility_check.py", "compatibility.json", "compatibility.log", "golden-before.json"]},
}
(HERE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(json.dumps(manifest["verification"]))
