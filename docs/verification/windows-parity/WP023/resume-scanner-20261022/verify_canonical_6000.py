"""Re-run explicit linear versus current indexed lookup; never reuse old output."""
from pathlib import Path
import hashlib
import json
import sys
import time

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "src"))
from attackmap import taint_flow
from attackmap.scanner import scan_repo


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def linear(self, line):
    best = None
    best_start = -1
    for start, end, node in self.funcs:
        if start <= line <= end and start > best_start:
            best, best_start = node, start
    return best


output = Path(sys.argv[1]).resolve()
if output.exists():
    raise FileExistsError("Use a fresh result path; retained evidence must not be overwritten.")
fixture = ROOT / ".tmp/wp023-perf-profile-20261021-01/many_matches"
inputs = {str(path.relative_to(ROOT)): sha(path)
          for path in sorted((ROOT / "src/attackmap").rglob("*.py"))}
fixture_inputs = {str(path.relative_to(fixture)): sha(path)
                  for path in sorted(fixture.rglob("*")) if path.is_file()}
indexed = taint_flow._PyFlow._enclosing
records, outputs = [], []
try:
    for name, lookup in (("explicit_original_linear", linear), ("current_canonical_index", indexed)):
        taint_flow._PyFlow._enclosing = lookup
        started, cpu = time.perf_counter(), time.process_time()
        scan = scan_repo(fixture)
        data = scan.model_dump(mode="json")
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        assert len(scan.routes) == len(scan.external_calls) == 6000
        records.append({"lookup": name, "wall_seconds": time.perf_counter() - started,
                        "cpu_seconds": time.process_time() - cpu,
                        "routes": len(scan.routes), "external_calls": len(scan.external_calls),
                        "scan_result_sha256": hashlib.sha256(payload).hexdigest()})
        outputs.append(data)
finally:
    taint_flow._PyFlow._enclosing = indexed
assert outputs[0] == outputs[1], "Full ScanResult changed"
assert inputs == {str(path.relative_to(ROOT)): sha(path)
                  for path in sorted((ROOT / "src/attackmap").rglob("*.py"))}, "Source inputs changed"
assert fixture_inputs == {str(path.relative_to(fixture)): sha(path)
                          for path in sorted(fixture.rglob("*")) if path.is_file()}, "Fixture changed"
result = {"passed": True, "equal_full_scan_result": True, "records": records,
          "source_inputs": inputs, "fixture_inputs": fixture_inputs,
          "source_inputs_unchanged": True, "fixture_inputs_unchanged": True,
          "scope": "One local fixture, explicit original lookup and current canonical index; no broad performance claim"}
with output.open("x", encoding="utf-8") as stream:
    json.dump(result, stream, indent=2)
    stream.write("\n")
print(json.dumps({"passed": True, "records": records}, indent=2))
