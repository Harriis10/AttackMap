"""Extract pure harness JSON without discarding first-run SDK stdout."""
import hashlib
import json
from pathlib import Path

here = Path(__file__).resolve().parent
raw_path = here / "harness/harness-results.json"
raw = raw_path.read_bytes()
text = raw.decode("utf-8-sig")
start = text.index('\n{') + 1 if not text.startswith("{") else 0
result = json.loads(text[start:])
assert result["passed"] is True
assert result["assertions"] == 579 and result["cases"] == 123
with (here / "results.json").open("x", encoding="utf-8", newline="\n") as stream:
    json.dump(result, stream, indent=2)
    stream.write("\n")
pins = json.loads((here / "pins.json").read_text())
summary = {
    "passed": True,
    "process_exit_code": 0,
    "assertions": result["assertions"],
    "scenario_cases": result["cases"],
    "variants": ["Baseline", "Core", "Optional"],
    "raw_stdout": str(raw_path.relative_to(here)),
    "raw_stdout_sha256": hashlib.sha256(raw).hexdigest(),
    "raw_stdout_prefix": "Preserved initial SDK first-run text; pure parsed result saved separately",
    "stderr_bytes": (here / "harness/harness-stderr.txt").stat().st_size,
    "results_sha256": hashlib.sha256((here / "results.json").read_bytes()).hexdigest(),
    "core_patch_sha256": pins["artifacts_sha256"]["core.patch"],
    "optional_patch_sha256": pins["artifacts_sha256"]["optional-after-core.patch"],
    "preimage_sha256": pins["preimage_sha256"],
    "native_window": False,
    "actual_winui_cleanup": False,
    "crash_reproduction": False,
    "provider_or_model": False,
    "build_scope": "Fresh isolated net8 console only; repository SDK, package sources cleared, no external package references",
}
with (here / "test-summary.json").open("x", encoding="utf-8", newline="\n") as stream:
    json.dump(summary, stream, indent=2)
    stream.write("\n")
print(json.dumps(summary, indent=2))
