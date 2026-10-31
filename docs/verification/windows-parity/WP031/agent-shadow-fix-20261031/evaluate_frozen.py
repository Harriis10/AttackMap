"""Fresh post-correction offline CLI reports; never overwrite earlier evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

EVIDENCE = Path(__file__).resolve().parent
ROOT = EVIDENCE.parents[4]
EARLIER = EVIDENCE.parent / "agent-20261031"
assert len(sys.argv) == 1 or len(sys.argv) == 2 and sys.argv[1] in {"post-declarators", "final-scope-guard", "final-expression-guard", "final-binder-guard", "final-binder-spellings"}
OUT = EVIDENCE if len(sys.argv) == 1 else EVIDENCE / sys.argv[1]
OUT.mkdir(exist_ok=True)


def inventory() -> dict[str, str]:
    paths = list((ROOT / "fixtures/evaluation").rglob("*"))
    paths += list((ROOT / "src/attackmap").rglob("*.py"))
    paths += [ROOT / "tests/test_authz_bound_handlers.py"]
    return {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(set(paths)) if path.is_file()}


before = inventory()
runs = []
for name, corpus in (("increment", "fixtures/evaluation/increment-20261031/corpus.json"),
                     ("baseline", "fixtures/evaluation/corpus.json")):
    output = OUT / f"evaluation-{name}"
    assert not output.exists(), "Use a fresh corrective output path"
    command = [sys.executable, "-B", "-m", "attackmap", "evaluate", "--corpus", corpus, "--output", str(output)]
    started = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    (OUT / f"{name}-stdout.txt").write_text(result.stdout, encoding="utf-8")
    (OUT / f"{name}-stderr.txt").write_text(result.stderr, encoding="utf-8")
    report = output / "evaluation-report.json"
    previous = EARLIER / f"evaluation-{name}-qualified/evaluation-report.json"
    runs.append({"command": command, "exit_code": result.returncode,
                 "seconds": round(time.monotonic() - started, 3),
                 "exact_json_equal_to_pre_correction_report": report.is_file() and
                     json.loads(report.read_text(encoding="utf-8")) == json.loads(previous.read_text(encoding="utf-8"))})
after = inventory()
freeze = json.loads((EARLIER / "preimplementation-freeze.json").read_text(encoding="utf-8-sig"))
frozen_unchanged = all(before.get(row["path"]) == row["sha256"] for row in freeze["frozen_inputs"])
proof = {"runs": runs, "before": before, "after": after,
         "inputs_and_sources_unchanged_during_runs": before == after,
         "original_frozen_increment_exactly_unchanged": frozen_unchanged, "provider_calls": 0}
(OUT / "evaluation-execution.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
print(json.dumps({key: value for key, value in proof.items() if key not in {"before", "after"}}, indent=2))
assert before == after and frozen_unchanged
assert all(run["exit_code"] == 0 for run in runs)
