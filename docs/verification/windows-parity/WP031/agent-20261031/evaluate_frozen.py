"""Record actual offline CLI runs and immutable input/source identities."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent


def inventory() -> dict[str, str]:
    paths = list((ROOT / "fixtures/evaluation/increment-20261031").rglob("*"))
    paths += list((ROOT / "src/attackmap").rglob("*.py"))
    paths += [ROOT / "fixtures/evaluation/corpus.json", ROOT / "tests/test_authz_bound_handlers.py"]
    return {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(set(paths)) if path.is_file()}


before = inventory()
runs = []
for name, corpus in (("increment", "fixtures/evaluation/increment-20261031/corpus.json"),
                     ("baseline", "fixtures/evaluation/corpus.json")):
    command = [sys.executable, "-B", "-m", "attackmap", "evaluate", "--corpus", corpus,
               "--output", str(OUT / f"evaluation-{name}-qualified")]
    start = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    (OUT / f"{name}-stdout.txt").write_text(result.stdout, encoding="utf-8")
    (OUT / f"{name}-stderr.txt").write_text(result.stderr, encoding="utf-8")
    runs.append({"command": command, "exit_code": result.returncode,
                 "elapsed_seconds": round(time.monotonic() - start, 3)})
after = inventory()
freeze = json.loads((OUT / "preimplementation-freeze.json").read_text(encoding="utf-8-sig"))
frozen_unchanged = all(before.get(row["path"]) == row["sha256"] for row in freeze["frozen_inputs"])
proof = {"runs": runs, "before": before, "after": after, "inputs_and_sources_unchanged_during_runs": before == after,
         "original_frozen_increment_exactly_unchanged": frozen_unchanged, "live_provider_calls": 0}
(OUT / "evaluation-execution.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
assert before == after and frozen_unchanged
assert all(run["exit_code"] == 0 for run in runs)
print(json.dumps({key: value for key, value in proof.items() if key not in {"before", "after"}}, indent=2))
