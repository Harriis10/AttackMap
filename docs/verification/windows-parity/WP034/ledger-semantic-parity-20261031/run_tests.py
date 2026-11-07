"""Record scoped pytest evidence with the existing host-only temp ACL workaround."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
SOURCE = ROOT / "tests/test_fleet_parallelism.py"


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    label, *arguments = sys.argv[1:]
    if label == "snapshot":
        (OUT / "test_fleet_parallelism.before.py.txt").write_bytes(SOURCE.read_bytes())
        raise SystemExit(0)
    if label == "worker":
        import pytest

        original_mkdir = os.mkdir

        def compatible_mkdir(path, mode=0o777, *args, **kwargs):
            return original_mkdir(path, 0o777 if mode == 0o700 else mode, *args, **kwargs)

        os.mkdir = compatible_mkdir
        temp = ROOT / "artifacts/wp034-ledger-semantic-parity-20261031/process-temp"
        temp.mkdir(parents=True, exist_ok=True)
        for name in ("TEMP", "TMP", "TMPDIR"):
            os.environ[name] = str(temp)
        raise SystemExit(pytest.main(arguments))
    junit = OUT / f"{label}.xml"
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "worker", *arguments,
               "--junitxml", str(junit)]
    before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    started = time.monotonic()
    save(f"{label}.command.json", {"command": command, "cwd": str(ROOT),
                                  "test_file_sha256_before": before})
    with (OUT / f"{label}.txt").open("xb") as output:
        result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                timeout=900, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    counts = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    if junit.exists():
        for suite in ET.parse(junit).getroot().iter("testsuite"):
            for key in counts:
                counts[key] += int(suite.get(key, "0"))
    counts["passed"] = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    summary = {"exit_code": result.returncode, "seconds": round(time.monotonic() - started, 3),
               "counts": counts, "test_file_sha256_before": before,
               "test_file_sha256_after": hashlib.sha256(SOURCE.read_bytes()).hexdigest()}
    save(f"{label}.summary.json", summary)
    print(json.dumps(summary, indent=2))
    print((OUT / f"{label}.txt").read_text(encoding="utf-8", errors="replace")[-10000:])
    raise SystemExit(result.returncode)
