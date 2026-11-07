"""Run one ordinary-fleet counterexample with HEAD scan_service in memory.

The dirty checkout is never reset or rewritten. All other current code and
installed analyzers remain present, so this is a bounded baseline comparison.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types

import attackmap
import pytest

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
source = subprocess.check_output(["git", "-C", str(ROOT), "show", "HEAD:src/attackmap/scan_service.py"])
module = types.ModuleType("attackmap.scan_service")
module.__package__ = "attackmap"
module.__file__ = str(ROOT / "src/attackmap/scan_service.py")
sys.modules[module.__name__] = module
attackmap.scan_service = module
exec(compile(source, "<HEAD:src/attackmap/scan_service.py>", "exec"), module.__dict__)
(HERE / "baseline-identity.json").write_text(json.dumps({
    "scope": "HEAD scan_service loaded only in memory; all other current dirty source and installed analyzers retained",
    "head": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
    "head_scan_service_sha256": hashlib.sha256(source).hexdigest(),
    "current_scan_service_sha256": hashlib.sha256((ROOT / "src/attackmap/scan_service.py").read_bytes()).hexdigest(),
    "working_tree_rewritten": False,
}, indent=2) + "\n", encoding="utf-8")
raise SystemExit(pytest.main([
    str(ROOT / "tests/test_fleet_parallelism.py") + "::test_fleet_real_workers_match_serial[all]",
    "-q", "-p", "no:cacheprovider", "--tb=short",
    "--basetemp=C:/tmp/wp034-head-baseline-20261031",
    "--junitxml=" + str(HERE / "baseline.xml"),
]))
