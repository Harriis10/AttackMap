"""Process-local Windows ACL workaround and explicit scope-guard RED switch."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[4]
stage = sys.argv[1]
assert stage in {"red", "focused", "focused-final", "declarator-red", "focused-final2", "focused-final3", "focused-final4", "parameter-red", "focused-final5", "generator-red", "focused-final6", "focused-final7"}
original_mkdir = os.mkdir


def inherited_mkdir(path, mode=0o777, *, dir_fd=None):
    # Python 3.13's Windows mode=0700 ACL excludes the restricted test identity.
    # This only changes directory creation in this short-lived test process.
    return original_mkdir(path, 0o777, dir_fd=dir_fd)


os.mkdir = inherited_mkdir
if stage == "red":
    import attackmap.authz_js_handlers as handlers
    # Reproduce the previous resolver's missing enclosing-scope veto without
    # modifying/restoring any file in this shared checkout.
    handlers._scope_preserves_import = lambda *_args: True

import pytest

arguments = ["tests/test_authz_bound_handlers.py"]
if stage == "red":
    arguments += ["-k", "lexically_shadowed or unshadowed_import or local_declarations"]
elif stage == "declarator-red":
    arguments += ["-k", "later_destructuring_declarators"]
elif stage == "parameter-red":
    arguments += ["-k", "default_parameter_registration or unshadowed_multiline_registration"]
elif stage == "generator-red":
    arguments += ["-k", "later_destructuring_declarators and function"]
else:
    arguments += ["tests/test_authz.py", "tests/test_route_auth_fusion.py", "tests/test_recall.py",
                  "tests/test_snapshot_consistency.py", "tests/test_evaluation.py", "tests/test_evaluation_increment.py"]
arguments += ["-q", "-p", "no:cacheprovider", "--basetemp", str(OUT / ("pytest-" + stage + "-qualified-01")),
              "--junitxml", str(OUT / (stage + "-qualified-final.xml"))]
start = time.monotonic()
result = pytest.main(arguments)
(OUT / (stage + "-execution.json")).write_text(json.dumps({
    "command": [sys.executable, "-B", str(Path(__file__)), stage],
    "pytest_arguments": arguments,
    "scope_guard_disabled_in_process": stage == "red",
    "directory_mode_workaround_in_process": "os.mkdir mode=0777; no source/harness changes",
    "exit_code": int(result), "seconds": round(time.monotonic() - start, 3), "provider_calls": 0,
}, indent=2) + "\n", encoding="utf-8")
raise SystemExit(result)
