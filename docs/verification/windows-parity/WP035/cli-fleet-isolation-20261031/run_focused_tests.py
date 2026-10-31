"""Host-only pytest temp ACL workaround; no production code is patched."""
from pathlib import Path
import os
import sys

import pytest


original_mkdir = os.mkdir


def compatible_mkdir(path, mode=0o777, *args, **kwargs):
    return original_mkdir(path, 0o777 if mode == 0o700 else mode, *args, **kwargs)


os.mkdir = compatible_mkdir
temp = Path("artifacts/wp035-cli-isolation-20261031/process-temp").resolve()
temp.mkdir(parents=True, exist_ok=True)
for name in ("TEMP", "TMP", "TMPDIR"):
    os.environ[name] = str(temp)

raise SystemExit(pytest.main(sys.argv[1:]))
