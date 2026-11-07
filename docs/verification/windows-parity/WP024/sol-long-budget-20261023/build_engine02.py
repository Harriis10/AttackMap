"""Run the existing immutable freeze inside one owned Windows Job."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as native


if __name__ == "__main__":
    output = Path(__file__).resolve().parent / "freeze-command02"
    freeze = ROOT / ".tmp/wp024-sol-long-budget-20261023-02"
    native.require(not output.exists() and not freeze.exists(), "Use fresh evidence and freeze directories")
    output.mkdir()
    environment = native.child_environment(output)
    environment.update(DOTNET_ROOT=str(ROOT / ".tools/dotnet"),
        DOTNET_CLI_HOME=str(ROOT / ".tools/dotnet-home"), PYTHONDONTWRITEBYTECODE="1")
    arguments = [str(ROOT / ".venv/Scripts/python.exe"),
        str(ROOT / "docs/verification/windows-parity/WP024/fresh_freeze.py"), "--root-released",
        "--repo", str(ROOT), "--output", str(freeze),
        "--freeze-python", str(ROOT / ".tools/wp024-freeze-venv/Scripts/python.exe"),
        "--dotnet", str(ROOT / ".tools/dotnet/dotnet.exe"),
        "--analyzer-audit", str(ROOT / "docs/verification/windows-parity/WP024/cached-analyzer-audit-2026-10-21.json"),
        "--wheelhouse", str(ROOT / ".tools/wp024-wheelhouse"), "--build"]
    native.save(output / "command.json", arguments)
    native.launch(arguments, output, environment, 1200)
    proof = native.read(freeze / "build-proof.json")
    print(json.dumps(dict(frozen=True, freeze=str(freeze), engine_sha256=proof["exe_sha256"],
        runtime_verified=False)))
