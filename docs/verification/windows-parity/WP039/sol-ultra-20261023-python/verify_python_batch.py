"""Owned, bounded verification for the isolated Python analyzer slice."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
WORK = ROOT / ".tmp/wp039-python-20261023"
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as jobs


def run(label, command, *, source=None, timeout=600):
    folder = OUT / label
    folder.mkdir()
    command = [str(value) for value in command]
    env = jobs.child_environment(folder)
    env.update(PYTHONDONTWRITEBYTECODE="1", DOTNET_ROOT=str(ROOT / ".tools/dotnet"),
               DOTNET_CLI_HOME=str(ROOT / ".tools/dotnet-home"), NUGET_PACKAGES=str(ROOT / ".tools/nuget-packages"))
    if source is not None:
        env["PYTHONPATH"] = str(Path(source) / "src")
    jobs.save(folder / "command.json", dict(argv=command, source_override=str(source) if source else None))
    jobs.launch(command, folder, env, timeout)
    return folder


if __name__ == "__main__":
    operation = sys.argv[1]
    if operation == "baseline-juice":
        engine = ROOT / ".tmp/wp042-sol-ultra-20261023-batch2/engine-final/dist/attackmap/attackmap.exe"
        run("baseline-juice", [engine, "analyze", r"C:\tmp\juice-shop", "--format", "json", "--no-progress",
                               "--output", WORK / "baseline-juice"])
    elif operation == "source-baseline-juice":
        run("source-baseline-juice", [ROOT / ".venv/Scripts/python.exe", "-m", "attackmap", "analyze", r"C:\tmp\juice-shop",
            "--format", "json", "--no-progress", "--output", WORK / "source-baseline-juice"], source=WORK / "baseline-source")
    else:
        raise SystemExit("Unknown operation")
    print(json.dumps(dict(operation=operation, passed=True)))
