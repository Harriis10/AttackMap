from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[6]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as harness

profile_root = HERE / "isolated"
profile_root.mkdir()
environment = harness.child_environment(profile_root)
arguments = [str(ROOT / ".tools/dotnet/dotnet.exe"), str(HERE / "bin/Release/net8.0/KnownFolderProbe.dll")]
for phase in ("before", "after"):
    if phase == "after":
        for name in ("Local", "Roaming"):
            (profile_root / "profile/AppData" / name).mkdir(parents=True)
    output = HERE / phase
    output.mkdir()
    harness.launch(arguments, output, environment, 30)
    result = json.loads((output / "stdout.log").read_text(encoding="utf-8"))
    (output / "resolved-paths.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(phase, json.dumps(result))
