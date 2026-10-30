"""One focused NativeAiOptions console checkpoint; no GUI or provider calls."""
import json
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[6]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as h

project = ROOT / "desktop/windows/NativeAiOptions.Tests/NativeAiOptions.Tests.csproj"
paths = [project, *project.parent.glob("*.cs")]
paths.extend((project.parent / node.attrib["Include"]).resolve() for node in ET.parse(project).iter("Compile"))
paths.append(ROOT / "desktop/windows/AttackMap.NativeSpike/ProviderSettingsView.cs")

def snapshot():
    return {p.relative_to(ROOT).as_posix(): h.sha(p) for p in sorted(set(paths))}

def main():
    h.require(not (OUT / "inputs-before.json").exists(), "Fresh checkpoint required")
    before = snapshot()
    h.save(OUT / "inputs-before.json", before)
    h.save(OUT / "runner-identity.json", dict(runner=h.record(Path(__file__)), helper=h.record(Path(h.__file__))))
    environment = dict(os.environ, DOTNET_ROOT=str(ROOT / ".tools/dotnet"),
        DOTNET_ROOT_X64=str(ROOT / ".tools/dotnet"),
        DOTNET_CLI_HOME=str(ROOT / ".tools/dotnet-home"), NUGET_PACKAGES=str(ROOT / ".tools/nuget-packages"),
        DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1", MSBUILDDISABLENODEREUSE="1",
        TEMP=str(OUT / "temp"), TMP=str(OUT / "temp"))
    (OUT / "temp").mkdir()
    dotnet = ROOT / ".tools/dotnet/dotnet.exe"
    executable = project.parent / "bin/Debug/net8.0/NativeAiOptions.Tests.exe"
    commands = [dict(name="build", argv=[str(dotnet), "build", str(project), "--no-restore",
                   "-p:NuGetAudit=false", "-p:UseSharedCompilation=false", "-nodeReuse:false"], timeout=300),
                dict(name="tests", argv=[str(executable)], timeout=120)]
    h.save(OUT / "plan.json", dict(commands=commands,
           environment={k: environment[k] for k in ("DOTNET_ROOT", "DOTNET_CLI_HOME", "NUGET_PACKAGES", "TEMP", "TMP")},
           scope="Offline native console assertions only; no full WinUI build, GUI or provider"))
    completed, failure, assertion_count = [], None, 0
    try:
        for command in commands:
            folder = OUT / command["name"]
            folder.mkdir()
            h.launch(command["argv"], folder, environment, command["timeout"])
            process = h.read(folder / "process.json")
            h.require(process.get("exit_code") == 0 and process.get("timed_out") is False
                      and all(process.get(key) is True for key in
                              ("exited", "owned_job_assigned", "owned_tree_cleanup_verified")),
                      "Failed process/cleanup: " + command["name"])
            if command["name"] == "tests":
                stdout = (folder / "stdout.log").read_text(encoding="utf-8", errors="replace")
                match = re.search(r"^PASS (\d+) WP015 offline settings/capability/secret checks; zero engine/provider dispatches$", stdout, re.M)
                h.require(match is not None, "Missing explicit assertion count")
                assertion_count = int(match[1])
            completed.append(command["name"])
    except BaseException as error:
        failure = repr(error)
        raise
    finally:
        after = snapshot()
        h.save(OUT / "inputs-after.json", after)
        changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
        h.save(OUT / "summary.json", dict(passed=failure is None and not changed and completed == ["build", "tests"],
            failure=failure, completed=completed, changed_inputs=changed, assertion_count=assertion_count,
            artifacts=[h.record(p) for p in sorted(OUT.rglob("*")) if p.is_file() and p.suffix in (".log", ".json")],
            executable=h.record(executable) if executable.exists() else None,
            accepted_gui=False, accepted_live_provider=False, accepted_wp017=False, accepted_release=False))
        h.require(not changed, "Checkpoint source drift")

if __name__ == "__main__":
    main()
