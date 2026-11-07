"""Independent captured-source native builds; never builds the moving fleet tree."""
from pathlib import Path
import hashlib
import json
import shutil
import sys
import xml.etree.ElementTree as ET

from verify_python_batch import ROOT, OUT, WORK, run


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unit(label):
    snapshot = WORK / label / "source"
    snapshot.mkdir(parents=True)
    project = Path("desktop/windows/ScanProgress.Tests/ScanProgress.Tests.csproj")
    files = [project, project.with_name("Program.cs")]
    for node in ET.parse(ROOT / project).findall(".//Compile"):
        files.append((ROOT / project.parent / node.attrib["Include"]).resolve().relative_to(ROOT))
    inputs = {str(path): sha(ROOT / path) for path in files}
    for path in files:
        target = snapshot / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
        assert sha(target) == inputs[str(path)]
    assert inputs == {str(path): sha(ROOT / path) for path in files}
    empty_feed = WORK / label / "empty-feed"
    empty_feed.mkdir()
    dotnet = ROOT / ".tools/dotnet/dotnet.exe"
    run(label + "-restore", [dotnet, "restore", snapshot / project, "--source", empty_feed,
                            "--ignore-failed-sources", "-p:NuGetAudit=false"])
    run(label + "-build", [dotnet, "build", snapshot / project, "--no-restore",
                           "-p:NuGetAudit=false", "-p:UseSharedCompilation=false", "-nodeReuse:false"])
    folder = run(label, [dotnet, snapshot / project.parent / "bin/Debug/net8.0/ScanProgress.Tests.dll"])
    proof = dict(inputs=inputs, source=str(snapshot), passed=True,
                 scope="Native console model checks; no visual acceptance")
    (folder / "build-proof.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")


if __name__ == "__main__":
    unit(sys.argv[1])
