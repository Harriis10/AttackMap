import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("phase", choices=["before", "after"])
parser.add_argument("evidence")
parser.add_argument("publish")
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
evidence = Path(args.evidence).resolve()
evidence.relative_to(root)
evidence.mkdir(parents=True, exist_ok=True)
project = root / "desktop/windows/AttackMap.NativeSpike"
paths = [p for p in project.rglob("*") if p.is_file() and not {"bin", "obj"}.intersection(p.relative_to(project).parts) and p.suffix in {".cs", ".xaml", ".csproj", ".manifest", ".props", ".targets"}]
paths.append(root / "desktop/windows/fixtures/findings.json")
assets = project / "obj/project.assets.json"
if assets.exists():
    paths.append(assets)
hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
document = {"captured_utc": datetime.now(timezone.utc).isoformat(), "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(), "inputs": hashes, "scope": "Native project sources, linked fixture and resolved NuGet assets; dirty source tree explicitly fingerprinted. Not frozen engine, signing or manual acceptance."}
if args.phase == "after":
    before = json.loads((evidence / "build-inputs-before.json").read_text())
    document["inputs_unchanged"] = before["inputs"] == hashes
    publish = Path(args.publish).resolve()
    document["artifacts"] = {name: {"sha256": hashlib.sha256((publish / name).read_bytes()).hexdigest(), "bytes": (publish / name).stat().st_size} for name in ("AttackMap.NativeSpike.exe", "AttackMap.NativeSpike.dll") if (publish / name).exists()}
target = evidence / f"build-inputs-{args.phase}.json"
with target.open("x", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2)
print(json.dumps({"phase": args.phase, "source_files": len(hashes), "inputs_unchanged": document.get("inputs_unchanged"), "artifacts": list(document.get("artifacts", {}))}))
