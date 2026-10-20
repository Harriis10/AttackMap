"""Collect retained fake-provider matrix artifacts; performs no scan or provider request."""
import argparse
import hashlib
import json
from pathlib import Path

from attackmap.artifact_publisher import current_generation, validate_generation
from attackmap.desktop_ai import MODES

parser=argparse.ArgumentParser()
parser.add_argument("--temp-root",type=Path,required=True)
args=parser.parse_args()
roots=[path for path in args.temp_root.glob("test_dispatch_matrix*")
       if path.is_dir() and not path.name.endswith("current")]
assert len(roots)==1,roots
rows=[]
for mode in MODES:
    folder=current_generation(roots[0]/mode)
    assert folder is not None,mode
    validate_generation(folder)
    findings=(folder/"findings.json").read_bytes()
    manifest=json.loads((folder/"run-manifest.json").read_text(encoding="utf-8"))
    outcome=manifest["desktop_ai"]
    rows.append({"mode":mode,"folder":str(folder),"findings_sha256":hashlib.sha256(findings).hexdigest(),
                 "findings_bytes":len(findings),"status":outcome["status"],
                 "model_output_available":outcome["model_output_available"],
                 "artifact":outcome.get("artifact"),"metadata_artifact":outcome.get("metadata_artifact"),
                 "allowance":manifest.get("ai_allowance"),"service_parameters":outcome.get("service_parameters")})
assert len({row["findings_sha256"] for row in rows})==1
output={"scope":"Deterministic fake SDK matrix only; no live HTTP, provider authentication, native UI or runtime acceptance",
        "findings_hash_invariant":True,"rows":rows}
Path(__file__).with_name("matrix-evidence.json").write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
print("PASS retained matrix: six modes; exact findings hash invariant; generations validate")
