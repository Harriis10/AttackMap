"""Compare preserved R10b candidate consumers against current canonical code."""
import dataclasses
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "src"))
from attackmap.models import AuthHint, EdgeHint, ServiceHint, Route, DatabaseHint, ScanResult
import attackmap.topology as canonical_topology
import attackmap.threat_model as canonical_threat


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


candidate_root = ROOT / "docs/verification/windows-parity/WP032/r10b-candidate-20261021-a/candidate-files/src/attackmap"
candidate_topology = load("attackmap._r10b_probe_topology", candidate_root / "topology.py")
sys.modules["attackmap.topology"] = candidate_topology
candidate_threat = load("attackmap._r10b_probe_threat", candidate_root / "threat_model.py")
sys.modules["attackmap.topology"] = canonical_topology

FILE = "services/layout/app.py"


def output(topology, threat, value):
    return {
        "topology_map": topology._file_service_map(value),
        "threat_map": threat._file_service_map(value),
        "graph": dataclasses.asdict(topology.build_service_graph(value)),
        "chains": [dataclasses.asdict(chain) for chain in threat._build_service_chains(value)],
    }


cases = {}
for family, hint_class in [("auth_hints", AuthHint), ("service_hints", ServiceHint), ("edge_hints", EdgeHint)]:
    for label, names in [("absent", []), ("empty", [""]), ("case_duplicate", ["Auth", "auth"]),
                         ("spaced", ["Auth "]), ("ambiguous", ["alpha", "beta"]),
                         ("empty_named", ["", "alpha"]), ("named_empty", ["alpha", ""])]:
        value = ScanResult(root=".", routes=[Route(method="GET", path="/api", file=FILE)],
                           databases=[DatabaseHint(kind="postgresql", file=FILE)],
                           **{family: [hint_class(hint="service_name:" + name, file=FILE) for name in names]})
        before = output(canonical_topology, canonical_threat, value)
        after = output(candidate_topology, candidate_threat, value)
        cases[family + ":" + label] = {"equal": before == after, "canonical": before, "candidate": after}
print(json.dumps(cases, indent=2))
