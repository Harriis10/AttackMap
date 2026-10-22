"""Assert complete baseline/current outputs for bounded ownership edge cases."""

from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import importlib.util
import itertools
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / "src"))

from attackmap import threat_model, topology
from attackmap.models import AuthHint, DatabaseHint, EdgeHint, ExternalCall, ProtocolHint, Route, ScanResult, ServiceHint


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


baseline_topology = load("attackmap._owner_baseline_topology", HERE / "baseline/topology.py")
baseline_threat = load("attackmap._owner_baseline_threat", HERE / "baseline/threat_model.py")
candidate_dir = ROOT / "docs/verification/windows-parity/WP032/r10b-candidate-20261021-a/candidate-files/src/attackmap"
candidate_topology = load("attackmap._owner_rejected_topology", candidate_dir / "topology.py")
sys.modules["attackmap.topology"] = candidate_topology
candidate_threat = load("attackmap._owner_rejected_threat", candidate_dir / "threat_model.py")
sys.modules["attackmap.topology"] = topology


def output(topo, threat, original):
    value = original.model_copy(deep=True)
    files = [route.file for route in value.routes] + [db.file for db in value.databases]
    return {
        "topology_map": topo._file_service_map(value),
        "topology_services": {file: topo._services_in_file(file, value) for file in files},
        "graph": asdict(topo.build_service_graph(value)),
        "threat_map": threat._file_service_map(value),
        "service_chains": [asdict(chain) for chain in threat._build_service_chains(value)],
        "atproto_chains": [asdict(chain) for chain in threat._build_atproto_chains(value)],
        "findings": [finding.model_dump(mode="json") for finding in threat.generate_findings(value)],
        "attack_paths": [path.model_dump(mode="json") for path in threat.generate_attack_paths(value)],
    }


NAMES = [
    [], [""], ["alpha"], ["Auth", "auth"], ["Auth "], [" Auth"], [" "],
    ["alpha", "beta"], ["beta", "alpha"], ["", "alpha"], ["alpha", ""],
    ["alpha", "beta", "alpha"], ["", "alpha", ""], ["alpha", "", "alpha"],
    ["alpha", "", "beta"], ["Straße", "STRASSE"], ["İ", "i"], ["Auth", "auth "],
]
FAMILIES = [("auth_hints", AuthHint), ("service_hints", ServiceHint), ("edge_hints", EdgeHint)]
TARGETS = ["https://peer.internal/users", "env://PEER_URL", "queue://kafka/events"]
FILES = ["services/layout/app.py", "services\\layout\\app.py"]


def scan(file, declarations, target):
    value = ScanResult(
        root=".",
        routes=[Route(method="POST", path="/xrpc/com.atproto.repo.createRecord", file=file)],
        databases=[DatabaseHint(kind="postgresql", file=file, source_analyzer="owner-db-probe")],
        external_calls=[ExternalCall(target=target, file=file, source_analyzer="owner-call-probe")],
        auth_hints=[AuthHint(hint="service_role:privileged", file=file)],
        protocol_hints=[
            ProtocolHint(hint="atproto_namespace:com.atproto", file=file),
            ProtocolHint(hint="atproto_service_note:note-owner", file=file),
        ],
    )
    for family, hint_class, names in declarations:
        getattr(value, family).extend(hint_class(hint="service_name:" + name, file=file,
                                                source_analyzer="owner-" + family) for name in names)
    return value


cases = {}
for (family, hint_class), (index, names), target, file in itertools.product(
    FAMILIES, enumerate(NAMES), TARGETS, FILES
):
    key = f"{family}:{index}:{target}:{file}"
    cases[key] = scan(file, [(family, hint_class, names)], target)

for (auth_index, auth_names), (service_index, service_names) in itertools.product(
    enumerate(NAMES[7:11]), enumerate(NAMES[7:11])
):
    key = f"mixed:{auth_index}:{service_index}"
    cases[key] = scan(FILES[0], [("auth_hints", AuthHint, auth_names),
                                ("service_hints", ServiceHint, service_names),
                                ("edge_hints", EdgeHint, ["edge-only"])], TARGETS[0])

for label, names in [("ambiguous", ["alpha", "beta"]), ("empty", [""]), ("absent", [])]:
    for file in ["src/app.py", "services/layout/app.py"]:
        value = scan(file, [("service_hints", ServiceHint, names)], TARGETS[0])
        value.databases[0].file = "services/sink/database.py"
        value.service_hints.append(ServiceHint(hint="service_name:sink", file="services/sink/database.py"))
        value.edge_hints.append(EdgeHint(hint="edge:alpha->sink", file=file))
        cases[f"separate-sink:{label}:{file}"] = value

golden = {}
differences = []
before_inputs = sha256(json.dumps({key: value.model_dump(mode="json") for key, value in cases.items()},
                                  sort_keys=True).encode()).hexdigest()
for key, value in cases.items():
    before = output(baseline_topology, baseline_threat, value)
    after = output(topology, threat_model, value)
    golden[key] = before
    if before != after:
        differences.append({"case": key, "baseline": before, "current": after})

after_inputs = sha256(json.dumps({key: value.model_dump(mode="json") for key, value in cases.items()},
                                 sort_keys=True).encode()).hexdigest()
negative = scan(FILES[0], [("service_hints", ServiceHint, [""])], TARGETS[0])
negative_before = output(baseline_topology, baseline_threat, negative)
negative_candidate = output(candidate_topology, candidate_threat, negative)
assert negative_before != negative_candidate, "Probe must detect the rejected candidate's empty-owner regression"
assert negative_before["threat_map"][FILES[0]] == ""
assert negative_candidate["threat_map"][FILES[0]] == "layout"

golden_bytes = json.dumps(golden, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
(HERE / "golden-before.json").write_bytes(golden_bytes)
result = {
    "cases": len(cases), "equal": len(cases) - len(differences), "differences": differences,
    "full_outputs": ["topology_map", "topology_services", "graph", "threat_map", "service_chains",
                     "atproto_chains", "findings", "attack_paths"],
    "golden_sha256": sha256(golden_bytes).hexdigest(),
    "inputs_unchanged": before_inputs == after_inputs,
    "rejected_candidate_negative_control_detected": True,
    "negative_control": {"baseline": negative_before, "rejected_candidate": negative_candidate},
    "baseline_source_sha256": {name: sha256((HERE / "baseline" / name).read_bytes()).hexdigest()
                               for name in ["topology.py", "threat_model.py"]},
    "current_source_sha256": {name: sha256((ROOT / "src/attackmap" / name).read_bytes()).hexdigest()
                              for name in ["topology.py", "threat_model.py"]},
}
(HERE / "compatibility.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
assert before_inputs == after_inputs, "Compatibility scan inputs were mutated"
assert not differences, f"{len(differences)} complete output mismatches"
print(json.dumps({key: result[key] for key in ["cases", "equal", "inputs_unchanged",
                                              "rejected_candidate_negative_control_detected", "golden_sha256"]}))
