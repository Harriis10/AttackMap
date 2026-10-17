from itertools import permutations
import pytest

from attackmap.evidence import classify_source_path
from attackmap.models import Route, ScanResult, Signal, SignalOrigin, SignalConflict
from attackmap.signal_provenance import _identity, _semantic_dump, merge_normalized_signals


def test_role_conflicts_coalesce_and_remain_stable_when_merged_again():
    first = Signal(kind="route", label="GET /same", file="same.py", source_role="test",
                   conflicts=[SignalConflict(field="source_role", values=["mock", "test"])])
    second = Signal(kind="route", label="GET /same", file="same.py", source_role="fixture")
    merged = merge_normalized_signals([first, second])
    assert merged[0].source_role == "unknown"
    conflicts = [c for c in merged[0].conflicts if c.field == "source_role"]
    assert len(conflicts) == 1
    assert conflicts[0].values == ["fixture", "mock", "test"]
    assert merge_normalized_signals(merged) == merged


@pytest.mark.parametrize("path,role", [("tests/a.py", "test"), (r"src\__tests__\a.ts", "test"), ("fixtures/a.py", "fixture"), ("mocks/a.py", "mock"), ("examples/a.py", "example"), ("src/__generated__/a.py", "generated"), ("generated/a.py", "generated"), ("src/a.py", "unknown"), ("contest/a.py", "unknown"), ("", "unknown")])
def test_path_conventions(path, role):
    assert classify_source_path(path) == role


def test_static_synthesis_and_legacy_unknown_are_distinct():
    scan = ScanResult(root=".", routes=[Route(path="/x", file="tests/a.py")])
    signal = scan.all_signals()[0]
    assert (signal.source_role, signal.evidence_kind, signal.classification_version) == ("test", "static_extraction", "1.0")
    assert signal.origins[0].source_role == "test"
    legacy = Signal(kind="route", label="GET /x", file="tests/a.py")
    assert legacy.source_role == legacy.evidence_kind == "unknown"
    assert legacy.classification_version is None
    origin = SignalOrigin(file="tests/a.py")
    assert origin.source_role == origin.evidence_kind == "unknown"


def test_production_requires_positive_detector_owned_metadata():
    unsupported = Signal(kind="auth", label="x", file="src/a.py", source_role="production")
    assert unsupported.source_role == "unknown"
    supported = unsupported.model_copy(update={"source_role": "production", "classification_version": "1.0", "classification_basis": "detector_owned"})
    assert Signal.model_validate(supported.model_dump()).source_role == "production"


def test_additive_fields_preserve_semantic_identity_payload_and_immutability():
    legacy = Signal(kind="auth", label="x", file="a.py", line=1, properties={"auth": "present"}, origins=[SignalOrigin(analyzer="p", file="a.py")])
    classified = legacy.model_copy(deep=True)
    classified.classification_version = "1.0"
    classified.source_role = "production"
    classified.classification_basis = "detector_owned"
    classified.evidence_kind = "static_extraction"
    assert _identity(legacy) == _identity(classified)
    assert _semantic_dump(legacy, exclude={"origins"}) == _semantic_dump(classified, exclude={"origins"})
    before = [item.model_dump() for item in (legacy, classified)]
    variants = [merge_normalized_signals(list(order))[0] for order in permutations((legacy, classified))]
    assert variants[0].model_dump() == variants[1].model_dump()
    assert variants[0].observation_id == merge_normalized_signals([legacy])[0].observation_id
    assert variants[0].source_role == "unknown"
    assert any(c.field == "source_role" for c in variants[0].conflicts)
    assert [item.model_dump() for item in (legacy, classified)] == before
