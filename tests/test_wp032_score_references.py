"""Owned R3 prototype; synthetic snapshot contexts, never a scan/runtime proof."""
import hashlib
import json
from itertools import permutations

import pytest
from pydantic import ValidationError

from attackmap.exploitability import best_by_sink_kind, score_exploitability
from attackmap.finding_presentation import FindingPresentationIndex
from attackmap.index import ScanSnapshot
from attackmap.models import (AttackSurface, ExploitabilityScore, ExploitabilityScoreReference,
    Finding, ScanResult, TaintChain)
from attackmap.threat_model import generate_findings


def chain(*, file="public.py", path="/items", kind="sql_execute", sink="shared_db.py", line=10, hops=0):
    return TaintChain(route_path=path, route_method="GET", route_file=file, sink_kind=kind,
        sink_file=sink, sink_line=line, hops=hops, files=[file, sink])


def scan(chains=None, *, root="/synthetic/repository", basis="fixture-a", captured=True):
    chains = list(chains or [chain()])
    # Real snapshot identity algorithm over clearly synthetic fixture contents;
    # does not inspect/resolve any live source paths or create a RepoIndex.
    files = {path: hashlib.sha256((basis + ":" + path).encode()).hexdigest()
        for c in chains for path in [c.route_file, c.sink_file]}
    snapshot = ScanSnapshot.from_identity({"files": files, "total_size": 0, "index_config": {}}).identity()
    return ScanResult(root=root, taint_chains=chains, scan_snapshot=snapshot if captured else None)


def scored(value):
    surfaces = [AttackSurface(route=c.route_path, method=c.route_method, file=c.route_file,
        category="public_api", exposure="public", risk="high") for c in value.taint_chains]
    return score_exploitability(value, surfaces)


def finding(score, **updates):
    fields = dict(title="Synthetic aggregate", rule_id="synthetic-rule", severity="high", mitigation="Review",
        exploitability=score.score, exploitability_tier=score.tier, exploitability_reference=score.producer_reference,
        locations=[{"file": score.producer_reference.chain.sink_file, "line": score.producer_reference.chain.sink_line}])
    fields.update(updates)
    return Finding(**fields)


def priority(value, scores, selected):
    return FindingPresentationIndex(value, scores).for_finding(selected)["priority"]


def test_producer_fusion_copies_exact_selected_reference_without_rescoring():
    value = scan([chain(), chain(file="other.py", path="/other", hops=2), chain(file="eval.py", path="/eval", kind="eval")])
    scores = scored(value)
    surfaces = [AttackSurface(route=c.route_path, method=c.route_method, file=c.route_file,
        category="public_api", exposure="public", risk="high") for c in value.taint_chains]
    emitted = [f for f in generate_findings(value, surfaces) if f.exploitability is not None]
    assert emitted
    expected = best_by_sink_kind(scores)
    for f in emitted:
        source = expected[f.exploitability_reference.chain.sink_kind]
        assert f.exploitability_reference == source.producer_reference
        assert (f.exploitability, f.exploitability_tier) == (source.score, source.tier)
        assert priority(value, scores, f)["score_reference"]["status"] == "resolved"


def test_equal_numbers_on_different_sink_chains_never_select_unrelated_factors():
    value = scan([chain(), chain(file="eval.py", path="/eval", kind="eval")])
    scores = scored(value)
    assert len(scores) == 2 and scores[0].score == scores[1].score and scores[0].tier == scores[1].tier
    for order in permutations(scores):
        result = priority(value, list(order), finding(scores[0]))
        assert result["point_contributions"] == "supplied"
        assert len(result["decomposition"]) == 1
        assert result["decomposition"][0]["producer_reference"] == scores[0].producer_reference.model_dump()


def test_full_typed_chain_identity_includes_route_file_and_remains_order_independent():
    chains = [chain(file="one.py"), chain(file="two.py")]
    ids = []
    for order in permutations(chains):
        value = scan(order)
        scores = scored(value)
        ids.append({s.producer_reference.score_id for s in scores})
        assert len(ids[-1]) == 2
        for score in scores:
            assert priority(value, scores, finding(score))["score_reference"]["status"] == "resolved"
    assert ids[0] == ids[1]


@pytest.mark.parametrize("change", ["repository", "snapshot"])
def test_identical_relative_paths_in_other_repository_or_snapshot_cannot_resolve(change):
    original = scan(); original_score = scored(original)[0]
    other = scan(root="/synthetic/other" if change == "repository" else "/synthetic/repository",
        basis="fixture-b" if change == "snapshot" else "fixture-a")
    other_score = scored(other)[0]
    assert original_score.score == other_score.score
    assert original_score.producer_reference.score_id != other_score.producer_reference.score_id
    result = priority(other, [original_score, other_score], finding(original_score))
    assert result["score_reference"]["status"] == "context_mismatch"
    assert result["decomposition"] == [] and result["point_contributions"] == "not_supplied"


def test_exact_duplicate_producer_reference_is_rejected_as_ambiguous():
    value = scan(); score = scored(value)[0]
    result = priority(value, [score, score.model_copy(deep=True)], finding(score))
    assert result["score_reference"]["status"] == "ambiguous_reference"
    assert result["decomposition"] == []


@pytest.mark.parametrize("change", ["finding_number", "finding_tier", "producer_number", "producer_tier"])
def test_same_chain_reference_does_not_override_number_or_tier_disagreement(change):
    value = scan(); score = scored(value)[0]; selected = finding(score)
    if change == "finding_number": selected.exploitability = score.score - 1
    if change == "finding_tier": selected.exploitability_tier = "low"
    if change == "producer_number": score = score.model_copy(update={"score": score.score - 1})
    if change == "producer_tier": score = score.model_copy(update={"tier": "low"})
    result = priority(value, [score], selected)
    assert result["score_reference"]["status"] == "numeric_mismatch"
    assert result["decomposition"] == []


@pytest.mark.parametrize("root,captured", [("/synthetic/repository", False), (".", True), ("", True)])
def test_missing_captured_scope_remains_explicit_unverified_without_owned_factors(root, captured):
    value = scan(root=root, captured=captured); score = scored(value)[0]
    assert score.producer_reference.scope == "unverified"
    result = priority(value, [score], finding(score))
    assert result["score_reference"]["status"] == "unverified_scope"
    assert result["point_contributions"] == "not_supplied" and result["decomposition"] == []
    assert result["exploitability_score"] == score.score


def test_legacy_models_import_and_preserve_numbers_without_inventing_references():
    value = scan(); score = scored(value)[0]
    legacy_score = ExploitabilityScore.model_validate(score.model_dump(exclude={"producer_reference"}))
    legacy_finding = Finding.model_validate(finding(score).model_dump(exclude={"exploitability_reference"}))
    assert legacy_score.producer_reference is None and legacy_finding.exploitability_reference is None
    assert legacy_finding.exploitability == score.score
    result = priority(value, [score, legacy_score], legacy_finding)
    assert result["score_reference"]["status"] == "missing_reference"
    assert result["point_contributions"] == "not_supplied" and result["decomposition"] == []


def test_new_optional_fields_roundtrip_through_existing_model_dump():
    value = scan(); score = scored(value)[0]; selected = finding(score)
    assert ExploitabilityScore.model_validate_json(score.model_dump_json()) == score
    assert Finding.model_validate_json(selected.model_dump_json()) == selected
    assert Finding.model_validate(selected.model_dump(exclude={"exploitability_reference"})).model_dump()["exploitability_reference"] is None


def test_missing_score_missing_source_chain_and_factor_corruption_fail_closed():
    value = scan(); score = scored(value)[0]; selected = finding(score)
    assert priority(value, [], selected)["score_reference"]["status"] == "score_unavailable"
    without_chain = value.model_copy(update={"taint_chains": []})
    assert priority(without_chain, [score], selected)["score_reference"]["status"] == "source_chain_unavailable"
    altered = score.model_copy(update={"raw_score": score.raw_score + 1})
    assert priority(value, [altered], selected)["score_reference"]["status"] == "factor_integrity_mismatch"


def test_reference_id_is_bound_to_its_structured_identity():
    reference = scored(scan())[0].producer_reference
    payload = reference.model_dump(); payload["chain"]["route_file"] = "other.py"
    with pytest.raises(ValidationError): ExploitabilityScoreReference.model_validate(payload)
    with pytest.raises(ValidationError): ExploitabilityScoreReference.model_validate({**reference.model_dump(), "version": "future"})


def test_score_reference_is_not_derived_from_display_subject_or_factor_order():
    value = scan(); score = scored(value)[0]; selected = finding(score)
    changed = score.model_copy(update={"subject": "Changed display prose", "factors": list(reversed(score.factors))})
    result = priority(value, [changed], selected)
    assert result["score_reference"]["status"] == "resolved"
    assert result["decomposition"][0]["producer_reference"] == score.producer_reference.model_dump()


def test_score_reference_fields_are_additive_in_json_schema():
    for model, field in [(ExploitabilityScore, "producer_reference"), (Finding, "exploitability_reference")]:
        schema = model.model_json_schema()
        assert field in schema["properties"] and field not in schema.get("required", [])
        assert schema["properties"][field]["default"] is None
    assert json.loads(scored(scan())[0].model_dump_json())["producer_reference"]["chain"]["route_file"] == "public.py"


def test_score_producer_consumes_existing_captured_context_without_resolving_live_paths(tmp_path, monkeypatch):
    from pathlib import Path
    from attackmap.index import RepoIndex, clear_pinned_index

    (tmp_path / "public.py").write_text("# Synthetic captured fixture only\n", encoding="utf-8")
    (tmp_path / "shared_db.py").write_text("# Synthetic sink fixture only\n", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    try:
        assert index.snapshot is not None
        captured = index.snapshot.identity()
        value = ScanResult(root=str(index.root), scan_snapshot=captured, taint_chains=[chain()])
        def forbidden(*args, **kwargs): raise AssertionError("Producer must consume existing scope, not resolve live paths or build an index")
        with monkeypatch.context() as local:
            local.setattr(Path, "resolve", forbidden)
            local.setattr(RepoIndex, "build", forbidden)
            score = scored(value)[0]
        assert score.producer_reference.repository_root == str(index.root)
        assert score.producer_reference.snapshot_id == captured.snapshot_id
        assert score.producer_reference.scope == "repository_snapshot"
    finally:
        clear_pinned_index()
