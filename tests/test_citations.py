import json
from pathlib import Path

import pytest

from attackmap.citations import (
    capture_source_spans, citation_scope, context_from_payload, current_citation_context,
    validate_references,
)


@pytest.fixture
def captured(tmp_path):
    path = tmp_path / "src" / "app.py"
    path.parent.mkdir()
    path.write_bytes(b"one\ntwo\nthree\nfour\n")
    spans = capture_source_spans(tmp_path, [("src/app.py", 2)], redact_line=lambda line: line,
                                 context_lines=1)
    context = context_from_payload({"taint_chains": [{"id": "taint:1", "sink": "src/app.py:2"}],
        "findings": [{"id": "finding:1", "evidence": ["observed src/app.py:2"]}]},
        spans, repository_root=str(tmp_path))
    return path, context


def test_capture_has_fixed_golden_source_and_redacted_span_identity(captured):
    _, context = captured
    span = context.spans[0]
    assert span.evidence_id == "source:86c285cabe402084ee88b576378e64e8a71413fe4ee15643679a504291727a51"
    assert span.source_sha256 == "c45d3a272228cc542168164ba961fa622e95260bfd107eb1276940cb5209433e"
    assert span.excerpt_sha256 == "44d32c48456c7e413e2825329e7850cf3189aae62f947dfea55e938d237d6cce"
    assert (span.start_line, span.end_line, span.anchor_line) == (1, 3, 2)
    assert span.excerpt == "1: one\n2: two\n3: three"
    assert context.metadata()["claim_support"] == "not_assessed"


@pytest.mark.parametrize("reference", ["taint:1", "finding:1", "src/app.py:2", "src/app.py:1-3"])
def test_exact_allowed_reference_resolves_to_captured_span(captured, reference):
    _, context = captured
    validation = validate_references(f"See `{reference}`.", context)
    assert validation.reference_validity == "valid"
    assert validation.source_reference_valid
    assert validation.source_spans == context.spans
    assert validation.claim_support == "not_assessed"


def test_exact_source_id_resolves_without_live_filesystem_guess(captured):
    path, context = captured
    source_id = context.spans[0].evidence_id
    path.write_text("changed after capture")
    validation = validate_references(source_id, context)
    assert validation.source_reference_valid
    assert "2: two" in validation.source_spans[0].excerpt
    replacement = capture_source_spans(path.parents[1], [("src/app.py", 1)], redact_line=lambda line: line)
    assert replacement[0].evidence_id != source_id


@pytest.mark.parametrize("reason", [
    "app.py shows exec", "per src/app.py", "prefix_taint:1_suffix", "taint:10", "taint:1junk",
    "TAINT:1", "src/app.py:20", "src/app.py:2-3", "src/app.py:1-4", "other/app.py:2",
    "src/App.py:2", "src/app.py:2x", "taint:1α", "taint:1\u200b0", "taint:1\u202e", "https://host/taint:1",
    "https://host/src/app.py:2", "../src/app.py:2", "src\\app.py:2", "source:invented",
])
def test_basename_substring_case_alias_and_unknown_span_do_not_validate(captured, reason):
    _, context = captured
    validation = validate_references(reason, context)
    assert not validation.source_reference_valid
    assert validation.claim_support == "not_assessed"


def test_unknown_reference_alongside_valid_reference_is_not_silently_accepted(captured):
    _, context = captured
    validation = validate_references("taint:1 and taint:10", context)
    assert validation.reference_validity == "invalid"
    assert validation.valid_references == ("taint:1",)
    assert validation.invalid_references == ("taint:10",)


@pytest.mark.parametrize("malformed", ["src/app.py:2x", "src/app.py:02", "src/app.py:0", "taint:1\u200b0"])
def test_malformed_reference_cannot_hide_beside_a_valid_reference(captured, malformed):
    _, context = captured
    validation = validate_references("taint:1 and " + malformed, context)
    assert validation.reference_validity == "invalid"
    assert not validation.source_reference_valid


def test_same_basename_in_different_directories_remains_distinct(captured):
    path, context = captured
    other = path.parents[1] / "other" / "app.py"
    other.parent.mkdir()
    other.write_text("other content\n")
    spans = capture_source_spans(path.parents[1], [("src/app.py", 2), ("other/app.py", 1)],
                                 redact_line=lambda line: line, context_lines=1)
    expanded = context_from_payload({}, spans, repository_root=str(path.parents[1]))
    assert validate_references("app.py", expanded).reference_validity == "missing"
    assert validate_references("src/app.py:2", expanded).source_spans == (spans[0],)
    assert validate_references("other/app.py:1", expanded).source_spans == (spans[1],)


def test_only_explicit_producer_evidence_arrays_can_allowlist_ids(captured):
    path, context = captured
    payload = {"hypotheses": [{"id": "taint:999", "evidence": "taint:888"}],
        "note": "taint:777", "findings": [{"id": "taint:666"}],
        "taint_chains": [{"id": "taint:1", "sink": "src/app.py:2"}]}
    scoped = context_from_payload(payload, context.spans, repository_root=str(path.parents[1]))
    assert [record.evidence_id for record in scoped.records] == ["taint:1"]
    assert not validate_references("taint:999", scoped).source_reference_valid


@pytest.mark.parametrize("identity", ["taint:0", "taint:-1", "taint:1junk", "TAINT:1", "taint:1\n", "../taint:1"])
def test_malformed_producer_ids_are_not_allowlisted(captured, identity):
    path, context = captured
    scoped = context_from_payload({"taint_chains": [{"id": identity, "sink": "src/app.py:2"}]},
        context.spans, repository_root=str(path.parents[1]))
    assert not scoped.records


def test_duplicate_producer_ids_are_ambiguous_and_rejected(captured):
    path, context = captured
    scoped = context_from_payload({"taint_chains": [
        {"id": "taint:1", "sink": "src/app.py:2"}, {"id": "taint:1", "sink": "other/app.py:2"}]},
        context.spans, repository_root=str(path.parents[1]))
    assert not scoped.records


def test_structured_reference_without_source_is_valid_but_not_source_or_claim_support(captured):
    path, _ = captured
    scoped = context_from_payload({"taint_chains": [{"id": "taint:1", "sink": "missing.py:2"}]},
        (), repository_root=str(path.parents[1]))
    validation = validate_references("taint:1", scoped)
    assert validation.reference_validity == "valid"
    assert not validation.source_reference_valid
    assert validation.claim_support == "not_assessed"


def test_empty_context_never_promotes_uncited_or_invented_claims(tmp_path):
    context = context_from_payload({}, (), repository_root=str(tmp_path))
    assert validate_references("looks safe", context).reference_validity == "missing"
    assert validate_references("taint:1", context).reference_validity == "invalid"


def test_scope_restores_prior_context_after_failure(captured):
    _, context = captured
    assert current_citation_context() is None
    with pytest.raises(RuntimeError):
        with citation_scope(context):
            assert current_citation_context() is context
            raise RuntimeError("test")
    assert current_citation_context() is None


def test_capture_redacts_before_retaining_or_exporting_excerpt(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("credential=SUPER_SECRET\n")
    spans = capture_source_spans(tmp_path, [("app.py", 1)],
        redact_line=lambda line: line.replace("SUPER_SECRET", "[REDACTED]"))
    context = context_from_payload({}, spans, repository_root=str(tmp_path))
    assert "SUPER_SECRET" not in repr(context)
    assert "SUPER_SECRET" not in json.dumps(context.metadata())
    assert "[REDACTED]" in context.excerpts["app.py:1"]


def test_capture_bounds_locations_bytes_and_line_range(tmp_path):
    (tmp_path / "app.py").write_text("one\ntwo\nthree\n")
    spans = capture_source_spans(tmp_path, [("app.py", 0), ("app.py", 99), ("app.py", 2), ("app.py", 1)],
        redact_line=lambda line: line, max_locations=1, context_lines=0)
    assert len(spans) == 1
    assert spans[0].excerpt == "2: two"
    assert not capture_source_spans(tmp_path, [("app.py", 2)], redact_line=lambda line: line, max_file_bytes=3)


@pytest.mark.parametrize("relative", ["../secret.py", "/secret.py", "C:/secret.py", "C:secret.py", "\\\\host\\secret.py", "~secret.py", "./app.py", "src/../app.py"])
def test_capture_refuses_noncanonical_or_escaping_paths(tmp_path, relative):
    (tmp_path / "app.py").write_text("source")
    assert not capture_source_spans(tmp_path, [(relative, 1)], redact_line=lambda line: line)


def test_capture_refuses_symlink_even_with_follow_enabled(tmp_path, monkeypatch):
    (tmp_path / "source.py").write_text("must not read through link")
    try:
        (tmp_path / "link.py").symlink_to(tmp_path / "source.py")
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    monkeypatch.setenv("ATTACKMAP_FOLLOW_SYMLINKS", "1")
    assert not capture_source_spans(tmp_path, [("link.py", 1)], redact_line=lambda line: line)


def test_multiple_locations_read_same_file_once(captured, monkeypatch):
    path, _ = captured
    import attackmap.citations as module
    original = module.os.open
    opened = []
    def counted(candidate, flags):
        opened.append(Path(candidate))
        return original(candidate, flags)
    monkeypatch.setattr(module.os, "open", counted)
    spans = capture_source_spans(path.parents[1], [("src/app.py", 1), ("src/app.py", 2)],
                                 redact_line=lambda line: line)
    assert len(spans) == 2
    assert opened == [path]


def test_producer_payload_is_captured_once_and_returned_as_isolated_copies(captured):
    path, context = captured
    payload = {"taint_chains": [{"id": "taint:1", "sink": "src/app.py:2"}]}
    frozen = context_from_payload(payload, context.spans, repository_root=str(path.parents[1]))
    payload["taint_chains"][0]["sink"] = "invented.py:99"
    exported = frozen.producer_payload
    exported["taint_chains"].append({"id": "taint:999"})
    assert frozen.producer_payload == {"taint_chains": [{"id": "taint:1", "sink": "src/app.py:2"}]}
    assert validate_references("taint:1", frozen).source_reference_valid
    assert not validate_references("taint:999", frozen).source_reference_valid


def test_hunt_prompts_and_validation_reuse_exact_pre_generation_snapshot(tmp_path):
    from attackmap.hunt_harness import run_majority_verify
    from attackmap.llm_review import LlmReviewResult
    from attackmap.models import Finding, FindingLocation, ScanResult
    from attackmap.review_prompts import render_skeptic_prompts
    source = tmp_path / "app.py"
    original = b"original_constant = 1\n"
    source.write_bytes(original)
    finding = Finding(title="Original finding", rule_id="source-review", severity="medium",
        evidence=["app.py:1"], mitigation="Review", locations=[FindingLocation(file="app.py", line=1)])
    scan = ScanResult(root=str(tmp_path))
    seen = []
    def fake(mode, hypotheses=None, **kwargs):
        if mode == "hunt_generate":
            source.write_text("MUTATED_SECRET = 2\n")
            finding.title = "Mutated finding"
            return LlmReviewResult("=== HYPOTHESES ===\nH1: lead [evidence: finding:1]", "fake", None, {}, "api")
        prompt = render_skeptic_prompts(scan, [], [finding], [], hypotheses)
        payload = json.loads(prompt.evidence_json)
        seen.append(payload)
        assert payload["findings"][0]["title"] == "Original finding"
        assert "original_constant" in payload["code_excerpts"]["app.py:1"]
        assert "MUTATED_SECRET" not in prompt.evidence_json
        return LlmReviewResult("VERDICT H1: REFUTED — constant in finding:1", "fake", None, {}, "api")
    result = run_majority_verify(scan, [], [finding], [], votes=2, llm_call=fake)
    assert result.consensus[0].refuted == 2
    assert result.citation_context["claim_support"] == "not_assessed"
    assert seen[0]["citation_context"] == seen[1]["citation_context"] == result.citation_context


def test_hunt_never_disables_reference_checks_when_no_source_was_available():
    from attackmap.hunt_harness import run_majority_verify
    from attackmap.llm_review import LlmReviewResult
    def fake(mode, **kwargs):
        text = ("=== HYPOTHESES ===\nH1: lead [evidence: taint:1]" if mode == "hunt_generate"
                else "VERDICT H1: REFUTED — taint:1 is safe")
        return LlmReviewResult(text, "fake", None, {}, "api")
    result = run_majority_verify(None, [], [], [], votes=2, llm_call=fake)
    assert result.consensus[0].refuted == 0
    assert result.consensus[0].needs_review == 2
    assert result.citation_context["sources"] == []


def test_prompt_scope_rejects_foreign_repository_context(captured, tmp_path):
    from attackmap.models import ScanResult
    from attackmap.review_prompts import render_skeptic_prompts
    _, context = captured
    with citation_scope(context), pytest.raises(ValueError, match="different repository"):
        render_skeptic_prompts(ScanResult(root=str(tmp_path / "different")), [], [], [], [])


@pytest.mark.parametrize("token", ["src/app.py:0", "src/app.py:2junk", "src/app.py:2-0", "src/other.py:2", "finding:999", "source:unissued"])
def test_malformed_and_unissued_references_never_gain_association(captured, token):
    _, context = captured
    result = validate_references(token, context)
    assert result.reference_validity == "invalid"
    assert not result.source_spans


def test_location_parser_remains_full_token_only():
    from attackmap.citations import _LOCATION
    assert _LOCATION.fullmatch("src/app.py:2-4").groupdict() == {"path": "src/app.py", "line": "2", "end": "4"}
    assert _LOCATION.fullmatch("src/app.py:2junk") is None
    assert list(_LOCATION.finditer("a/" * 25000)) == []


def test_location_like_predicate_matches_legacy_token_grammar():
    import random
    import re
    from attackmap.citations import _looks_like_location
    legacy = re.compile(r".*[./][^:]*:[0-9].*\Z")
    rng = random.Random(236)
    for _ in range(2000):
        token = "".join(rng.choice("ab./:012x-") for _ in range(rng.randrange(1, 45)))
        assert _looks_like_location(token) == bool(legacy.fullmatch(token)), token


def test_location_like_hostile_large_token_is_bounded():
    import time
    from attackmap.citations import _looks_like_location
    start = time.perf_counter()
    assert not _looks_like_location("a/" * 500000)
    assert time.perf_counter() - start < 2.0
