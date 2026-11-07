"""Actual Flint Markdown label regression; exact ID validity is not claim support.

The retained text/metadata hashes are pinned in
artifacts/wp017-citation-label-20261107/baseline-inputs.json.
"""
import json
from types import SimpleNamespace

import pytest

from attackmap.citations import CitationContext, EvidenceReference, validate_references
from attackmap.llm_review import LlmReviewResult, _validate_narrative_references

# Exact leading excerpt of the retained Flint review, line30 (not a model fixture).
ACTUAL_LABEL = "- **finding:1:** Investigate unauthenticated or inconsistent access"


def context(*identities):
    return CitationContext("", tuple(EvidenceReference(value, "a" * 64) for value in identities), ())


def test_actual_bold_label_colon_is_delimiter_for_exact_issued_id():
    result = validate_references(ACTUAL_LABEL, context("finding:1"))
    assert result.reference_validity == "valid"
    assert result.valid_references == ("finding:1",) and not result.invalid_references
    assert not result.source_spans


def test_existing_punctuation_outside_bold_is_unchanged():
    result = validate_references("- **finding:1**: Example", context("finding:1"))
    assert result.reference_validity == "valid" and result.valid_references == ("finding:1",)


def test_exact_issued_colon_id_takes_precedence_over_label_delimiter():
    result = validate_references("- **finding:1:** Example", context("finding:1", "finding:1:"))
    assert result.valid_references == ("finding:1:",)


@pytest.mark.parametrize("text", [
    "- **finding:999:** Unissued ID",
    "- **finding:1:other:** Extended ID",
    "- **finding:1::** Double colon",
    "`finding:1:`",
    "`**finding:1:**`",
    "```text\n**finding:1:** literal\n```",
    "~~~text\n**finding:1:** literal\n~~~",
    "    **finding:1:** indented code",
    "[label](**finding:1:**)",
    "[label](finding:1:)",
    "[label]: **finding:1:**",
    "[label](\n**finding:1:**\n)",
    "`literal\n**finding:1:**\n`",
    "<pre>\n**finding:1:**\n</pre>",
    "Ordinary prose **finding:1:** is not a heading label",
])
def test_nonlabel_or_literal_unknown_extended_tokens_remain_invalid(text):
    result = validate_references(text, context("finding:1"))
    assert result.reference_validity == "invalid"
    assert result.invalid_references and not result.valid_references and not result.source_spans


def test_actual_narrative_path_formats_reference_without_claim_support_upgrade():
    rendered = SimpleNamespace(evidence_json=json.dumps({"findings": [{"id": "finding:1"}]}))
    output = LlmReviewResult(markdown=ACTUAL_LABEL + " Source server.ts:430 remains unresolved.",
        model="offline-no-provider", stop_reason="completed", usage={}, backend="api")
    checked = _validate_narrative_references(output, rendered)
    metadata = checked.reference_validation
    assert metadata["reference_validity"] == "valid"
    assert metadata["valid_references"] == ["finding:1"] and metadata["invalid_references"] == []
    assert metadata["claim_support"] == "not_assessed"
    assert metadata["claim_support_assessments"] and all(
        item["claim_support"] == "not_assessed" for item in metadata["claim_support_assessments"])
    assert metadata["source_location_validation"] == "unvalidated"
    assert metadata["source_reference_validity"] == "unresolved"
    assert "server.ts:430" in metadata["unresolved_source_references"]
