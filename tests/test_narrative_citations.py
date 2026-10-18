"""Offline narrative ID checks; reference validity never proves claim support."""
import json
from types import SimpleNamespace
import pytest
from attackmap.llm_review import LlmReviewResult, _validate_narrative_references


def check(text, payload=None):
    rendered = SimpleNamespace(evidence_json=json.dumps(payload or {'findings':[{'id':'finding:2','finding_id':'stable-id'}]}))
    result = LlmReviewResult(text, 'offline', 'completed', {}, 'api')
    return _validate_narrative_references(result, rendered)


@pytest.mark.parametrize('text,status,invalid', [
    ('Observed syntax [finding:2].', 'valid', []),
    ('Omitted finding:3.', 'invalid', ['finding:3']),
    ('Target routes (`find:2`) lack auth authorization signal at handler level.', 'invalid', ['find:2']),
    ('finding:2 and find:2', 'invalid', ['find:2']),
    ('No citations; time 12:30; https://example.org/path:42.', 'missing', []),
])
def test_exact_selected_reference_status(text, status, invalid):
    result = check(text)
    meta = result.reference_validation
    assert meta['reference_validity'] == status
    assert meta['invalid_references'] == invalid
    assert meta['claim_support'] == 'not_assessed'
    assert meta['source_location_validation'] == 'not_assessed'
    assert result.markdown.endswith(text)  # Original prose and typo are preserved.
    json.dumps(meta)


def test_duplicate_and_wrong_collection_ids_are_not_authorized():
    result = check('finding:2 asset:invented', {'findings':[{'id':'finding:2'},{'id':'finding:2'},{'id':'asset:invented'}]})
    assert result.reference_validation['reference_validity'] == 'invalid'
    assert result.reference_validation['allowed_reference_count'] == 0


def test_included_asset_reference_does_not_imply_source_or_claim_support():
    result = check('asset:payment', {'assets':[{'id':'asset:payment'}]})
    assert result.reference_validation['valid_references'] == ['asset:payment']
    assert result.reference_validation['claim_support'] == 'not_assessed'


def test_generate_wrapper_persists_selected_reference_warning_and_original_prose(tmp_path, monkeypatch):
    import attackmap.pipeline as pipeline
    from attackmap.artifact_publisher import current_generation, validate_generation
    from attackmap.llm_review import generate_llm_review
    from attackmap.models import Finding, ScanResult
    from attackmap.pipeline import AnalyzeOptions, ScanAiLimits

    repo = tmp_path / 'repo'
    repo.mkdir()
    findings = [Finding(title=title, severity='high', evidence=['Static source signal'],
        mitigation='Validate effective authorization.', confidence='medium')
        for title in ('First static signal', 'Second static signal')]
    monkeypatch.setattr(pipeline, 'resolve_run_analyzers', lambda *_a, **_k: [])
    monkeypatch.setattr(pipeline, 'analyze_repository', lambda *_a, **_k: ScanResult(root=str(repo)))
    monkeypatch.setattr(pipeline, 'translate_recon', lambda *_a, **_k: SimpleNamespace(
        attack_surfaces=[], findings=findings, attack_paths=[]))
    original = 'Target routes (`find:2`) lack auth authorization signal at handler level. Reference finding:2 at routes/handler.ts:42; runtime enforcement is unverified.'
    calls = []
    class FakeProvider:
        base_url = 'http://127.0.0.1:1234/v1'
        def __init__(self):
            self.responses = self
        def with_options(self, **kwargs):
            return self
        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(output_text=original, model='recorded-fake', status='completed',
                                   usage=SimpleNamespace(input_tokens=3, output_tokens=4))
    client = FakeProvider()
    generated = []
    def actual_generation(*args, **kwargs):
        result = generate_llm_review(*args, **kwargs, openai_client=client)
        generated.append(result)
        return result
    monkeypatch.setattr(pipeline, 'generate_llm_review', actual_generation)
    options = AnalyzeOptions(repo_path=repo, output=tmp_path / 'reports', llm=True,
        llm_provider='openai', llm_backend='api', no_suppress=True, no_progress=True,
        ai_limits=ScanAiLimits(max_calls=1), echo=lambda *_a, **_k: None)
    assert pipeline.run_scan(options).exit_code == 0
    assert len(calls) == len(generated) == 1
    assert '"finding:2"' in calls[0]['input']
    result = generated[0]
    assert result.markdown.endswith(original)
    assert 'Unresolved evidence IDs' in result.markdown
    assert result.reference_validation['valid_references'] == ['finding:2']
    assert result.reference_validation['invalid_references'] == ['find:2']
    folder = current_generation(options.output)
    validate_generation(folder)
    persisted = json.loads((folder / 'defensive-review-llm.meta.json').read_text(encoding='utf-8'))
    assert persisted['reference_validation'] == result.reference_validation
    assert persisted['reference_validation']['claim_support'] == 'not_assessed'
    assert persisted['reference_validation']['source_location_validation'] == 'unvalidated'
    assert persisted['reference_validation']['unresolved_source_references'] == ['routes/handler.ts:42']
    markdown = (folder / 'defensive-review-llm.md').read_text(encoding='utf-8')
    assert 'Unresolved evidence IDs' in markdown and original in markdown
    assert 'Source file/line references are unresolved' in markdown
    assert len(result.reference_validation['context_sha256']) == 64



def test_source_locations_are_unresolved_even_when_producer_id_is_valid(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(Path, 'read_bytes', lambda *_a, **_k: pytest.fail('No live source reads'))
    result = check('finding:2 at routes/handler.ts:42 and handler.ts:10-12. Time 12:30; https://example.org/path:42.')
    metadata = result.reference_validation
    assert metadata['reference_validity'] == 'valid'
    assert metadata['source_reference_validity'] == 'unresolved'
    assert metadata['unresolved_source_references'] == ['routes/handler.ts:42', 'handler.ts:10-12']
    assert metadata['claim_support'] == 'not_assessed'
    assert 'Source file/line references are unresolved' in result.markdown


def test_per_claim_assessments_carry_the_closed_set_and_stay_not_assessed():
    result = check('OBSERVED syntax [finding:2].\nA second claim cites finding:2 and find:2.\nUncited line.')
    metadata = result.reference_validation
    assessments = metadata['claim_support_assessments']
    # One entry per (claim line, cited reference); uncited lines are not claims.
    assert [(a['reference'], a['claim_support']) for a in assessments] == [
        ('finding:2', 'not_assessed'), ('finding:2', 'not_assessed'), ('find:2', 'not_assessed'),
    ]
    assert all(a['reason'] == 'no captured source spans in the selected narrative prompt' for a in assessments)
    assert 'never implies claim support' in metadata['claim_support_basis']
    json.dumps(assessments)


def test_claim_support_assessments_are_absent_without_citations():
    result = check('No citations; plain narrative only.')
    assert result.reference_validation['claim_support_assessments'] == []
