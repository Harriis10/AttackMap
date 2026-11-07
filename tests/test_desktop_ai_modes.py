"""WP014 transport→service→provider matrix. Fake SDK only; no live HTTP or CLI execution."""
import hashlib
import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import attackmap.pipeline as pipeline
from attackmap.ai_budget import AiBudget, budget_scope, current_budget
from attackmap.artifact_publisher import current_generation, validate_generation
from attackmap.desktop_ai import ARTIFACTS, MODES, manifest_ai_result, service_ai_options
from attackmap.desktop_capabilities import validate_desktop_request
from attackmap.llm_review import generate_llm_review
from attackmap.models import Finding, ScanResult
from attackmap.provider_options import ProviderOptions, ProviderOptionsV13
from attackmap.run_contract import CURRENT_SCHEMA_VERSION, RunRequest
from attackmap.scan_service import _analyze_options, _fleet_incompatible_flags, scan_request_from_run


def payload(tmp_path, mode="review", schema="1.3", **changes):
    provider={"enable_ai": mode != "none", "mode": mode, **changes}
    return dict(schema_version=schema,run_id="desktop-"+mode,repository_id="fixture",generation=1,revision=0,
                repository_path=str(tmp_path/"repo"),output_path=str(tmp_path/mode),options={"provider":provider})


@pytest.mark.parametrize("schema", ["1.0","1.1","1.2"])
def test_legacy_provider_bytes_defaults_and_mode_gate_unchanged(tmp_path,schema):
    legacy=ProviderOptions(enable_ai=True)
    expected='{"enable_ai":true,"provider":"openai","endpoint":"http://127.0.0.1:1234/v1","model":"cyberstag-security-26b-a4b-v1","max_calls":8,"timeout_seconds":600,"output_token_limit":32000}'
    assert legacy.model_dump_json()==expected
    raw=payload(tmp_path,schema=schema);raw["options"]["provider"]=legacy.model_dump()
    request=validate_desktop_request(raw)
    assert request.options.provider.model_dump_json()==expected
    assert scan_request_from_run(request).llm and scan_request_from_run(request).desktop_ai_mode is None
    assert CURRENT_SCHEMA_VERSION=="1.2"
    with pytest.raises(ValueError):validate_desktop_request(payload(tmp_path,schema=schema))


@pytest.mark.parametrize("change", [
    {"enable_ai":False}, {"mode":"invented"}, {"backend":"cli"}, {"backend":"auto"},
    {"jury_votes":3}, {"jury_votes":True}, {"effort":"ultra"}, {"speed":"fast"},
    {"mode":"none","enable_ai":False,"effort":"high"},
    {"mode":"hunt_verify","jury_votes":8}, {"output_token_limit":None},
    {"provider":"claude","speed":"fast","model":"unsupported-model"},
])
def test_unsupported_combinations_rejected_before_dispatch(tmp_path,change):
    with pytest.raises(ValueError):validate_desktop_request(payload(tmp_path,**change))


def test_real_effort_speed_and_jury_mapping():
    configured=ProviderOptionsV13(enable_ai=True,mode="hunt_verify",jury_votes=5,effort="max",speed="fast",provider="claude",model="claude-opus-4-8",endpoint=None)
    mapped=service_ai_options(configured)
    assert mapped["hunt"] and mapped["verify"] and not mapped["llm"]
    assert (mapped["verify_votes"],mapped["llm_effort"],mapped["llm_speed"],mapped["llm_backend"])==(5,"max","fast","api")
    with pytest.raises(ValidationError):service_ai_options(configured.model_copy(update={"backend":"cli"}))


@pytest.mark.parametrize("mode",MODES)
def test_worker_engine_entry_maps_mode_and_inherits_typed_allowance(tmp_path,monkeypatch,mode):
    import attackmap.scan_service as service
    from attackmap.desktop_worker import run_request_file
    (tmp_path/"repo").mkdir()
    raw=payload(tmp_path,mode,max_calls=2,output_token_limit=7,timeout_seconds=9)
    path=tmp_path/"request.json";path.write_text(json.dumps(raw))
    received=[]
    def execute(request):
        received.append(request)
        ledger=current_budget()
        assert ledger.max_calls==2 and ledger.output_token_limit==7
        assert ledger.remaining_seconds<=9
        return SimpleNamespace(exit_code=0)
    monkeypatch.setattr(service,"execute_scan_request",execute)
    assert run_request_file(path,engine=True)==0
    assert received[0].desktop_ai_mode==mode
    assert current_budget() is None


def test_worker_rejects_cli_before_application_or_provider_dispatch(tmp_path,monkeypatch):
    import attackmap.scan_service as service
    from attackmap.desktop_worker import run_request_file
    (tmp_path/"repo").mkdir()
    path=tmp_path/"request.json";path.write_text(json.dumps(payload(tmp_path,backend="cli")))
    monkeypatch.setattr(service,"execute_scan_request",lambda *_a,**_k:pytest.fail("Unsupported CLI configuration reached dispatch"))
    assert run_request_file(path,engine=True)!=0


class FakeSDK:
    base_url="http://127.0.0.1:1234/v1"
    def __init__(self):self.responses=self;self.calls=[];self.mode="review";self.fail=False;self.missing_usage=False;self.clock_hook=None
    def with_options(self,**kwargs):return self
    def create(self,**kwargs):
        self.calls.append((self.mode,kwargs))
        if self.clock_hook:self.clock_hook()
        if self.fail:raise RuntimeError("synthetic provider unavailable")
        text=("=== HYPOTHESES ===\nH1: Synthetic candidate [evidence: finding:1]\n" if self.mode=="hunt_generate" else
              "VERDICT H1: NEEDS REVIEW — [evidence: finding:1]\n" if self.mode=="hunt_skeptic" else
              "Synthetic model assessment [finding:1].")
        return SimpleNamespace(output_text=text,model="fake-only",status="completed",
                               usage=None if self.missing_usage else SimpleNamespace(input_tokens=2,output_tokens=1))


@pytest.fixture
def engine(tmp_path,monkeypatch):
    repo=tmp_path/"repo";repo.mkdir();(repo/"app.py").write_text("# synthetic static source\n")
    finding=Finding(title="Synthetic static signal",severity="high",evidence=["app.py:1"],mitigation="Review static control",confidence="medium")
    monkeypatch.setattr(pipeline,"resolve_run_analyzers",lambda *_a,**_k:[])
    monkeypatch.setattr(pipeline,"analyze_repository",lambda *_a,**_k:ScanResult(root=str(repo),files_scanned=1))
    monkeypatch.setattr(pipeline,"translate_recon",lambda *_a,**_k:SimpleNamespace(attack_surfaces=[],findings=[finding],attack_paths=[]))
    client=FakeSDK()
    def generate(*args,**kwargs):
        client.mode=kwargs.get("mode","review")
        return generate_llm_review(*args,**kwargs,openai_client=client)
    monkeypatch.setattr(pipeline,"generate_llm_review",generate)
    def scan(mode,**changes):
        request=scan_request_from_run(validate_desktop_request(payload(tmp_path,mode,**changes)))
        request.atomic_output=True
        options=_analyze_options(request,repo,request.output,[]);options.no_progress=True;options.no_suppress=True;options.echo=lambda *_a,**_k:None
        result=pipeline.run_scan(options)
        assert result.exit_code==0
        folder=current_generation(options.output);validate_generation(folder)
        return folder,json.loads((folder/"run-manifest.json").read_text())
    return client,scan


def test_dispatch_matrix_and_exact_findings_bytes_hash_invariance(engine):
    client,scan=engine;baseline=None
    for mode in MODES:
        client.calls.clear();folder,manifest=scan(mode)
        findings=(folder/"findings.json").read_bytes()
        if baseline is None:baseline=findings
        assert findings==baseline
        assert hashlib.sha256(findings).digest()==hashlib.sha256(baseline).digest()
        outcome=manifest["desktop_ai"]
        assert outcome["mode"]==mode
        if mode=="none":
            assert not client.calls and outcome["status"]=="not_requested"
            continue
        expected=["hunt_generate","hunt_skeptic","hunt_skeptic","hunt_skeptic"] if mode=="hunt_verify" else [mode]
        assert [call[0] for call in client.calls]==expected
        assert outcome["status"] in {"completed","partial"} and outcome["model_output_available"]
        assert manifest["ai_allowance"]["calls_reserved"]==len(expected)
        assert (folder/ARTIFACTS[mode][0]).is_file()
        if mode in {"review","remediate","triage"}:
            metadata=json.loads((folder/ARTIFACTS[mode][1]).read_text())
            assert metadata["reference_validation"]["claim_support"]=="not_assessed"


@pytest.mark.parametrize("mode", ["review","hunt","remediate","triage"])
def test_unavailable_never_becomes_completed_and_triage_stays_fallback(engine,mode):
    client,scan=engine;client.fail=True
    folder,manifest=scan(mode,max_calls=1)
    outcome=manifest["desktop_ai"]
    assert len(client.calls)==1 and not outcome["model_output_available"]
    assert outcome["status"]==("fallback" if mode=="triage" else "unavailable")
    assert (folder/ARTIFACTS[mode][0]).exists()==(mode=="triage")
    assert (folder/ARTIFACTS[mode][1]).exists()==(mode=="triage")


@pytest.mark.parametrize("limiter", ["calls","output","time"])
def test_jury_shares_one_ledger_and_no_attempt_after_exhaustion(engine,limiter):
    client,scan=engine
    now=[0.0]
    ledger=AiBudget(max_calls=1 if limiter=="calls" else 8,max_seconds=5,output_token_limit=5 if limiter=="output" else 100000,clock=lambda:now[0])
    if limiter=="output":client.missing_usage=True
    if limiter=="time":client.clock_hook=lambda:now.__setitem__(0,6.0)
    with budget_scope(ledger):
        folder,manifest=scan("hunt_verify")
        assert current_budget() is ledger
    assert len(client.calls)==ledger.calls_reserved==1
    assert manifest["desktop_ai"]["status"]=="partial"
    assert manifest["ai_allowance"]["calls_reserved"]==1
    assert ledger.reserved_output_tokens<=ledger.output_token_limit


def test_stale_output_cannot_masquerade_as_this_run_completion(tmp_path):
    (tmp_path/"defensive-review-llm.md").write_text("old output")
    (tmp_path/"defensive-review-llm.meta.json").write_text(json.dumps({"backend":"api","model":"old"}))
    result=manifest_ai_result("review",tmp_path,None,{})
    assert result["status"]=="unavailable" and result["artifact"] is None


@pytest.mark.parametrize("stop,allowance",[("max_tokens",{}),("completed",{"output_limit_violations":1})])
def test_truncation_or_reported_limit_violation_remains_partial(tmp_path,stop,allowance):
    (tmp_path/"defensive-review-llm.md").write_text("synthetic returned text")
    (tmp_path/"defensive-review-llm.meta.json").write_text(json.dumps({"backend":"api","model":"fake","stop_reason":stop}))
    result=manifest_ai_result("review",tmp_path,allowance,{"review":True})
    assert result["status"]=="partial" and result["model_output_available"]


def test_single_pass_verify_and_openai_effort_mapping_are_explicit(engine):
    client,scan=engine
    _,manifest=scan("hunt_verify",jury_votes=1,effort="max")
    assert [mode for mode,_ in client.calls]==["hunt_verify"]
    assert client.calls[0][1]["reasoning"]["effort"]=="high"
    parameters=manifest["desktop_ai"]["service_parameters"]
    assert parameters["requested_effort"]=="max" and parameters["mapped_effort"]=="high"
    assert parameters["jury_votes"]==1


@pytest.mark.parametrize("mode", [m for m in MODES if m!="none"])
def test_each_ai_mode_remains_rejected_for_fleet(tmp_path,mode):
    request=scan_request_from_run(validate_desktop_request(payload(tmp_path,mode)))
    request.repo_paths.append(tmp_path/"other")
    assert _fleet_incompatible_flags(request)
