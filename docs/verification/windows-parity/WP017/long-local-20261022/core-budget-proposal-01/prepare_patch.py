"""Evidence-only proposal generator; imports no product/test modules."""
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[6]
FILES = {
    "src/attackmap/provider_options.py": "provider_options",
    "tests/test_provider_options.py": "test_provider_options",
    "tests/test_local_provider_timeouts.py": "test_local_provider_timeouts",
}

def sha(data):
    return hashlib.sha256(data).hexdigest()

before = {name: sha((ROOT / name).read_bytes()) for name in FILES}
original = {name: (HERE / (stem + ".before.py")).read_text(encoding="utf-8") for name, stem in FILES.items()}
for name, text in original.items():
    if (ROOT / name).read_text(encoding="utf-8") != text:
        raise RuntimeError("Active source changed since proposal copy: " + name)
proposed = dict(original)
name = "src/attackmap/provider_options.py"
proposed[name] = proposed[name].replace(
    "timeout_seconds: int = Field(default=600, ge=1, le=3600)",
    "timeout_seconds: int = Field(default=600, ge=1, le=7200)", 1)
proposed[name] = proposed[name].replace("from typing import Literal", "import re\nfrom typing import Literal", 1)
anchor = '    @field_validator("model")\n'
validator = '''    @model_validator(mode="after")
    def local_extended_allowance(self) -> ProviderOptions:
        if self.timeout_seconds <= 3600:
            return self
        endpoint = urlsplit(self.endpoint or "")
        if (self.provider != "openai" or endpoint.scheme != "http"
                or endpoint.hostname not in {"localhost", "127.0.0.1", "::1"}
                or endpoint.username is not None or endpoint.password is not None
                or endpoint.query or endpoint.fragment
                or "?" in (self.endpoint or "") or "#" in (self.endpoint or "")
                or (endpoint.port is not None and endpoint.port <= 0)
                or re.match(r"\\Ahttp://(?:localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?(?:/|\\Z)",
                            self.endpoint or "", re.IGNORECASE) is None):
            raise ValueError("AI allowances above 3600 seconds require local OpenAI HTTP")
        return self

'''
if proposed[name].count(anchor) != 1:
    raise RuntimeError("Unexpected provider validator anchor")
proposed[name] = proposed[name].replace(anchor, validator + anchor, 1)
name = "tests/test_provider_options.py"
proposed[name] = proposed[name].replace(
    "LOCAL_MODEL, ProviderOptions", "LOCAL_MODEL, ProviderOptions, ProviderOptionsV13", 1)
proposed[name] = proposed[name].replace("{'timeout_seconds':3601}", "{'timeout_seconds':7201}", 1)
proposed[name] += '''

@pytest.mark.parametrize("model", [ProviderOptions, ProviderOptionsV13])
@pytest.mark.parametrize("endpoint", [
    "http://127.0.0.1:1234/v1", "http://localhost:1234/v1",
    "http://[::1]:1234/v1", "http://localhost/v1", "HTTP://LOCALHOST:1234/v1",
    "http://127.0.0.1:01234/v1",
    "  http://localhost:1234/v1  ",
])
@pytest.mark.parametrize("seconds", [3601, 7200])
def test_explicit_local_total_allowance_roundtrips(model, endpoint, seconds):
    options = model(enable_ai=True, endpoint=endpoint, timeout_seconds=seconds)
    assert options.timeout_seconds == seconds
    assert (options.max_calls, options.output_token_limit) == (8, 32000)
    assert model.model_validate_json(options.model_dump_json()) == options


@pytest.mark.parametrize("model", [ProviderOptions, ProviderOptionsV13])
@pytest.mark.parametrize("target", [
    {"endpoint": "https://provider.example/v1"},
    {"endpoint": "https://localhost:1234/v1"},
    {"endpoint": "https://127.0.0.1:1234/v1"},
    {"endpoint": "https://[::1]:1234/v1"},
    {"endpoint": "https://127.0.0.1.attacker.example/v1"},
    {"endpoint": None},
    {"endpoint": " "},
    {"provider": "claude", "endpoint": LOCAL_ENDPOINT},
    {"endpoint": "http://127.0.0.1:0/v1"},
    {"endpoint": "http://localhost:/v1"},
    {"endpoint": "http://127.0.0.1:/v1"},
    {"endpoint": "http://[::1]:/v1"},
    {"endpoint": "http://localhost:+1234/v1"},
    {"endpoint": "http://localhost:-1234/v1"},
    {"endpoint": "http://localhost: 1234/v1"},
    {"endpoint": "http://localhost:1234 /v1"},
    {"endpoint": "http://localhost:１２３４/v1"},
    {"endpoint": "http://localhost:invalid/v1"},
    {"endpoint": "http://user:SENTINEL@localhost:1234/v1"},
    {"endpoint": "http://localhost:1234/v1?key=SENTINEL"},
    {"endpoint": "http://localhost:1234/v1#SENTINEL"},
    {"endpoint": "http://localhost:1234/v1?"},
    {"endpoint": "http://localhost:1234/v1#"},
])
def test_extended_allowance_never_promotes_other_targets(model, target, monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", LOCAL_ENDPOINT)
    with pytest.raises(ValidationError) as error:
        model(enable_ai=True, timeout_seconds=3601, **target)
    assert "SENTINEL" not in str(error.value)


@pytest.mark.parametrize("model", [ProviderOptions, ProviderOptionsV13])
@pytest.mark.parametrize("seconds", [True, 7200.0, "7200", 0, 7201])
def test_extended_allowance_retains_strict_integer_bound(model, seconds):
    with pytest.raises(ValidationError):
        model(timeout_seconds=seconds)


@pytest.mark.parametrize("model", [ProviderOptions, ProviderOptionsV13])
def test_remote_ceiling_and_defaults_remain_unchanged(model):
    options = model(endpoint="https://provider.example/v1", timeout_seconds=3600)
    assert options.timeout_seconds == 3600
    assert (model().timeout_seconds, model().max_calls, model().output_token_limit) == (600, 8, 32000)
    with pytest.raises(ValidationError):
        ProviderOptionsV13(enable_ai=True, timeout_seconds=7200, backend="cli")
'''
name = "tests/test_local_provider_timeouts.py"
proposed[name] += '''

def test_explicit_two_hour_total_keeps_one_jury_deadline_and_one_hour_call_cap():
    now = [0.0]
    budget = AiBudget(max_calls=8, max_seconds=7200, clock=lambda: now[0])
    client = FakeOpenAI(now=now, cost=1000)

    def provider(mode, **kwargs):
        return generate_llm_review(ScanResult(root="."), [], [], [], provider="openai",
            backend="api", openai_client=client, mode=mode, **kwargs)

    result = run_majority_verify(None, [], [], [], votes=3, llm_call=provider, budget=budget)
    assert [request["timeout"] for request in client.calls] == [3600, 3600, 3600, 3600]
    assert all(reservation.ledger is budget for reservation in client.reservations)
    assert all(option["max_retries"] == 0 for option in client.options)
    assert all(request["max_output_tokens"] == 32000 for request in client.calls)
    assert budget.calls_reserved == budget.calls_settled == 4
    assert budget.remaining_seconds == 3200
    assert result.votes == 3 and result.failed_passes == 0


def test_two_hour_jury_clamps_remaining_time_then_exhausts_without_reset():
    now = [0.0]
    budget = AiBudget(max_calls=8, max_seconds=7200, clock=lambda: now[0])
    now[0] = 100.0
    client = FakeOpenAI(now=now, cost=2500)

    def provider(mode, **kwargs):
        return generate_llm_review(ScanResult(root="."), [], [], [], provider="openai",
            backend="api", openai_client=client, mode=mode, **kwargs)

    result = run_majority_verify(None, [], [], [], votes=3, llm_call=provider, budget=budget)
    assert [request["timeout"] for request in client.calls] == [3600, 3600, 2100]
    assert all(reservation.ledger is budget for reservation in client.reservations)
    assert all(option["max_retries"] == 0 for option in client.options)
    assert budget.calls_reserved == budget.calls_settled == 3
    assert budget.remaining_seconds == 0
    assert result.votes == 3 and result.failed_passes == 1
    assert result.allowance["passes_not_dispatched"] == 1
    assert result.allowance["remaining_seconds"] == 0
'''

patch = ""
for name, stem in FILES.items():
    (HERE / (stem + ".proposed.py")).write_text(proposed[name], encoding="utf-8", newline="\n")
    patch += "".join(difflib.unified_diff(original[name].splitlines(keepends=True),
        proposed[name].splitlines(keepends=True), fromfile="a/" + name, tofile="b/" + name))
patch_path = HERE.parent / "newlong-budget-core.patch"
if patch_path.exists():
    raise RuntimeError("Refuse replacing evidence patch")
patch_path.write_text(patch, encoding="utf-8", newline="\n")
after = {name: sha((ROOT / name).read_bytes()) for name in FILES}
proof = dict(scope="Evidence-only unified diff; not applied, imported, or tested",
             source_hashes_before=before, source_hashes_after=after,
             source_unchanged=before == after, patch_sha256=sha(patch_path.read_bytes()),
             patch=str(patch_path), proposed_files=list(FILES), tests_executed=False)
(HERE / "source-hash-proof.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
if before != after:
    raise RuntimeError("Active source changed while preparing evidence patch")
print(json.dumps(proof, indent=2))
