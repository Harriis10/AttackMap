"""Explicit local allowances reach the SDK without resetting shared deadlines."""
from types import SimpleNamespace
import sys

import pytest

from attackmap.ai_budget import AiBudget, budget_scope, current_reservation
from attackmap.hunt_harness import run_majority_verify
from attackmap.llm_review import LlmReviewError, generate_llm_review
from attackmap.models import ScanResult


class FakeOpenAI:
    def __init__(self, endpoint="http://127.0.0.1:1234/v1", *, now=None, cost=0, option_cost=0, fail=False):
        self.base_url = endpoint
        self.responses = self
        self.calls, self.options, self.reservations = [], [], []
        self.now, self.cost, self.option_cost, self.fail = now, cost, option_cost, fail

    def with_options(self, **kwargs):
        self.options.append(kwargs)
        if self.now is not None:
            self.now[0] += self.option_cost
        return self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        self.reservations.append(current_reservation())
        if self.now is not None:
            self.now[0] += self.cost
        if self.fail:
            raise RuntimeError("fixture transport failure")
        return SimpleNamespace(output_text="=== HYPOTHESES ===\nH1: issue [evidence: taint:1]\n",
                               model="fixture", status="completed",
                               usage=SimpleNamespace(input_tokens=7, output_tokens=3))


@pytest.fixture(autouse=True)
def isolated_endpoint(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("ATTACKMAP_QA_HTTP_AUDIT_DIR", raising=False)


def call(client, budget=None, **kwargs):
    return generate_llm_review(ScanResult(root="fixture"), [], [], [], provider="openai",
                               backend="api", openai_client=client, budget=budget,
                               max_tokens=32000, mode="hunt", **kwargs)


@pytest.mark.parametrize("endpoint,seconds,consumed,expected", [
    ("http://127.0.0.1:1234/v1", 3600, 100, 3500),
    ("http://127.0.0.1:1234/v1", 3600, 2800, 800),
    ("http://127.0.0.1:1234/v1", 900, 0, 900),
    ("http://127.0.0.1:1234/v1", 901, 0, 901),
    ("http://127.0.0.1:1234/v1", 1, 0, 1),
    ("http://127.0.0.1:1234/v1", 7200, 0, 3600),
    ("http://127.25.0.1:1234/v1", 3600, 0, 3600),
    ("http://[::1]:1234/v1", 3600, 0, 3600),
    ("http://localhost:1234/v1", 3600, 0, 3600),
    ("https://127.0.0.1:1234/v1", 3600, 0, 900),
    ("http://127.0.0.1.evil.invalid:1234/v1", 3600, 0, 900),
    ("http://192.168.1.2:1234/v1", 3600, 0, 900),
    ("https://api.openai.com/v1", 3600, 0, 900),
    ("http://user@127.0.0.1:1234/v1", 3600, 0, 900),
    ("http://127.0.0.1:invalid/v1", 3600, 0, 900),
    ("http://127.0.0.1:0/v1", 3600, 0, 900),
])
def test_endpoint_and_allowance_boundaries(endpoint, seconds, consumed, expected):
    now = [0.0]
    budget = AiBudget(max_calls=1, max_seconds=seconds, clock=lambda: now[0])
    now[0] = consumed
    client = FakeOpenAI(endpoint)
    call(client, budget)
    assert client.calls[0]["timeout"] == expected
    assert client.options == [{"max_retries": 0, "timeout": expected}]
    assert client.calls[0]["max_output_tokens"] == 32000
    assert client.reservations[0].ledger is budget
    assert budget.calls_reserved == budget.calls_settled == 1


def test_local_without_explicit_allowance_keeps_default():
    client = FakeOpenAI()
    call(client)
    assert 899 < client.calls[0]["timeout"] <= 900
    assert client.options[0]["max_retries"] == 0


@pytest.mark.parametrize("endpoint", ["https://api.openai.com/v1", ""])
def test_explicit_client_target_precedes_ambient_local_url(monkeypatch, endpoint):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:1234/v1")
    client = FakeOpenAI(endpoint)
    call(client, AiBudget(max_calls=1, max_seconds=3600, clock=lambda: 0))
    assert client.calls[0]["timeout"] == 900


def test_constructor_options_and_request_use_remaining_local_allowance(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    now = [0.0]
    budget = AiBudget(max_calls=1, max_seconds=3600, clock=lambda: now[0])
    now[0] = 100.0
    constructors, transports = [], []
    client = FakeOpenAI(now=now, option_cost=10)

    def construct(**kwargs):
        constructors.append(kwargs)
        client.base_url = kwargs["base_url"]
        now[0] += 20
        return client

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(
        OpenAI=construct, DefaultHttpxClient=lambda **kwargs: transports.append(kwargs)))
    call(None, budget)
    assert constructors[0]["timeout"] == 3500
    assert constructors[0]["max_retries"] == 0
    assert constructors[0]["base_url"] == "http://127.0.0.1:1234/v1"
    assert transports == [{"trust_env": False, "follow_redirects": False}]
    assert client.options == [{"max_retries": 0, "timeout": 3480}]
    assert client.calls[0]["timeout"] == 3470


def test_active_budget_and_late_dispatch_keep_consumed_time():
    now = [0.0]
    budget = AiBudget(max_calls=2, max_seconds=3600, clock=lambda: now[0])
    client = FakeOpenAI(now=now, cost=1000, option_cost=10)
    with budget_scope(budget):
        call(client)
        call(client)
    assert [request["timeout"] for request in client.calls] == [3590, 2580]
    assert all(reservation.ledger is budget for reservation in client.reservations)
    assert budget.remaining_seconds == 1580


def test_local_transport_failure_never_retries_implicitly():
    client = FakeOpenAI(fail=True)
    budget = AiBudget(max_calls=1, max_seconds=3600)
    with pytest.raises(LlmReviewError, match="fixture transport failure"):
        call(client, budget)
    with pytest.raises(LlmReviewError, match="call allowance"):
        call(client, budget)
    assert len(client.calls) == 1 and client.options[0]["max_retries"] == 0
    assert budget.unknown_output_usage_calls == 1


@pytest.mark.parametrize("endpoint,expected", [
    ("http://127.0.0.1:1234/v1", [3500, 2500, 1500, 500]),
    ("https://api.openai.com/v1", [900, 900, 900, 500]),
])
def test_hunt_jury_shares_one_deadline_and_exhaustion_abstains(endpoint, expected):
    now = [0.0]
    budget = AiBudget(max_calls=5, max_seconds=3600, clock=lambda: now[0])
    now[0] = 100
    client = FakeOpenAI(endpoint, now=now, cost=1000)

    def provider(mode, **kwargs):
        return generate_llm_review(ScanResult(root="."), [], [], [], provider="openai",
            backend="api", openai_client=client, mode=mode, **kwargs)

    result = run_majority_verify(None, [], [], [], votes=4, llm_call=provider, budget=budget)
    assert [request["timeout"] for request in client.calls] == expected
    assert all(reservation.ledger is budget for reservation in client.reservations)
    assert all(option["max_retries"] == 0 for option in client.options)
    assert all(request["max_output_tokens"] == 32000 for request in client.calls)
    assert budget.calls_reserved == budget.calls_settled == 4
    assert result.votes == 4 and result.failed_passes == 1
    assert result.allowance["passes_not_dispatched"] == 1
    assert result.allowance["remaining_seconds"] == 0


def test_hunt_without_explicit_budget_keeps_900_second_deadline():
    client = FakeOpenAI()

    def provider(mode, **kwargs):
        return generate_llm_review(ScanResult(root="."), [], [], [], provider="openai",
            backend="api", openai_client=client, mode=mode, **kwargs)

    result = run_majority_verify(None, [], [], [], votes=2, llm_call=provider)
    assert len(client.calls) == 3
    assert all(899 < request["timeout"] <= 900 for request in client.calls)
    assert result.allowance["max_calls"] == result.allowance["calls_reserved"] == 3
