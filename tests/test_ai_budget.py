from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from attackmap.ai_budget import AiBudget, AiBudgetExhausted, budget_scope, current_reservation
from attackmap.hunt_harness import run_majority_verify
from attackmap.llm_review import LlmReviewError, LlmReviewResult, generate_llm_review
from attackmap.models import ScanResult


def test_reservations_fit_remaining_and_known_usage_refunds_only_unused_output():
    budget = AiBudget(max_calls=2, max_seconds=10, output_token_limit=10)
    first = budget.reserve(max_output_tokens=8, timeout_seconds=100)
    assert first.output_tokens == 8
    assert 0 < first.timeout_seconds <= 10
    first.finish({"output_tokens": 3, "input_tokens": 100000})
    second = budget.reserve(max_output_tokens=8, timeout_seconds=100)
    assert second.output_tokens == 7
    second.finish({"output_tokens": 2})
    assert budget.known_output_tokens == 5
    assert budget.reserved_output_tokens == 5
    with pytest.raises(AiBudgetExhausted, match="call"):
        budget.reserve(max_output_tokens=1, timeout_seconds=1)


def test_missing_usage_keeps_allowance_and_zero_is_reported():
    budget = AiBudget(max_calls=3, max_seconds=10, output_token_limit=5)
    first = budget.reserve(max_output_tokens=5, timeout_seconds=5)
    first.finish({"output_tokens": 0})
    second = budget.reserve(max_output_tokens=5, timeout_seconds=5)
    second.finish(None)
    assert budget.known_output_tokens == 0
    assert budget.unknown_output_usage_calls == 1
    assert budget.reserved_output_tokens == 5
    with pytest.raises(AiBudgetExhausted, match="output-token"):
        budget.reserve(max_output_tokens=1, timeout_seconds=1)


def test_parallel_admission_cannot_exceed_call_or_token_reservations():
    budget = AiBudget(max_calls=3, max_seconds=10, output_token_limit=9)
    def attempt(_):
        try:
            reservation = budget.reserve(max_output_tokens=3, timeout_seconds=3)
            reservation.claim_dispatch()
            reservation.finish(None)
            return True
        except AiBudgetExhausted:
            return False
    with ThreadPoolExecutor(max_workers=10) as pool:
        assert sum(pool.map(attempt, range(30))) == 3
    assert budget.calls_reserved == 3
    assert budget.reserved_output_tokens == 9


def test_expired_or_cancelled_reservation_cannot_dispatch():
    now = [0.0]
    cancelled = [False]
    budget = AiBudget(max_calls=2, max_seconds=5, clock=lambda: now[0],
                      cancelled=lambda: cancelled[0])
    reservation = budget.reserve(max_output_tokens=5, timeout_seconds=20)
    now[0] = 5.0
    with pytest.raises(AiBudgetExhausted, match="wall-time"):
        reservation.claim_dispatch()
    now[0] = 1.0
    cancelled[0] = True
    with pytest.raises(AiBudgetExhausted, match="cancelled"):
        budget.reserve(max_output_tokens=5, timeout_seconds=20)


class FakeOpenAI:
    def __init__(self, *, missing_usage=False, failures=0, text="review"):
        self.responses = self
        self.options = []
        self.calls = []
        self.missing_usage, self.failures, self.text = missing_usage, failures, text
    def with_options(self, **kwargs):
        self.options.append(kwargs)
        return self
    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.failures:
            self.failures -= 1
            raise RuntimeError("injected transport failure")
        return SimpleNamespace(output_text=self.text, model="fake", status="completed",
            usage=None if self.missing_usage else SimpleNamespace(input_tokens=5, output_tokens=1))


def provider_call(client, budget):
    return generate_llm_review(ScanResult(root="fixture"), [], [], [],
        provider="openai", backend="api", openai_client=client, budget=budget, max_tokens=50)


def test_sdk_requests_fit_reservation_and_retries_require_new_allowance():
    budget = AiBudget(max_calls=2, max_seconds=10, output_token_limit=10)
    client = FakeOpenAI(failures=1)
    with pytest.raises(LlmReviewError, match="transport"):
        provider_call(client, budget)
    # A failed transport has unknown usage and keeps its full reservation.
    with pytest.raises(LlmReviewError, match="output-token"):
        provider_call(client, budget)
    assert len(client.calls) == 1
    assert client.calls[0]["max_output_tokens"] == 10
    assert client.options[0]["max_retries"] == 0
    assert 0 < client.calls[0]["timeout"] <= 10


def test_manual_retry_is_a_second_call_and_third_is_rejected():
    budget = AiBudget(max_calls=2, max_seconds=10)
    client = FakeOpenAI(failures=1)
    with pytest.raises(LlmReviewError):
        provider_call(client, budget)
    assert provider_call(client, budget).usage_status == "reported"
    with pytest.raises(LlmReviewError, match="call"):
        provider_call(client, budget)
    assert len(client.calls) == 2
    assert all(option["max_retries"] == 0 for option in client.options)


def test_provider_missing_usage_is_unknown_and_exhausts_its_reserved_output():
    budget = AiBudget(max_calls=2, max_seconds=10, output_token_limit=10)
    client = FakeOpenAI(missing_usage=True)
    result = provider_call(client, budget)
    assert result.usage == {}
    assert result.usage_status == "unknown"
    with pytest.raises(LlmReviewError, match="output-token"):
        provider_call(client, budget)
    assert len(client.calls) == 1


def test_strict_output_budget_refuses_cli_before_dispatch():
    called = []
    with pytest.raises(LlmReviewError, match="API backend"):
        generate_llm_review(ScanResult(root="fixture"), [], [], [], provider="openai",
            backend="cli", codex_runner=lambda *args: called.append(args),
            budget=AiBudget(max_calls=1, max_seconds=10, output_token_limit=5))
    assert not called


def test_all_hunt_lenses_and_verification_share_remaining_reservations():
    calls = []
    def fake(mode, **kwargs):
        reservation = current_reservation()
        calls.append((mode, reservation.output_tokens))
        return LlmReviewResult("=== HYPOTHESES ===\nH1: issue [evidence: taint:1]\n", "fake", None,
                               {"output_tokens": 4}, "api")
    result = run_majority_verify(None, [], [], [], votes=3, llm_call=fake,
        lenses=["one", "two", "three"], token_budget=12, max_output_tokens_per_call=5)
    assert calls == [("hunt_generate", 5), ("hunt_generate", 5), ("hunt_generate", 4)]
    assert result.failed_passes == 3
    assert result.consensus[0].abstained == 3


def test_hunt_unknown_usage_is_never_fabricated_as_token_count():
    calls = []
    def fake(mode, **kwargs):
        calls.append(mode)
        return LlmReviewResult("=== HYPOTHESES ===\nH1: issue [evidence: taint:1]\n", "fake", None, {}, "api")
    result = run_majority_verify(None, [], [], [], votes=2, llm_call=fake,
        lenses=["one", "two", "three"], token_budget=10, max_output_tokens_per_call=5)
    assert calls == ["hunt_generate", "hunt_generate"]
    assert "output_tokens" not in result.usage
    assert result.usage["unknown_output_usage_calls"] == 2


def test_real_provider_adapter_inherits_hunt_reservation_without_double_counting():
    budget = AiBudget(max_calls=3, max_seconds=10, output_token_limit=100)
    client = FakeOpenAI(text="=== HYPOTHESES ===\nH1: issue [evidence: taint:1]\n")
    def fake(mode, **kwargs):
        return generate_llm_review(ScanResult(root="."), [], [], [], mode=mode,
            provider="openai", backend="api", openai_client=client)
    run_majority_verify(None, [], [], [], votes=2, llm_call=fake, budget=budget)
    assert budget.calls_reserved == 3
    assert len(client.calls) == 3


@pytest.mark.parametrize("seconds", [float("nan"), float("inf"), 0, -1])
def test_nonfinite_or_empty_time_allowance_is_rejected(seconds):
    with pytest.raises(ValueError):
        AiBudget(max_calls=1, max_seconds=seconds)


def test_provider_dispatch_after_rendered_deadline_does_not_begin(monkeypatch):
    now = [0.0]
    budget = AiBudget(max_calls=2, max_seconds=5, clock=lambda: now[0])
    client = FakeOpenAI()
    import attackmap.llm_review as module
    render = module.render_review_prompts
    def slow_render(*args):
        result = render(*args)
        now[0] = 6.0
        return result
    monkeypatch.setattr(module, "render_review_prompts", slow_render)
    with pytest.raises(LlmReviewError, match="wall-time"):
        provider_call(client, budget)
    assert not client.calls


def test_cancelled_hunt_does_not_call_any_provider():
    calls = []
    budget = AiBudget(max_calls=5, max_seconds=10, cancelled=lambda: True)
    result = run_majority_verify(None, [], [], [], votes=2,
        llm_call=lambda *args, **kwargs: calls.append(args), budget=budget)
    assert not calls
    assert result.allowance["calls_reserved"] == 0
    assert result.allowance["usage_status"] == "not_attempted"
    assert result.allowance["passes_not_dispatched"] == 1
    assert "planned passes were not run" in result.report
    assert "No hypotheses" not in result.report


def test_multiround_critic_and_skeptic_reserve_from_same_call_ledger():
    calls = []
    budget = AiBudget(max_calls=2, max_seconds=10)
    def fake(mode, **kwargs):
        calls.append(mode)
        return LlmReviewResult("=== HYPOTHESES ===\nH1: issue [evidence: taint:1]\n", "fake", None,
                               {"output_tokens": 1}, "api")
    result = run_majority_verify(None, [], [], [], votes=3, max_rounds=5, llm_call=fake, budget=budget)
    assert calls == ["hunt_generate", "hunt_critic"]
    assert result.allowance["calls_reserved"] == 2
    assert result.failed_passes == 3


def test_shared_budget_cannot_be_replaced_by_a_fresh_provider_ledger():
    shared = AiBudget(max_calls=1, max_seconds=10, output_token_limit=1)
    fresh = AiBudget(max_calls=5, max_seconds=10)
    client = FakeOpenAI()
    with budget_scope(shared), pytest.raises(LlmReviewError, match="replace"):
        provider_call(client, fresh)
    assert not client.calls


def test_each_dispatch_requires_unique_reservation_and_usage_overrun_blocks_next():
    budget = AiBudget(max_calls=2, max_seconds=10, output_token_limit=5)
    reservation = budget.reserve(max_output_tokens=5, timeout_seconds=5)
    reservation.claim_dispatch()
    with pytest.raises(AiBudgetExhausted, match="own reservation"):
        reservation.claim_dispatch()
    reservation.finish({"output_tokens": 6})
    assert budget.snapshot()["output_limit_violations"] == 1
    with pytest.raises(AiBudgetExhausted):
        budget.reserve(max_output_tokens=1, timeout_seconds=1)


@pytest.mark.parametrize("invalid", [True, -1, "0", None])
def test_malformed_usage_is_unknown_instead_of_reported_zero(invalid):
    from attackmap.llm_review import _openai_usage, _usage_dict
    payload = SimpleNamespace(output_tokens=invalid)
    assert "output_tokens" not in _openai_usage(payload)
    assert "output_tokens" not in _usage_dict(payload)
    budget = AiBudget(max_calls=1, max_seconds=10, output_token_limit=5)
    budget.reserve(max_output_tokens=5, timeout_seconds=5).finish({"output_tokens": invalid})
    assert budget.snapshot()["unknown_output_usage_calls"] == 1
    assert budget.snapshot()["output_tokens_charged_or_reserved"] == 5
