"""Exercise the actual SDK wire format without contacting an external provider."""
import json

import pytest

httpx = pytest.importorskip("httpx")
OpenAI = pytest.importorskip("openai").OpenAI

from attackmap.llm_review import LlmReviewError, _run_via_openai_sdk


def invoke(client):
    return _run_via_openai_sdk("System scope", "Selected evidence", model="glm-5.3-flash",
                               effort="high", max_tokens=123, api_key=None, client=client)


@pytest.mark.parametrize("endpoint", ["https://api.z.ai/api/coding/paas/v4", "https://compatible.example/v1/"])
def test_custom_endpoint_chat_wire_format_and_usage(endpoint):
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"id": "chatcmpl-test", "object": "chat.completion",
            "created": 0, "model": "glm-5.3-flash", "choices": [{"index": 0,
            "message": {"role": "assistant", "content": "  Verified transport  ", "reasoning_content": "Do not display"},
            "finish_reason": "stop"}], "usage": {"prompt_tokens": 34, "completion_tokens": 12, "total_tokens": 46}})
    with OpenAI(api_key="test-only-credential", base_url=endpoint, max_retries=0,
                http_client=httpx.Client(transport=httpx.MockTransport(respond))) as client:
        result = invoke(client)
    assert len(requests) == 1
    assert str(requests[0].url) == endpoint.rstrip("/") + "/chat/completions"
    assert requests[0].headers["authorization"] == "Bearer test-only-credential"
    assert json.loads(requests[0].content) == {"model": "glm-5.3-flash", "max_tokens": 123,
        "messages": [{"role": "system", "content": "System scope"}, {"role": "user", "content": "Selected evidence"}]}
    assert result.markdown == "Verified transport"
    assert result.usage == {"input_tokens": 34, "output_tokens": 12}
    assert result.stop_reason == "stop"


@pytest.mark.parametrize("endpoint", ["https://api.openai.com/v1", "http://127.0.0.1:1234/v1"])
def test_established_responses_endpoints_preserved(endpoint):
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"id": "resp-test", "object": "response", "created_at": 0,
            "model": "test", "status": "completed", "output": [{"type": "message", "id": "msg-test",
            "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "OK", "annotations": []}]}]})
    with OpenAI(api_key="test", base_url=endpoint, http_client=httpx.Client(transport=httpx.MockTransport(respond))) as client:
        result = invoke(client)
    assert str(requests[0].url).endswith("/responses")
    assert json.loads(requests[0].content)["max_output_tokens"] == 123
    assert result.markdown == "OK" and result.usage == {}


@pytest.mark.parametrize("failure", ["http", "empty", "reasoning_only"])
def test_chat_failure_is_not_retried_or_treated_as_review(failure):
    requests = []
    def respond(request):
        requests.append(request)
        if failure == "http":
            return httpx.Response(404, json={"error": {"message": "Unknown model"}})
        return httpx.Response(200, json={"id": "test", "object": "chat.completion", "created": 0,
            "model": "test", "choices": [] if failure == "empty" else [{"index": 0,
            "message": {"role": "assistant", "content": None, "reasoning_content": "Thinking"}, "finish_reason": "length"}]})
    with OpenAI(api_key="test", base_url="https://api.z.ai/api/coding/paas/v4",
                http_client=httpx.Client(transport=httpx.MockTransport(respond))) as client:
        with pytest.raises(LlmReviewError):
            invoke(client)
    assert len(requests) == 1


def test_model_listing_warning_is_visible(monkeypatch):
    import openai
    from attackmap.desktop_provider import execute_provider_action
    from types import SimpleNamespace
    monkeypatch.setenv("ATTACKMAP_ACTION_CREDENTIAL", "test")
    monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: SimpleNamespace(
        models=SimpleNamespace(list=lambda: SimpleNamespace(data=[SimpleNamespace(id="glm-5.3-flash")])), close=lambda: None))
    result = execute_provider_action("provider_check", {"configuration": {
        "endpoint": "https://api.z.ai/api/coding/paas/v4", "model": "GLM-5.3-Flash"}})
    assert result["selected_model_listed"] is False
    assert "NOT listed" in result["message"]
