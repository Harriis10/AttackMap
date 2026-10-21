"""Mock HTTP fixtures only: no live provider or local server is contacted."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

try:
    import httpx2 as httpx  # Current installed OpenAI/Anthropic SDK transport.
except ImportError:
    import httpx  # Older supported SDK releases.
import pytest

from attackmap import ai_http_audit as audit
from attackmap.llm_review import _loopback_transport


def enabled(monkeypatch, tmp_path):
    monkeypatch.setenv(audit.DIRECTORY_ENV, str(tmp_path))
    monkeypatch.setenv(audit.NONCE_ENV, "fixture-run")
    return audit.client_audit_options(audit.ENDPOINT)


def records(tmp_path):
    log, = tmp_path.glob("wp017-*/http-audit.jsonl")
    return log, [json.loads(line) for line in log.read_text().splitlines()]


def payload(**changes):
    return dict(id="resp-fixture", model=audit.MODEL, status="completed",
                output=[dict(type="message", content=[dict(type="output_text", text="Generated fixture output")])], **changes)


def test_default_disabled_has_no_path_access(monkeypatch):
    monkeypatch.delenv(audit.DIRECTORY_ENV, raising=False)
    monkeypatch.setattr(Path, "lstat", lambda *args: (_ for _ in ()).throw(AssertionError("filesystem access")))
    assert audit.client_audit_options(None) == {}


def test_actual_response_bytes_observed_without_changing_messages(monkeypatch, tmp_path):
    options = enabled(monkeypatch, tmp_path)
    request_body = dict(model=audit.MODEL, input="Private request fixture prompt")
    seen = []
    reply = json.dumps(payload()).encode()
    def handle(request):
        seen.append((request.method, str(request.url), request.content, request.headers["authorization"]))
        return httpx.Response(200, content=reply, headers={"x-request-id": "req-fixture"})
    with httpx.Client(transport=httpx.MockTransport(handle), **options) as client:
        response = client.post(audit.ENDPOINT + "/responses", json=request_body, headers={"authorization": "Bearer private-credential"})
        assert response.content == reply
    assert len(seen) == 1 and json.loads(seen[0][2]) == request_body
    assert seen[0][3] == "Bearer private-credential"
    log, events = records(tmp_path)
    assert [e["event"] for e in events] == ["audit_started", "attempted_dispatch", "http_response_received", "observation_complete"]
    final = events[-1]
    assert final["completed"] is True and final["body_bytes"] == len(reply)
    assert final["body_sha256"] == hashlib.sha256(reply).hexdigest()
    output = (log.parent / final["output_file"]).read_bytes()
    assert output == b"Generated fixture output" and hashlib.sha256(output).hexdigest() == final["output_sha256"]
    assert final["output_bytes"] == len(output)
    assert events[1]["attempt_id"] == events[2]["attempt_id"] == final["attempt_id"]
    text = log.read_text()
    assert "private-credential" not in text and "Private request fixture prompt" not in text
    assert "Generated fixture output" not in text
    assert events[2]["provider_request_id"] == "req-fixture"


@pytest.mark.parametrize("body,status", [(b"not json", 200), (b"x" * (audit.MAX_BODY + 1), 200),
    (json.dumps(dict(model=audit.MODEL, status="completed", output=[])).encode(), 200),
    (json.dumps(dict(model=audit.MODEL, status="incomplete", output_text="Partial fixture")).encode(), 200),
    (json.dumps(dict(model=audit.MODEL, status="completed", output_text="Error fixture")).encode(), 500),
    (json.dumps(dict(model="unexpected", status="completed", output_text="Wrong model")).encode(), 200)],
    ids=["malformed", "oversized", "empty", "incomplete", "http-error", "wrong-model"])
def test_incomplete_malformed_or_failed_is_not_model_completion(monkeypatch, tmp_path, body, status):
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(status, content=body)), **enabled(monkeypatch, tmp_path)) as client:
        assert client.post(audit.ENDPOINT + "/responses", json={"model": audit.MODEL}).content == body
    _, events = records(tmp_path)
    assert events[-1]["event"] == "observation_complete" and events[-1]["completed"] is False
    assert events[-1]["output_file"] is None
    assert not list(tmp_path.glob("wp017-*/output-*"))


@pytest.mark.parametrize("request_payload", [{"model": "wrong"}, {"model": audit.MODEL, "stream": True}])
def test_wrong_model_streaming_rejected_before_dispatch(monkeypatch, tmp_path, request_payload):
    called = []
    with httpx.Client(transport=httpx.MockTransport(lambda _: called.append(True)), **enabled(monkeypatch, tmp_path)) as client:
        with pytest.raises(audit.AuditConfigurationError):
            client.post(audit.ENDPOINT + "/responses", json=request_payload)
    assert not called


def test_timeout_is_attempt_only_no_retry_or_completed_proof(monkeypatch, tmp_path):
    calls = []
    def timeout(request):
        calls.append(True)
        raise httpx.ReadTimeout("private detail", request=request)
    with httpx.Client(transport=httpx.MockTransport(timeout), **enabled(monkeypatch, tmp_path)) as client:
        with pytest.raises(httpx.ReadTimeout):
            client.post(audit.ENDPOINT + "/responses", json={"model": audit.MODEL})
    assert calls == [True]
    _, events = records(tmp_path)
    assert [e["event"] for e in events] == ["audit_started", "attempted_dispatch"]
    assert "private detail" not in json.dumps(events)


def test_invalid_path_endpoint_nonce_fail_before_client_creation(monkeypatch, tmp_path):
    monkeypatch.setenv(audit.DIRECTORY_ENV, str(tmp_path / "missing"))
    monkeypatch.setenv(audit.NONCE_ENV, "fixture-run")
    with pytest.raises(audit.AuditConfigurationError):
        audit.client_audit_options(audit.ENDPOINT)
    monkeypatch.setenv(audit.DIRECTORY_ENV, str(tmp_path))
    with pytest.raises(audit.AuditConfigurationError):
        audit.client_audit_options("https://example.invalid/v1")
    monkeypatch.setenv(audit.NONCE_ENV, "../bad")
    with pytest.raises(audit.AuditConfigurationError):
        audit.client_audit_options(audit.ENDPOINT)


def test_reused_outer_directory_never_overwrites_other_logs(monkeypatch, tmp_path):
    unrelated = tmp_path / "unrelated.log"
    unrelated.write_text("preserve")
    enabled(monkeypatch, tmp_path)
    enabled(monkeypatch, tmp_path)
    assert len(list(tmp_path.glob("wp017-*/http-audit.jsonl"))) == 2
    assert unrelated.read_text() == "preserve"


def test_sdk_factory_retains_existing_transport_options(monkeypatch, tmp_path):
    monkeypatch.delenv(audit.DIRECTORY_ENV, raising=False)
    captured = []
    sdk = SimpleNamespace(__name__="openai", DefaultHttpxClient=lambda **kwargs: captured.append(kwargs))
    _loopback_transport(sdk, audit.ENDPOINT)
    assert captured[-1] == {"trust_env": False, "follow_redirects": False}
    monkeypatch.setenv(audit.DIRECTORY_ENV, str(tmp_path))
    monkeypatch.setenv(audit.NONCE_ENV, "fixture-run")
    _loopback_transport(sdk, audit.ENDPOINT)
    assert captured[-1]["trust_env"] is False and captured[-1]["follow_redirects"] is False
    assert set(captured[-1]) == {"trust_env", "follow_redirects", "event_hooks"}


def test_audit_output_failure_does_not_replace_provider_response(monkeypatch, tmp_path):
    options = enabled(monkeypatch, tmp_path)
    observer = options["event_hooks"]["response"][0].__self__
    original = observer._write
    def fail(event, **fields):
        if event == "observation_complete":
            raise audit.AuditConfigurationError("fixture disk failure")
        original(event, **fields)
    monkeypatch.setattr(observer, "_write", fail)
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload())), **options) as client:
        assert client.post(audit.ENDPOINT + "/responses", json={"model": audit.MODEL}).status_code == 200
    _, events = records(tmp_path)
    assert "observation_complete" not in [e["event"] for e in events]


def test_installed_openai_sdk_uses_its_original_client_policy(monkeypatch, tmp_path):
    import openai
    monkeypatch.setenv(audit.DIRECTORY_ENV, str(tmp_path))
    monkeypatch.setenv(audit.NONCE_ENV, "fixture-run")
    transport = _loopback_transport(openai, audit.ENDPOINT)["http_client"]
    assert isinstance(transport, openai.DefaultHttpxClient)
    assert transport.trust_env is False and transport.follow_redirects is False
    calls = []
    def handle(request):
        calls.append((request.method, str(request.url)))
        return httpx.Response(200, json=payload())
    # Replace only the test client's network transport. Production factory and
    # client options remain exactly as constructed above; no socket is opened.
    transport._transport = httpx.MockTransport(handle)
    with openai.OpenAI(api_key="fixture-never-sent-to-network", base_url=audit.ENDPOINT,
                       http_client=transport, max_retries=0) as client:
        result = client.responses.create(model=audit.MODEL, input="Private SDK fixture prompt")
        assert result.output_text == "Generated fixture output"
    assert calls == [("POST", audit.ENDPOINT + "/responses")]
    _, events = records(tmp_path)
    assert events[-1]["completed"] is True
