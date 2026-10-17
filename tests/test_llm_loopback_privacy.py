import sys
from types import SimpleNamespace

import pytest

from attackmap.llm_review import (LlmReviewError, _resolve_backend, _resolve_openai_backend,
                                 _resolve_openai_client, _resolve_sdk_client)


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:1234/v1", "http://127.2.3.4:1234/v1", "http://[::1]:1234/v1"])
def test_literal_loopback_openai_ignores_proxy_environment_and_cloud_keys(monkeypatch, endpoint):
    captured = {}
    monkeypatch.setenv("OPENAI_BASE_URL", endpoint)
    monkeypatch.setenv("OPENAI_API_KEY", "cloud-key-must-not-leave")
    monkeypatch.setenv("HTTP_PROXY", "http://outside.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://outside.invalid:3128")
    def transport(**kwargs):
        captured["transport"] = kwargs
        return SimpleNamespace(policy=kwargs)
    def constructor(**kwargs):
        captured["client"] = kwargs
        return SimpleNamespace()
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(DefaultHttpxClient=transport, OpenAI=constructor))
    _resolve_openai_client("another-cloud-key", None)
    assert captured["transport"] == {"trust_env": False, "follow_redirects": False}
    assert captured["client"]["api_key"] == "attackmap-local"
    assert captured["client"]["base_url"] == endpoint
    assert "cloud-key" not in repr(captured)


def test_literal_loopback_openai_needs_no_cloud_credential(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:1234/v1")
    captured = {}
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(DefaultHttpxClient=lambda **kwargs: object(),
        OpenAI=lambda **kwargs: captured.update(kwargs) or object()))
    _resolve_openai_client(None, None)
    assert captured["api_key"] == "attackmap-local"


def test_remote_openai_constructor_preserves_credentials_and_transport_defaults(monkeypatch):
    captured = {}
    monkeypatch.setenv("OPENAI_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "configured-cloud-key")
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=lambda **kwargs: captured.update(kwargs) or object()))
    _resolve_openai_client(None, None)
    assert captured["api_key"] == "configured-cloud-key"
    assert "http_client" not in captured


def test_literal_loopback_anthropic_uses_isolated_transport_and_placeholder(monkeypatch):
    captured = {}
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:1234")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "cloud-key-must-not-leave")
    monkeypatch.setenv("HTTPS_PROXY", "http://outside.invalid:3128")
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(
        DefaultHttpxClient=lambda **kwargs: captured.update(transport=kwargs) or object(),
        Anthropic=lambda **kwargs: captured.update(client=kwargs) or object()))
    _, auth = _resolve_sdk_client(None, None)
    assert auth == "local"
    assert captured["client"]["api_key"] == "attackmap-local"
    assert captured["transport"] == {"trust_env": False, "follow_redirects": False}


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_auto_local_endpoint_never_falls_back_to_cloud_cli(monkeypatch, provider):
    monkeypatch.setenv(f"{provider.upper()}_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.delenv(f"{provider.upper()}_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(f"attackmap.llm_review._{provider}_sdk_available", lambda: False)
    if provider == "openai":
        monkeypatch.setattr("attackmap.llm_review._codex_cli_available", lambda: True)
        assert _resolve_openai_backend("auto", api_key=None, client=None, codex_runner=None) == "api"
    else:
        monkeypatch.setattr("attackmap.llm_review._claude_cli_available", lambda: True)
        assert _resolve_backend("auto", api_key=None, client=None) == "api"


def test_local_endpoint_embedded_credentials_are_refused(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://user:password@127.0.0.1:1234/v1")
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace())
    with pytest.raises(LlmReviewError, match="embedded credentials"):
        _resolve_openai_client(None, None)


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_localhost_is_pinned_without_dns_and_ignores_cloud_credentials(monkeypatch, provider):
    captured = {}
    monkeypatch.setenv(f"{provider.upper()}_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv(f"{provider.upper()}_API_KEY", "private-cloud-key")
    monkeypatch.setenv("HTTP_PROXY", "http://outside.invalid:3128")
    monkeypatch.setitem(sys.modules, provider, SimpleNamespace(
        DefaultHttpxClient=lambda **kwargs: captured.update(transport=kwargs) or object(),
        **{("OpenAI" if provider == "openai" else "Anthropic"):
           lambda **kwargs: captured.update(client=kwargs) or object()}))
    (_resolve_openai_client if provider == "openai" else _resolve_sdk_client)(None, None)
    assert captured["client"]["base_url"] == "http://127.0.0.1:1234/v1"
    assert captured["client"]["api_key"] == "attackmap-local"
    assert captured["transport"] == {"trust_env": False, "follow_redirects": False}
