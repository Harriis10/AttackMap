"""Desktop privacy boundaries without a real provider or credential."""

import json
import os
import sys
from pathlib import Path

import pytest

from attackmap.ui import secrets
from attackmap.ui.config import ScanConfig
from attackmap.ui.runner import ScanRunner, child_python_env

SENTINEL = "privacy-sentinel-do-not-export-7H2k9P4x"


def test_fresh_config_keeps_optional_network_features_off(tmp_path):
    args = ScanConfig(repos=[tmp_path], output=tmp_path / "reports").cli_args()
    assert not {"--llm", "--hunt", "--verify", "--triage", "--remediate", "--cve"}.intersection(args)


@pytest.mark.parametrize("endpoint", ["http://localhost:1234/v1", "http://127.0.0.1:1234/v1", "http://[::1]:1234/v1"])
def test_local_endpoint_never_receives_saved_cloud_key(monkeypatch, endpoint):
    def forbidden_load(*args):
        pytest.fail("A local endpoint must not load a production credential")

    monkeypatch.setattr(secrets, "load_llm_key", forbidden_load)
    assert secrets.child_llm_env("openai", endpoint) == {
        "OPENAI_BASE_URL": endpoint, "OPENAI_API_KEY": "lm-studio",
    }


@pytest.mark.parametrize("endpoint", ["https://localhost.evil.example/v1", "http://127.0.0.1.evil.example/v1", "file:///localhost", "http://user:pass@localhost/v1"])
def test_loopback_recognition_does_not_trust_hostname_substrings(endpoint):
    assert not secrets.is_loopback_endpoint(endpoint)


def test_secure_store_failure_preserves_existing_blob_and_hides_secret(monkeypatch, tmp_path):
    blob = tmp_path / "llm-openai.key"
    blob.write_bytes(b"previous-encrypted-value")
    monkeypatch.setattr(secrets, "_key_path", lambda provider: blob)

    def fail(data):
        raise OSError("Windows DPAPI could not protect the API key.")

    monkeypatch.setattr(secrets, "_protect", fail)
    with pytest.raises(OSError) as error:
        secrets.save_llm_key(SENTINEL, "openai")
    assert SENTINEL not in str(error.value)
    assert blob.read_bytes() == b"previous-encrypted-value"


def test_unsupported_secure_store_never_saves_or_loads_plaintext(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "unsupported")
    blob = tmp_path / "key"
    monkeypatch.setattr(secrets, "_key_path", lambda provider: blob)
    with pytest.raises(OSError, match="unavailable"):
        secrets.save_llm_key(SENTINEL)
    assert not blob.exists()
    assert secrets._unprotect(SENTINEL.encode()) is None


@pytest.mark.parametrize("mode", ["none", "local", "claude"])
def test_spawn_boundary_strips_inherited_credentials_before_selected_overlay(monkeypatch, tmp_path, mode):
    names = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"]
    for name in names:
        monkeypatch.setenv(name, SENTINEL)
    selected = secrets.child_llm_env("openai", "http://127.0.0.1:1234/v1") if mode == "local" else {}
    if mode == "claude":
        selected = {"ANTHROPIC_API_KEY": "explicit-selected-key"}
    captured = {}

    def popen(**kwargs):
        captured.update(kwargs)
        raise OSError("fixture spawn stopped")

    monkeypatch.setattr("attackmap.ui.runner.subprocess.Popen", popen)
    runner = ScanRunner()
    assert not runner.start(tmp_path, tmp_path / "reports", env=selected)
    assert SENTINEL not in json.dumps(captured)
    for name in names:
        assert captured["env"].get(name) == selected.get(name)
    assert SENTINEL not in runner.stderr_tail
    assert all(os.environ[name] == SENTINEL for name in names)


def test_child_python_env_preserves_unrelated_configuration(monkeypatch):
    monkeypatch.setenv("ATTACKMAP_PRIVACY_TEST", "keep")
    assert child_python_env()["ATTACKMAP_PRIVACY_TEST"] == "keep"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI boundary")
def test_windows_dpapi_blob_is_not_plaintext(monkeypatch, tmp_path):
    blob = tmp_path / "llm-openai.key"
    monkeypatch.setattr(secrets, "_key_path", lambda provider: blob)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    secrets.save_llm_key(SENTINEL, "openai")
    assert SENTINEL.encode() not in blob.read_bytes()
    assert secrets.load_llm_key("openai") == SENTINEL


def test_sentinel_source_secret_is_masked_in_verification_prompt_and_report(tmp_path):
    from attackmap.models import Finding, ScanResult
    from attackmap.review_json import build_defensive_review_json
    from attackmap.review_prompts import render_hunt_verify_prompts

    (tmp_path / "app.py").write_text(f'API_KEY = "{SENTINEL}"\nprint("context retained")\n', encoding="utf-8")
    scan = ScanResult(root=str(tmp_path))
    finding = Finding(title="Credential in source", severity="high", mitigation="Rotate credential", evidence=[f'app.py:1 API_KEY = "{SENTINEL}"'])
    prompt = render_hunt_verify_prompts(scan, [], [finding], [])
    report = build_defensive_review_json(scan, [], [finding], [])
    for text in (prompt.user, prompt.evidence_json, json.dumps(report)):
        assert SENTINEL not in text
        assert "Credential in source" in text
    assert "context retained" in prompt.user
