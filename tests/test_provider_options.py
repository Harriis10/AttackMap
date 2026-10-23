import pytest
from pydantic import ValidationError
from attackmap.provider_options import LOCAL_ENDPOINT, LOCAL_MODEL, ProviderOptions, ProviderOptionsV13


def test_defaults_are_local_disabled_and_credential_free():
    options = ProviderOptions()
    assert not options.enable_ai
    assert options.endpoint == LOCAL_ENDPOINT and options.model == LOCAL_MODEL
    assert (options.max_calls, options.timeout_seconds, options.output_token_limit) == (8,600,32000)
    assert 'key' not in options.model_dump_json() and 'credential' not in options.model_dump_json()


@pytest.mark.parametrize('endpoint', ['http://127.0.0.1:1234/v1','http://localhost:1234/v1','http://[::1]:1234/v1','https://provider.example/v1'])
def test_explicit_endpoints_validate_without_network(endpoint):
    assert ProviderOptions(endpoint=endpoint).endpoint == endpoint


@pytest.mark.parametrize('endpoint', ['http://remote.example/v1','http://127.0.0.1.attacker.example/v1','ftp://localhost/x','https://user:SENTINEL@provider.example/v1','https://provider.example/v1?key=SENTINEL','https://provider.example/v1#SENTINEL','http://localhost:99999/v1'])
def test_invalid_endpoint_error_does_not_echo_secret(endpoint):
    with pytest.raises(ValidationError) as error:
        ProviderOptions(endpoint=endpoint)
    assert 'SENTINEL' not in str(error.value)


@pytest.mark.parametrize('change', [{'max_calls':0},{'max_calls':65},{'max_calls':True},{'timeout_seconds':0},{'timeout_seconds':7201},{'output_token_limit':0},{'output_token_limit':256001},{'enable_ai':'true'},{'provider':'other'},{'api_key':'SENTINEL'},{'model':'x\ny'}])
def test_strict_bounds_and_credentials_rejected(change):
    with pytest.raises(ValidationError):
        ProviderOptions(**change)


def test_optional_and_restored_configuration_roundtrip():
    explicit = ProviderOptions(enable_ai=True,provider='claude',endpoint=None,model=None,max_calls=1,timeout_seconds=1,output_token_limit=1)
    assert ProviderOptions.model_validate_json(explicit.model_dump_json()) == explicit
    assert ProviderOptions(endpoint='  ',model=' ').endpoint is None
    assert ProviderOptions(endpoint=LOCAL_ENDPOINT+'/').endpoint == LOCAL_ENDPOINT


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
