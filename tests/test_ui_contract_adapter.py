from attackmap.run_contract import parse_run_message
from attackmap.ui.contract_adapter import LegacyRunContractAdapter

BASE = dict(runId="run1",repositoryKey="repo1",status="running",progress={})


def test_stable_generation_and_revision_across_polls_and_publication():
    adapter = LegacyRunContractAdapter()
    first = adapter.snapshot(BASE)
    assert adapter.snapshot(BASE) == first
    advanced = adapter.snapshot(BASE | {"progress":{"event":"advance","done":1,"total":3,"label":"scan"}})
    assert advanced["message"]["revision"] == 1
    assert advanced["message"]["total_units"] == 3
    terminal = adapter.snapshot(BASE | {"status":"done","reportGeneration":"uuid1","reportRepositoryKey":"repo1"})
    assert terminal["message"]["generation"] == first["message"]["generation"]
    assert terminal["message"]["revision"] == 2
    assert terminal["legacyGeneration"] == "uuid1"
    assert terminal["scope"] == "windows-legacy-adapter"
    assert parse_run_message(terminal["message"]).state == "completed"


def test_unique_identity_gets_new_generation_and_old_is_stable():
    adapter = LegacyRunContractAdapter()
    first = adapter.snapshot(BASE)
    second = adapter.snapshot(BASE | {"runId":"run2"})
    third = adapter.snapshot(BASE | {"repositoryKey":"repo2"})
    assert [first["message"]["generation"],second["message"]["generation"],third["message"]["generation"]] == [1,2,3]
    assert adapter.snapshot(BASE) == first


def test_explicit_lifecycle_preserves_cancel_states_and_rejects_regression():
    adapter = LegacyRunContractAdapter()
    cancelling = adapter.snapshot(BASE,run_state="cancelling")
    assert cancelling["message"]["state"] == "cancelling"
    assert adapter.snapshot(BASE)["message"] == cancelling["message"]
    cancelled = adapter.snapshot(BASE | {"status":"failed"},run_state="cancelled")
    assert cancelled["message"]["state"] == "cancelled"
    assert adapter.snapshot(BASE)["message"] == cancelled["message"]


def test_exit_two_and_report_presence_never_invent_policy_or_readiness():
    adapter = LegacyRunContractAdapter()
    result = adapter.snapshot(BASE | {"exitCode":2,"status":"failed","hasReport":True})["message"]
    assert result["state"] == "failed"
    assert result["policy_outcome"] == "not_evaluated"
    assert result["artifact_readiness"] == "unavailable"
    assert result["limitations"]


def test_done_event_is_not_terminal_and_unbounded_stage_has_no_counters():
    adapter = LegacyRunContractAdapter()
    result = adapter.snapshot(BASE | {"progress":{"event":"done","done":3,"total":3}})["message"]
    assert result["state"] == "running"
    assert result["total_units"] is None
    result = adapter.snapshot(BASE | {"progress":{"event":"stage","done":3,"total":3,"label":"AI review"}})["message"]
    assert result["total_units"] is None


def test_idle_or_missing_identity_has_no_contract_and_cross_repository_report_is_ignored():
    adapter = LegacyRunContractAdapter()
    assert adapter.snapshot(BASE | {"status":"idle"}) is None
    assert adapter.snapshot(BASE | {"runId":None}) is None
    assert adapter.snapshot(BASE | {"reportGeneration":"old","reportRepositoryKey":"other"})["legacyGeneration"] is None
