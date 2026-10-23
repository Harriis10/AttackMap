"""Synthetic verifier tests; these do not prove live provider integration."""
import hashlib
import copy
import json
from pathlib import Path
import tempfile
import unittest

from verify_wp017_live import ENDPOINT, MODEL, verify


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wp017-verifier-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        def file(name, value):
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            (self.base / name).write_bytes(data)
            return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}
        self.file = file
        provider = {"endpoint": ENDPOINT, "model": MODEL, "mode": "review", "backend": "api", "speed": "standard",
                    "max_calls": 8, "max_output_tokens": 32000, "timeout_seconds": 900}
        self.evidence = dict(mode="review", engine_kind="source-native", engine=file("engine.exe", b"synthetic, never executed"),
            smoke=file("smoke.json", {"failure": None, "result": dict(passed=True, capabilitiesChecked=True, scanCompleted=True,
                progressTerminal=True, progressState="completed", personalSettingsRead=False, run="generation", reportHash="report-hash")}),
            request=file("request.json", {"provider": provider}), emitted_provider=provider, provider_pointer="/provider",
            provider_fields={key: key for key in provider}, isolated_output=True,
            run_manifest=file("run-manifest.json", {"desktop_ai": dict(mode="review", status="completed", model_output_available=True)}),
            artifact=file("defensive-review-llm.md", b"Synthetic fixture model prose"),
            metadata=file("defensive-review-llm.meta.json", dict(backend="api", model=MODEL, stop_reason="completed")),
            displayed_mode="review", displayed_generation="generation", selected_report_sha256="report-hash",
            capture=file("capture.png", b"synthetic capture fixture"), export=file("export.md", b"Synthetic fixture model prose"),
            provider_log=file("server.log", b"request-1 completed synthetic response"), provider_event_source="lm-studio-server-log",
            provider_events=[dict(request_id="request-1", route="/v1/responses", model=MODEL, completed=True,
                nonempty_output=True, response_sha256=hashlib.sha256(b"synthetic response").hexdigest(),
                response=file("response.txt", b"synthetic response"), raw_excerpt="request-1 completed synthetic response")],
            actual_http_requests=1, completed_responses=1)

    def test_interim_is_not_packaged_acceptance(self):
        result = verify(self.evidence, self.base)
        self.assertTrue(result["passed"], result)
        self.assertIn("interim only", result["verdict"])
        self.assertFalse(result["accepted_manual_ui"])

    def budget_evidence(self, provider=3600, scan=4200, harness=4500):
        budget = dict(provider_timeout_seconds=provider, scan_timeout_seconds=scan, harness_timeout_seconds=harness)
        self.evidence["timeout_budget"] = budget
        self.evidence["emitted_provider"]["timeout_seconds"] = provider
        self.evidence["request"] = self.file("request.json", {"options": {"provider": self.evidence["emitted_provider"], "timeout_seconds": scan}})
        self.evidence["provider_pointer"] = "/options/provider"
        smoke = json.loads((self.base / "smoke.json").read_text())
        smoke["result"]["timeoutBudget"] = budget
        self.evidence["smoke"] = self.file("smoke.json", smoke)
        self.evidence["preflight"] = self.file("preflight.json", dict(provider_budget_seconds=provider,
            native_scan_timeout_seconds=scan, process_timeout_seconds=harness))
        self.evidence["process"] = self.file("process.json", dict(timeout_seconds=harness, exit_code=0,
            exited=True, timed_out=False, owned_job_assigned=True, owned_tree_cleanup_verified=True))

    def test_exact_default_and_long_budget_provenance_pass(self):
        for triplet in ((900, 1200, 1500), (3600, 4200, 4500), (3600, 3600, 3601),
                        (7200, 7800, 8100), (7200, 7200, 7201), (7200, 10799, 10800)):
            with self.subTest(triplet=triplet):
                self.budget_evidence(*triplet)
                result = verify(self.evidence, self.base)
                self.assertTrue(result["passed"], result)

    def test_long_budget_without_new_provenance_rejected(self):
        self.evidence["emitted_provider"]["timeout_seconds"] = 3600
        self.evidence["request"] = self.file("request.json", {"provider": self.evidence["emitted_provider"]})
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_budget_provenance_missing_or_hash_tampered_rejected(self):
        for key in ("preflight", "process"):
            for change in ("missing", "tampered"):
                with self.subTest(key=key, change=change):
                    self.budget_evidence()
                    if change == "missing":
                        del self.evidence[key]
                    else:
                        (self.base / self.evidence[key]["path"]).write_text("{}")
                    self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_each_bound_timeout_source_must_match(self):
        cases = [("preflight", (key,), 900) for key in ("provider_budget_seconds", "native_scan_timeout_seconds", "process_timeout_seconds")]
        cases += [("smoke", ("result", "timeoutBudget", key), 900) for key in ("provider_timeout_seconds", "scan_timeout_seconds", "harness_timeout_seconds")]
        cases += [("request", ("options", "timeout_seconds"), 1200), ("request", ("options", "provider", "timeout_seconds"), 900),
                  ("request", ("options", "provider", "timeout_seconds"), 3600.0),
                  ("process", ("timeout_seconds",), 1500), ("process", ("timeout_seconds",), 4500.0),
                  ("process", ("owned_tree_cleanup_verified",), False), ("process", ("timed_out",), True),
                  ("preflight", ("provider_budget_seconds",), 3600.0), ("smoke", ("result", "timeoutBudget"), None)]
        for source, parts, changed in cases:
            with self.subTest(source=source, parts=parts, changed=changed):
                self.budget_evidence()
                record = self.evidence[source]
                value = json.loads((self.base / record["path"]).read_text())
                parent = value
                for part in parts[:-1]:
                    parent = parent[part]
                parent[parts[-1]] = changed
                self.evidence[source] = self.file(record["path"], value)
                self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_malformed_collector_budgets_fail_closed(self):
        self.budget_evidence()
        valid = copy.deepcopy(self.evidence["timeout_budget"])
        bad = [None, [], "3600/4200/4500", {}, {**valid, "extra": 1}]
        for key in valid:
            bad += [{**valid, key: value} for value in (True, 1.0, "3600", None, 0)]
        bad += [{**valid, "provider_timeout_seconds": 7201}, {**valid, "harness_timeout_seconds": 10801},
                {**valid, "scan_timeout_seconds": 86401}, {**valid, "scan_timeout_seconds": 4500},
                {**valid, "scan_timeout_seconds": 3599}]
        for value in bad:
            with self.subTest(value=value):
                self.evidence["timeout_budget"] = value
                self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_extended_each_bound_timeout_source_must_match(self):
        cases = [("preflight", (key,), 900) for key in ("provider_budget_seconds", "native_scan_timeout_seconds", "process_timeout_seconds")]
        cases += [("smoke", ("result", "timeoutBudget", key), 900) for key in ("provider_timeout_seconds", "scan_timeout_seconds", "harness_timeout_seconds")]
        cases += [("request", ("options", "timeout_seconds"), 1200), ("request", ("options", "provider", "timeout_seconds"), 900),
                  ("request", ("options", "provider", "timeout_seconds"), 7200.0),
                  ("process", ("timeout_seconds",), 1500), ("process", ("timeout_seconds",), 8100.0),
                  ("process", ("owned_tree_cleanup_verified",), False), ("process", ("timed_out",), True),
                  ("preflight", ("provider_budget_seconds",), 7200.0), ("smoke", ("result", "timeoutBudget"), None)]
        for source, parts, changed in cases:
            with self.subTest(source=source, parts=parts, changed=changed):
                self.budget_evidence(7200, 7800, 8100)
                record = self.evidence[source]
                value = json.loads((self.base / record["path"]).read_text())
                parent = value
                for part in parts[:-1]:
                    parent = parent[part]
                parent[parts[-1]] = changed
                self.evidence[source] = self.file(record["path"], value)
                self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_extended_budget_cannot_promote_legacy_or_remote_evidence(self):
        self.evidence["emitted_provider"]["timeout_seconds"] = 7200
        self.evidence["request"] = self.file("request.json", {"provider": self.evidence["emitted_provider"]})
        self.assertFalse(verify(self.evidence, self.base)["passed"])
        self.budget_evidence(7200, 7800, 8100)
        self.evidence["emitted_provider"]["endpoint"] = "https://api.openai.com/v1"
        self.evidence["request"] = self.file("request.json", {"options": {
            "provider": self.evidence["emitted_provider"], "timeout_seconds": 7800}})
        result = verify(self.evidence, self.base)
        self.assertFalse(result["passed"])
        self.assertIn("provider setting mismatch: endpoint", result["failures"])

    def test_reservations_do_not_prove_http_responses(self):
        self.evidence.update(provider_events=[], actual_http_requests=0, completed_responses=0, calls_reserved=8)
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_tampered_export_rejected(self):
        (self.base / "export.md").write_text("changed")
        result = verify(self.evidence, self.base)
        self.assertFalse(result["passed"])
        self.assertIn("selected artifact export hash mismatch", result["failures"])

    def test_wrong_displayed_mode_and_fallback_rejected(self):
        self.evidence["displayed_mode"] = "hunt"
        self.evidence["metadata"] = self.file("fallback.json", dict(backend="deterministic", model=MODEL, stop_reason="completed"))
        result = verify(self.evidence, self.base)
        self.assertFalse(result["passed"])
        self.assertIn("metadata provider mismatch/fallback", result["failures"])

    def test_packaged_requires_separate_proof(self):
        self.evidence["engine_kind"] = "packaged"
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_server_excerpt_must_exist_in_hashed_observation(self):
        self.evidence["provider_events"][0]["raw_excerpt"] = "invented"
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_response_hash_alone_does_not_prove_completed_output(self):
        del self.evidence["provider_events"][0]["response"]
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def own_audit(self):
        attempt = "a" * 32
        data = b"Synthetic fixture model prose"
        self.file(f"output-{attempt}.utf8", data)
        common = dict(schema_version="1.0", nonce="fixture", pid=123, utc="2026-10-21T01:00:00Z")
        events = [dict(event="audit_started", endpoint=ENDPOINT, model=MODEL),
                  dict(event="attempted_dispatch", attempt_id=attempt, method="POST", path="/v1/responses", origin="http://127.0.0.1:1234", model=MODEL),
                  dict(event="http_response_received", attempt_id=attempt, method="POST", path="/v1/responses", status=200),
                  dict(event="observation_complete", attempt_id=attempt, parse_status="json", body_bytes=100,
                       body_sha256="b" * 64, completed=True, model=MODEL, status=200,
                       output_file=f"output-{attempt}.utf8", output_sha256=hashlib.sha256(data).hexdigest(), output_bytes=len(data))]
        for i, event in enumerate(events, 1):
            event.update(common, sequence=i, monotonic_ns=i)
        self.evidence.update(provider_event_source="attackmap-httpx-audit", audit_nonce="fixture",
            provider_audits=[self.file("audit.jsonl", ("\n".join(json.dumps(e) for e in events)+"\n").encode())])
        return events

    def test_own_observer_generated_bytes_are_valid_evidence(self):
        self.own_audit()
        result = verify(self.evidence, self.base)
        self.assertTrue(result["passed"], result)
        self.assertFalse(result["accepted_wp017"])

    def test_own_observer_unsettled_attempt_rejected(self):
        events = self.own_audit()
        self.evidence["provider_audits"] = [self.file("audit.jsonl", ("\n".join(json.dumps(e) for e in events[:2])+"\n").encode())]
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_own_observer_output_tamper_rejected(self):
        self.own_audit()
        (self.base / ("output-" + "a" * 32 + ".utf8")).write_bytes(b"changed")
        self.assertFalse(verify(self.evidence, self.base)["passed"])


if __name__ == "__main__":
    unittest.main()
